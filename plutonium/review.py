"""One staged review transaction. Proposals never touch the worktree before approval."""
from __future__ import annotations
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
from typing import Callable
import yaml
from PIL import Image
from plutonium.config import PlutoniumConfig, find_config, validate_yaml
from plutonium.models import FindingCategory, ScanResult
from plutonium.scanner import _is_placeholder
from plutonium.review_policy import ReviewPolicy


class ReviewError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args, data=None, env=None, check=True):
    p = subprocess.run(['git', '-C', str(root), *args], input=data, capture_output=True,
                       env=env, timeout=60)
    if check and p.returncode:
        raise ReviewError(p.stderr.decode(errors='replace').strip() or 'Git operation failed')
    return p


def read_policy(root):
    path = find_config(root)
    raw = validate_yaml(path.read_text()) if path else {}
    return ReviewPolicy.from_raw(raw or {}), path


def scan_snapshot(root, paths, policy):
    from plutonium.scanner import Scanner
    from plutonium.llm_router import GemmaRouter
    cfg = PlutoniumConfig(policy.raw)
    router = None if policy.offline else GemmaRouter(
        ollama_url=cfg.models['ollama_url'], offline_safe=policy.allow_fallback,
        cache_path=root / '.plutonium' / 'demo_cache.json')
    scanner = Scanner(str(root), router=router, config=cfg, offline=policy.offline)
    results = []
    text_paths = [str(root / p) for p in paths if Path(p).suffix.lower() not in ('.png', '.jpg', '.jpeg', '.webp')]
    if text_paths:
        results.append(scanner.scan_files(text_paths, mode=policy.engine, preset=policy.preset))
    image_paths = list(paths)
    for path in text_paths:
        if Path(path).suffix.lower() != '.ipynb':
            continue
        doc = json.loads(Path(path).read_text())
        for ci, cell in enumerate(doc.get('cells', [])):
            for oi, output in enumerate(cell.get('outputs', [])):
                payload = output.get('data', {}).get('image/png')
                if payload:
                    name = str(Path(path).relative_to(root)) + f'#cell-{ci + 1}-output-{oi + 1}.png'
                    target = root / name
                    target.write_bytes(base64.b64decode(''.join(payload) if isinstance(payload, list) else payload))
                    if name not in image_paths:
                        image_paths.append(name)
    if results:
        results[0].findings = [f for f in results[0].findings if f.target_type != 'image']
    for path in image_paths:
        if Path(path).suffix.lower() in ('.png', '.jpg', '.jpeg', '.webp'):
            # Fixture sidecars are not evidence about the current proposed pixels.
            image_dir = root / '.plutonium' / 'review-images'
            image_dir.mkdir(parents=True, exist_ok=True)
            target = image_dir / (digest(path.encode()) + Path(path).suffix)
            target.write_bytes((root / path).read_bytes())
            result = scanner.scan_image(str(target), mode=policy.engine, preset=policy.preset)
            for finding in result.findings:
                finding.file_path = path
            results.append(result)
    return ScanResult(verdict='BLOCK' if any(r.verdict == 'BLOCK' for r in results) else 'PASS',
                      engine_used=', '.join(dict.fromkeys(r.engine_used for r in results)),
                      preset_used=policy.preset, summary=' '.join(r.summary for r in results),
                      findings=[f for r in results for f in r.findings],
                      thinking_trace='\n'.join(r.thinking_trace or '' for r in results))


class ReviewSession:
    def __init__(self, root, *, policy=None, scan_provider: Callable = scan_snapshot):
        self.root = Path(git(root, 'rev-parse', '--show-toplevel').stdout.decode().strip()).resolve()
        self.policy, self.policy_path = read_policy(self.root)
        if policy is not None:
            self.policy = policy
            self.policy_path = None
        self.policy_bytes = self.policy_path.read_bytes() if self.policy_path else None
        self.branch = git(self.root, 'symbolic-ref', '--short', '-q', 'HEAD', check=False).stdout.decode().strip() or 'Detached HEAD'
        self.head = git(self.root, 'rev-parse', '--verify', 'HEAD', check=False).stdout
        self.index = Path(git(self.root, 'rev-parse', '--path-format=absolute', '--git-path', 'index').stdout.decode().strip())
        self.index_bytes = self.index.read_bytes() if self.index.exists() else b''
        self.tmp = tempfile.TemporaryDirectory(prefix='plutonium-review-')
        self.base = Path(self.tmp.name)
        self.snapshot = self.base / 'snapshot'
        self.snapshot.mkdir()
        self.token = secrets.token_urlsafe(32)
        self.revision = 0
        self.validated_revision = None
        self.validation = None
        self.state = 'reviewing'
        self.last_seen = time.monotonic()
        self.files = {}
        self.decisions = {}
        self.findings = []
        self.coverage = []
        self.scan_provider = scan_provider
        self.env_updates = {}
        try:
            self._snapshot()
            self._extract_images()
            self.static_coverage = list(self.coverage)
            self.result = self._scan()
            self.findings = self.result.findings
            self._propose()
        except Exception:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.tmp.cleanup()

    def _snapshot(self):
        changed = set(git(self.root, 'diff', '--cached', '--name-only', '--diff-filter=ACMRT', '-z').stdout.split(b'\0'))
        entries = git(self.root, 'ls-files', '--stage', '-z').stdout.split(b'\0')
        for entry in entries:
            if not entry:
                continue
            meta, raw_path = entry.split(b'\t', 1)
            mode, oid, stage = meta.decode().split()
            path = os.fsdecode(raw_path)
            if stage != '0':
                raise ReviewError('Resolve merge conflicts before reviewing a commit')
            if Path(path).is_absolute() or '..' in Path(path).parts:
                raise ReviewError('Unsafe Git path')
            supported = mode in ('100644', '100755')
            content = git(self.root, 'cat-file', 'blob', oid).stdout if supported else b''
            if supported and len(content) <= self.policy.max_file_bytes:
                dest = self.snapshot / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
            if raw_path not in changed:
                continue
            kind, text = 'text', None
            reason = None
            if not supported:
                reason = 'Symlinks and submodules require external review'
            elif len(content) > self.policy.max_file_bytes:
                reason = 'File exceeds the configured review size limit'
            elif Path(path).suffix.lower() in ('.png', '.jpg', '.jpeg', '.webp'):
                kind = 'image'
                try:
                    Image.open(io.BytesIO(content)).verify()
                except Exception:
                    reason = 'Invalid image'
            else:
                try:
                    text = content.decode('utf-8')
                    if '\0' in text:
                        reason = 'Binary content is not supported'
                except UnicodeDecodeError:
                    reason = 'Only UTF-8 text is editable'
            if reason:
                kind = 'unsupported'
                self.coverage.append(f'{path}: {reason}')
            work = self.root / path
            if work.is_symlink() or any(p.is_symlink() for p in work.parents if p != self.root.parent):
                raise ReviewError(f'{path}: working path contains a symlink')
            self.files[path] = {'path': path, 'kind': kind, 'mode': mode, 'oid': oid,
                                'original': text, 'proposed': text, 'bytes': content,
                                'working': work.read_bytes() if work.exists() else None,
                                'regions': [], 'style': 'solid_mask', 'reason': reason,
                                'proposal': text}

    def _extract_images(self):
        for path, file in list(self.files.items()):
            if not path.endswith('.ipynb') or file['kind'] != 'text':
                continue
            try:
                doc = json.loads(file['proposed'])
                for ci, cell in enumerate(doc.get('cells', [])):
                    for oi, output in enumerate(cell.get('outputs', [])):
                        png = output.get('data', {}).get('image/png')
                        if not png:
                            continue
                        data = base64.b64decode(''.join(png) if isinstance(png, list) else png, validate=True)
                        Image.open(io.BytesIO(data)).verify()
                        name = f'{path}#cell-{ci + 1}-output-{oi + 1}.png'
                        if name in self.files:
                            raise ReviewError('Notebook image name conflicts with a staged path')
                        self.files[name] = {'path': name, 'kind': 'image', 'parent': path,
                            'cell': ci, 'output': oi, 'bytes': data, 'working': None,
                            'mode': '100644', 'oid': '', 'original': None, 'proposed': None,
                            'proposal': None, 'regions': [], 'style': 'solid_mask', 'reason': None}
                        (self.snapshot / name).write_bytes(data)
            except (ValueError, TypeError, OSError, AttributeError) as e:
                self.coverage.append(f'{path}: could not read notebook images: {e}')

    def _embed_images(self):
        for path, f in self.files.items():
            if not f.get('parent') or (not f['regions'] and not f.get('last_rendered')):
                continue
            parent = self.files[f['parent']]
            try:
                doc = json.loads(parent['proposed'])
                data = doc['cells'][f['cell']]['outputs'][f['output']]['data']
                current = data['image/png']
                current_bytes = base64.b64decode(''.join(current) if isinstance(current, list) else current)
                redacted = self.image_bytes(path)
                if current_bytes not in (f['bytes'], f.get('last_rendered', f['bytes'])):
                    raise ReviewError('Embedded image changed in text editor; restore it before editing regions')
                data['image/png'] = base64.b64encode(redacted).decode()
                f['last_rendered'] = redacted
                parent['proposed'] = json.dumps(doc, ensure_ascii=False, indent=1) + '\n'
            except (ValueError, KeyError, IndexError, TypeError) as e:
                raise ReviewError(f"{f['parent']}: notebook structure changed; restore the image output before redacting: {e}")

    def _scan(self):
        self.coverage = list(self.static_coverage)
        paths = [p for p, f in self.files.items() if f['kind'] != 'unsupported']
        if not paths:
            return ScanResult(verdict='PASS', engine_used='none', preset_used=self.policy.preset,
                              summary='No supported changed files', findings=[])
        result = self.scan_provider(self.snapshot, paths, self.policy)
        # Scanner may return absolute filenames; expose only snapshot-relative paths.
        for f in result.findings:
            p = Path(f.file_path)
            if p.is_absolute():
                try:
                    f.file_path = p.relative_to(self.snapshot).as_posix()
                except ValueError:
                    raise ReviewError('Scanner returned a path outside the staged snapshot')
        engine = result.engine_used.lower()
        if not self.policy.allow_fallback and not self.policy.offline and any(
                term in engine for term in ('offline', 'heuristic', 'cache')):
            self.coverage.append('Required engine unavailable; fallback result cannot satisfy policy')
        if 'vision engine unavailable' in result.summary.lower():
            self.coverage.append(result.summary)
        return result

    def _propose(self):
        from plutonium.redactor import apply_text_fixes, extract_to_env
        for path, file in self.files.items():
            findings = [f for f in self.findings if f.file_path == path]
            if file['kind'] == 'image':
                file['regions'] = [f.bbox_2d for f in findings if f.bbox_2d]
            elif file['kind'] == 'text':
                # Notebook findings use rendered cell coordinates, not raw JSON lines.
                if Path(path).suffix == '.ipynb':
                    file['proposed'] = self._notebook_proposal(file['original'], findings)
                else:
                    file['proposed'] = apply_text_fixes(file['original'], findings,
                                                       {f.id: f.recommended_action for f in findings})
                for f in findings:
                    if f.recommended_action.value == 'env_extract':
                        _, name, value = extract_to_env(f)
                        if name and value:
                            self.env_updates[name] = value
                file['proposal'] = file['proposed']
        self._write_proposals()

    def _notebook_proposal(self, text, findings):
        from plutonium.redactor import apply_text_fixes
        doc = json.loads(text)
        # Match snippets in individual sources/outputs instead of patching JSON line offsets.
        def visit(value):
            if isinstance(value, dict):
                return {k: (visit(v) if k != 'image/png' else v) for k, v in value.items()}
            if isinstance(value, list):
                if value and all(isinstance(v, str) for v in value):
                    joined = ''.join(value)
                    return patch(joined).splitlines(keepends=True)
                return [visit(v) for v in value]
            return patch(value) if isinstance(value, str) else value
        def patch(value):
            matched = [f.model_copy(update={'line_start': None, 'line_end': None}) for f in findings
                       if f.target_type != 'image' and f.offending_snippet and f.offending_snippet in value]
            return apply_text_fixes(value, matched, {f.id: f.recommended_action for f in matched})
        return json.dumps(visit(doc), ensure_ascii=False, indent=1) + '\n'

    def image_bytes(self, path, proposed=True):
        f = self.files[path]
        if f['kind'] != 'image':
            raise ReviewError('Not an editable image')
        if not proposed or not f['regions']:
            return f['bytes']
        from plutonium.redactor import redact_image
        source = self.base / 'source-image'
        dest = self.base / 'redacted.png'
        source.write_bytes(f['bytes'])
        redact_image(str(source), f['regions'], style=f['style'], out_path=str(dest))
        original = Image.open(io.BytesIO(f['bytes']))
        output = io.BytesIO()
        Image.open(dest).save(output, format=original.format)
        return output.getvalue()

    def _write_proposals(self):
        self._embed_images()
        for path, f in self.files.items():
            if f['kind'] == 'text':
                (self.snapshot / path).write_bytes(f['proposed'].encode('utf-8'))
            elif f['kind'] == 'image':
                (self.snapshot / path).write_bytes(self.image_bytes(path))

    def _revision(self, revision):
        if self.state != 'reviewing':
            raise ReviewError('Review is already closed')
        if revision != self.revision:
            raise ReviewError('Review changed. Refresh before continuing.')
        self.last_seen = time.monotonic()

    def update(self, revision, *, path=None, content=None, regions=None, style=None, decisions=None):
        self._revision(revision)
        if path is not None:
            if path not in self.files:
                raise ReviewError('Unknown session file')
            f = copy.deepcopy(self.files[path])
            if content is not None:
                if f['kind'] != 'text' or not isinstance(content, str):
                    raise ReviewError('Not an editable text file')
                if len(content.encode()) > self.policy.max_file_bytes:
                    raise ReviewError('Edited file exceeds size limit')
                f['proposed'] = content
            if regions is not None:
                if f['kind'] != 'image' or not isinstance(regions, list) or len(regions) > 1000:
                    raise ReviewError('Invalid image regions')
                for box in regions:
                    if not isinstance(box, list) or len(box) != 4 or any(type(n) not in (int, float) or not 0 <= n <= 1000 for n in box) or box[0] >= box[2] or box[1] >= box[3]:
                        raise ReviewError('Invalid image region coordinates')
                f['regions'] = regions
            if style is not None:
                if style not in ('solid_mask', 'gaussian_blur'):
                    raise ReviewError('Invalid redaction style')
                f['style'] = style
        if decisions:
            for fid, action in decisions.items():
                finding = next((f for f in self.findings if f.id == fid), None)
                if not finding or action not in ('dismiss', 'resolve'):
                    raise ReviewError('Invalid finding decision')
                if action == 'dismiss' and not self.policy.can_dismiss(finding):
                    raise ReviewError('This finding is enforced by policy and cannot be dismissed')
        if path is not None:
            self.files[path] = f
            self.decisions = {}  # dismissals are content-bound
        if decisions:
            self.decisions.update(decisions)
        self.revision += 1
        self.validated_revision = None
        self.validation = None
        return self.public()

    def _finding_key(self, f):
        return (f.file_path, f.rule_id, f.offending_snippet, tuple(f.bbox_2d or []), f.title)

    def validate(self, revision):
        self._revision(revision)
        blockers = []
        for path, f in self.files.items():
            if path.endswith('.ipynb') and f['kind'] == 'text':
                try:
                    nb = json.loads(f['proposed'])
                    if not isinstance(nb.get('cells'), list):
                        raise ValueError('cells must be a list')
                except (ValueError, AttributeError) as e:
                    blockers.append(f'{path}: invalid notebook: {e}')
        if not blockers:
            try:
                self._write_proposals()
            except ReviewError as e:
                blockers.append(str(e))
        dismissed = {self._finding_key(f) for f in self.findings
                     if self.decisions.get(f.id) == 'dismiss' and self.policy.can_dismiss(f)}
        try:
            result = self._scan() if not blockers else self.result
        except Exception as e:
            blockers.append(f'Validation scan failed: {e}')
            result = self.result
        applied = {(f.replacement_snippet or '').strip() for f in self.findings
                   if f.category != FindingCategory.LOGICAL_BUG and (f.replacement_snippet or '').strip()}
        remaining = []
        for f in result.findings:
            snippet = (f.offending_snippet or '').strip()
            if f.category != FindingCategory.LOGICAL_BUG and snippet and (snippet in applied or _is_placeholder(snippet)):
                continue  # our own replacement value: never re-flag it
            if self._finding_key(f) not in dismissed:
                remaining.append(f)
        blockers.extend(f'{f.file_path}: {f.title}' for f in remaining)
        if self.coverage and self.policy.incomplete == 'block':
            blockers.extend(self.coverage)
        self.validation = {'revision': self.revision, 'valid': not blockers,
                           'blockers': list(dict.fromkeys(blockers)),
                           'remaining': [f.model_dump(mode='json') for f in remaining]}
        if not blockers:
            self.validated_revision = self.revision
        else:
            # Keep original IDs for existing findings, expose new validation findings for triage.
            keys = {self._finding_key(f) for f in self.findings}
            for f in remaining:
                if self._finding_key(f) not in keys:
                    if any(old.id == f.id for old in self.findings):
                        f = f.model_copy(update={'id': secrets.token_hex(8)})
                    self.findings.append(f)
        return self.validation

    def _unchanged(self):
        if (self.index.read_bytes() if self.index.exists() else b'') != self.index_bytes:
            raise ReviewError('Git index changed during review. Start a new review.')
        if git(self.root, 'rev-parse', '--verify', 'HEAD', check=False).stdout != self.head:
            raise ReviewError('HEAD changed during review')
        if self.policy_path and self.policy_path.read_bytes() != self.policy_bytes:
            raise ReviewError('Policy changed during review')
        for path, f in self.files.items():
            if f.get('parent'):
                continue
            p = self.root / path
            if p.is_symlink() or any(parent.is_symlink() for parent in p.parents):
                raise ReviewError('Working path changed to a symlink')
            if (p.read_bytes() if p.exists() else None) != f['working']:
                raise ReviewError(f'{path}: working file changed during review')

    def approve(self, revision):
        if self.state == 'approved':
            return {'state': self.state}
        self._revision(revision)
        if self.validated_revision != revision:
            raise ReviewError('Validate the latest changes before approval')
        self._unchanged()
        updates = {}
        index_updates = []
        for path, f in self.files.items():
            if f.get('parent'):
                continue
            proposed = f['proposed'].encode() if f['kind'] == 'text' else self.image_bytes(path) if f['kind'] == 'image' else f['bytes']
            if proposed == f['bytes']:
                continue
            working = f['working']
            if working is None:
                raise ReviewError(f'{path}: file was removed from the working tree')
            merged = proposed
            if working != f['bytes']:
                if f['kind'] != 'text':
                    raise ReviewError(f'{path}: unstaged image changes conflict with redaction')
                for name, data in [('current', working), ('base', f['bytes']), ('new', proposed)]:
                    (self.base / name).write_bytes(data)
                merge = git(self.root, 'merge-file', '-p', str(self.base / 'current'), str(self.base / 'base'), str(self.base / 'new'), check=False)
                if merge.returncode:
                    raise ReviewError(f'{path}: approved changes conflict with unstaged edits')
                merged = merge.stdout
            oid = git(self.root, 'hash-object', '-w', '--stdin', data=proposed).stdout.strip()
            index_updates.append(f['mode'].encode() + b' ' + oid + b'\t' + os.fsencode(path) + b'\0')
            updates[path] = merged
        temp_index = self.base / 'index'
        if self.index_bytes:
            temp_index.write_bytes(self.index_bytes)
        env = {**os.environ, 'GIT_INDEX_FILE': str(temp_index)}
        if index_updates:
            git(self.root, 'update-index', '-z', '--index-info', data=b''.join(index_updates), env=env)
        # Environment extraction is local-only and only accompanies an actual approved change.
        env_path = self.root / '.env'
        env_original = env_path.read_bytes() if env_path.exists() else None
        approved_env = {}
        from plutonium.redactor import extract_to_env
        for finding in self.findings:
            if finding.recommended_action.value != 'env_extract' or finding.file_path not in updates:
                continue
            _, name, value = extract_to_env(finding)
            proposal = self.files[finding.file_path].get('proposed') or ''
            if name in proposal and value not in proposal and self.decisions.get(finding.id) != 'dismiss':
                approved_env[name] = value
        if approved_env and updates:
            if env_path.is_symlink():
                raise ReviewError('.env cannot be a symlink')
            if git(self.root, 'ls-files', '--error-unmatch', '.env', check=False).returncode == 0:
                raise ReviewError('Environment extraction requires an untracked .env file')
            old = (env_original or b'').decode()
            additions = []
            for name, value in approved_env.items():
                if '\n' in value or '\r' in value:
                    raise ReviewError('Multiline secrets require manual environment configuration')
                if not any(line.split('=', 1)[0].strip() == name for line in old.splitlines()):
                    additions.append(f'{name}={json.dumps(value)}\n')
            if additions:
                updates['.env'] = (old + ('\n' if old and not old.endswith('\n') else '') + ''.join(additions)).encode()
        backups = {p: (self.root / p).read_bytes() if (self.root / p).exists() else None for p in updates}
        self._unchanged()
        lock = Path(str(self.index) + '.lock')
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise ReviewError('Git index is locked by another process')
        try:
            self._unchanged()
            with os.fdopen(fd, 'wb') as stream:
                stream.write(temp_index.read_bytes() if index_updates else self.index_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            for path, content in updates.items():
                (self.root / path).write_bytes(content)
            os.replace(lock, self.index)
        except Exception:
            for path, data in backups.items():
                p = self.root / path
                if data is None:
                    p.unlink(missing_ok=True)
                else:
                    p.write_bytes(data)
            raise
        finally:
            lock.unlink(missing_ok=True)
        self.state = 'approved'
        return {'state': self.state}

    def cancel(self):
        if self.state == 'approved':
            raise ReviewError('Review was already approved')
        self.state = 'cancelled'
        return {'state': self.state}

    def public(self):
        return {'revision': self.revision, 'state': self.state, 'repository': self.root.name,
                'branch': self.branch, 'policy': self.policy.public(),
                'policy_source': str(self.policy_path or 'provided policy'),
                'files': [{k: v for k, v in f.items() if k not in ('bytes', 'working', 'oid', 'mode', 'last_rendered')}
                          for f in self.files.values()],
                'findings': [{**f.model_dump(mode='json'), 'can_dismiss': self.policy.can_dismiss(f)} for f in self.findings],
                'decisions': self.decisions, 'validation': self.validation,
                'coverage': list(dict.fromkeys(self.coverage)),
                'local_env_keys': list(self.env_updates), 'summary': self.result.summary}
