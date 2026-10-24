"""Noninteractive CI gate: scan a revision with policy from a trusted base."""
import os
from pathlib import Path
import tempfile
import yaml
from plutonium.review import git, scan_snapshot, ReviewError
from plutonium.review_policy import ReviewPolicy
from plutonium.config import validate_yaml


def check_revision(root, base, head='HEAD', *, scan_provider=scan_snapshot):
    root = Path(root).resolve()
    base = git(root, 'rev-parse', '--verify', base + '^{commit}').stdout.decode().strip()
    head = git(root, 'rev-parse', '--verify', head + '^{commit}').stdout.decode().strip()
    policy_blob = git(root, 'show', base + ':.plutonium.yaml', check=False)
    if policy_blob.returncode:
        raise ReviewError('Trusted base must contain .plutonium.yaml')
    policy = ReviewPolicy.from_raw(validate_yaml(policy_blob.stdout.decode()))
    changed = set(git(root, 'diff', '--name-only', '--diff-filter=ACMRT', '-z', base + '...' + head).stdout.split(b'\0'))
    coverage, targets = [], []
    with tempfile.TemporaryDirectory(prefix='plutonium-check-') as tmp:
        snapshot = Path(tmp)
        for entry in git(root, 'ls-tree', '-r', '-z', head).stdout.split(b'\0'):
            if not entry:
                continue
            meta, name = entry.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            path = os.fsdecode(name)
            if Path(path).is_absolute() or '..' in Path(path).parts:
                raise ReviewError('Unsafe revision path')
            if mode not in ('100644', '100755'):
                if name in changed:
                    coverage.append(f'{path}: unsupported file type')
                continue
            content = git(root, 'cat-file', 'blob', oid).stdout
            if len(content) > policy.max_file_bytes:
                if name in changed:
                    coverage.append(f'{path}: exceeds scan size limit')
                continue
            image = Path(path).suffix.lower() in ('.png', '.jpg', '.jpeg', '.webp')
            if not image:
                try:
                    decoded = content.decode('utf-8')
                    if '\0' in decoded:
                        raise ValueError('binary')
                except (UnicodeDecodeError, ValueError):
                    if name in changed:
                        coverage.append(f'{path}: unsupported binary')
                    continue
            target = snapshot / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            if name in changed:
                targets.append(path)
        result = scan_provider(snapshot, targets, policy) if targets else None
        findings = result.findings if result else []
        if result and (('vision engine unavailable' in result.summary.lower()) or
                       (not policy.offline and not policy.allow_fallback and any(s in result.engine_used.lower() for s in ('cache', 'offline', 'heuristic')))):
            coverage.append('Required engine did not complete the scan')
        enforced = [f for f in findings if not policy.can_dismiss(f)]
        return {'passed': not enforced and not (coverage and policy.incomplete == 'block'),
                'policy_revision': base, 'revision': head, 'coverage': coverage,
                'engine': result.engine_used if result else 'none',
                'findings': [{'file_path': f.file_path, 'rule_id': f.rule_id,
                              'severity': f.severity.value, 'title': f.title,
                              'enforced': not policy.can_dismiss(f)} for f in findings]}
