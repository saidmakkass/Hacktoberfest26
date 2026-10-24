"""Plutonium remediation engine.

* Synthetic twins: format-valid but obviously fake Moroccan PII / secrets.
* Text patcher: applies twins, `.env` extraction and bug-fix patches (pitfall #5 safe).
* Image redactor: `[ymin, xmin, ymax, xmax]` 0-1000 boxes -> blurred / masked PNG (pitfall #4).
* Safe-to-Prompt firewall: deterministic on-device tokenization + rehydration.
"""
from __future__ import annotations

import base64
import difflib
import hashlib
import json
import re
import shutil
import textwrap
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from plutonium.models import ActionType, Finding

# --------------------------------------------------------------------------- twins

_KIND_ALIASES = {
    "ma.cin": "cin", "cin": "cin",
    "ma.rib": "rib", "rib": "rib",
    "ma.iban": "iban", "iban": "iban",
    "ma.phone": "phone", "phone": "phone",
    "lab.cne": "cne", "cne": "cne", "cnes": "cne", "massar": "cne",
    "email": "email",
    "gen.jwt": "jwt", "jwt": "jwt",
    "gen.aws_access_key": "aws", "aws": "aws",
    "gen.db_uri": "db_uri", "db_uri": "db_uri",
    "ma.cmi_key": "cmi_key", "cmi_key": "cmi_key",
}


def kind_from_rule(rule_id: str) -> str:
    """Map a rule id (`ma.cin`, `gemma.cin_leak`, ...) to a twin kind."""
    rid = (rule_id or "").lower()
    if rid in _KIND_ALIASES:
        return _KIND_ALIASES[rid]
    for key in ("iban", "rib", "cne", "massar", "cin", "phone", "email", "jwt", "aws", "db_uri", "cmi"):
        if key in rid:
            return _KIND_ALIASES.get(key, "cmi_key" if key == "cmi" else key)
    if any(k in rid for k in ("secret", "token", "key", "password")):
        return "secret"
    return "generic"


def _digits(seed: str, n: int) -> str:
    out, counter = "", 0
    while len(out) < n:
        out += str(int(hashlib.sha256(f"{seed}:{counter}".encode()).hexdigest(), 16))
        counter += 1
    return out[:n]


def _hex(seed: str, n: int = 8) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:n]


def rib_key(bank_branch_account_22_digits: str) -> str:
    """Moroccan RIB key: 97 - ((n * 100) % 97), zero-padded to 2 digits."""
    digits = re.sub(r"\D", "", bank_branch_account_22_digits)
    if len(digits) != 22:
        raise ValueError("RIB body must be exactly 22 digits (3 bank + 3 branch + 16 account)")
    return f"{97 - ((int(digits) * 100) % 97):02d}"


def is_valid_rib(rib: str) -> bool:
    d = re.sub(r"\D", "", rib)
    return len(d) == 24 and rib_key(d[:22]) == d[22:]


def iban_check_digits(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return f"{98 - (int(numeric) % 97):02d}"


def is_valid_iban(iban: str) -> bool:
    s = re.sub(r"\s", "", iban).upper()
    numeric = "".join(str(int(ch, 36)) for ch in s[4:] + s[:4])
    return int(numeric) % 97 == 1


def synthetic_twin(kind: str, value: str = "", index: int = 1) -> str:
    """Deterministic (per kind+value) format-valid fake replacement.

    Strict formats use reserved / impossible prefixes (CIN `ZZ`, bank code `999`,
    phone `+2126000000NN`) so the twin can never collide with a real person.
    """
    kind = kind_from_rule(kind)
    seed = f"{kind}|{value}" if value else f"{kind}|#{index}"
    if kind == "cin":
        m = re.match(r"^([A-Za-z]{1,2})(\d{5,6})$", value.strip()) if value else None
        n_digits = len(m.group(2)) if m else 6
        return "ZZ" + _digits(seed, n_digits)
    if kind == "rib":
        body = "999" + _digits(seed, 19)              # 999 = reserved/fake bank code
        twin = body + rib_key(body)
        sep = re.search(r"[ -]", value or "")
        if sep:  # keep the original grouping style
            ch = sep.group(0)
            twin = ch.join([twin[:3], twin[3:6], twin[6:22], twin[22:]])
        return twin
    if kind == "iban":
        bban = "999" + _digits(seed, 19)
        bban += rib_key(bban)
        return f"MA{iban_check_digits('MA', bban)}{bban}"
    if kind == "cne":
        return "Z" + _digits(seed, 9)
    if kind == "phone":
        nn = _digits(seed, 2)
        if value and re.match(r"^0[5-7]", value.strip()):
            return f"06000000{nn}"
        return f"+2126000000{nn}"
    if kind == "email":
        return f"synth.user{_digits(seed, 3)}@example.com"
    if kind == "jwt":
        def b64(obj: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
        return f"{b64({'alg': 'none', 'typ': 'SYNTH'})}.{b64({'sub': f'SYNTH_USER_{_hex(seed, 6)}'})}.SYNTH_SIGNATURE"
    if kind == "aws":
        return "AKIASYNTH" + _hex(seed, 11).upper()
    if kind == "db_uri":
        scheme = (value.split("://", 1)[0] if "://" in (value or "") else "postgresql")
        return f"{scheme}://synth_user:SYNTH_PASSWORD@db.example.com:5432/app"
    if kind == "cmi_key":
        return f"cmi_test_SYNTH_{_hex(seed, 10)}"
    label = "SECRET" if kind == "secret" else "VALUE"
    return f"SYNTH_{label}_{_hex(seed, 8) if value else index}"


# --------------------------------------------------------------------------- .env extraction

_ASSIGN_RE = re.compile(
    r"""^(?P<indent>\s*)(?P<decl>(?:export\s+)?(?:const|let|var)\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>[=:])\s*(?P<q>["'`])(?P<value>.*)(?P=q)\s*(?P<tail>[;,]?)\s*(?P<comment>(?:#|//).*)?$"""
)


def _env_name(text: str) -> str:
    name = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper()
    if not name or name[0].isdigit():
        name = "SECRET_" + name
    return name[:60]


def _language_for(path: str) -> str:
    p = (path or "").lower()
    if p.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return "javascript"
    return "python"


def extract_to_env(finding: Finding, language: str = "python") -> Tuple[str, str, str]:
    """Returns (replacement_code, ENV_NAME, value) for moving a secret into `.env`."""
    snippet = (finding.offending_snippet or "").strip()
    js = language.lower() in ("javascript", "js", "typescript", "ts")
    m = _ASSIGN_RE.match(snippet)
    if m:
        name = finding.env_var_name or _env_name(m.group("name"))
        value = finding.env_var_value or m.group("value")
        var = m.group("name")
        if js:
            decl = m.group("decl") or ""
            code = f"{decl}{var} = process.env.{name}{';' if (m.group('tail') == ';' or decl) else ''}"
        elif m.group("op") == ":":  # dict entry  "key": "value",
            code = f'{snippet.split(":", 1)[0]}: os.getenv("{name}", ""){m.group("tail")}'
        else:
            code = f'{var} = os.getenv("{name}", "")'
        return code, name, value
    value = finding.env_var_value or snippet.strip("\"'`")
    base = finding.env_var_name or {
        "cmi_key": "CMI_MERCHANT_KEY", "aws": "AWS_ACCESS_KEY_ID", "jwt": "JWT_TOKEN",
        "db_uri": "DATABASE_URL",
    }.get(kind_from_rule(finding.rule_id), _env_name(finding.rule_id.split(".")[-1] or "SECRET"))
    name = _env_name(base)
    code = f"process.env.{name}" if js else f'os.getenv("{name}", "")'
    return code, name, value


# --------------------------------------------------------------------------- text patching

_TEXT_ACTIONS = {ActionType.SYNTHETIC_TWIN, ActionType.ENV_EXTRACT, ActionType.CODE_PATCH,
                 ActionType.SOLID_MASK, ActionType.GAUSSIAN_BLUR}


def _action(value: Any) -> Optional[ActionType]:
    if value is None:
        return None
    try:
        return ActionType(value.value if isinstance(value, ActionType) else str(value))
    except ValueError:
        return None


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _reindent(replacement: str, indent: str) -> List[str]:
    rep = textwrap.dedent(replacement.strip("\n"))
    return [(indent + ln) if ln.strip() else "" for ln in rep.split("\n")]


def _replacement_for(f: Finding, action: ActionType) -> Tuple[Optional[str], Optional[Tuple[str, str]]]:
    """Returns (replacement_text, (env_name, env_value) or None)."""
    if action in (ActionType.SOLID_MASK, ActionType.GAUSSIAN_BLUR):
        return "[REDACTED]", None
    if action == ActionType.SYNTHETIC_TWIN:
        if f.replacement_snippet and f.recommended_action == ActionType.SYNTHETIC_TWIN:
            return f.replacement_snippet, None
        return synthetic_twin(kind_from_rule(f.rule_id), (f.offending_snippet or "").strip()), None
    if action == ActionType.ENV_EXTRACT:
        code, name, value = extract_to_env(f, _language_for(f.file_path))
        if f.replacement_snippet and f.recommended_action == ActionType.ENV_EXTRACT:
            code = f.replacement_snippet
        name = f.env_var_name or name
        value = f.env_var_value or value
        return code, (name, value)
    if action == ActionType.CODE_PATCH:
        return f.replacement_snippet, None
    return None, None


def _find_block(lines: List[str], snippet_lines: List[str], candidates: Iterable[int]) -> Optional[int]:
    want = [s.strip() for s in snippet_lines if s.strip()]
    if not want:
        return None
    for i in candidates:
        j, k = i, 0
        while j < len(lines) and k < len(want):
            if not lines[j].strip():
                j += 1
                continue
            if lines[j].strip() != want[k]:
                break
            j, k = j + 1, k + 1
        if k == len(want):
            return i
    return None


def _candidate_lines(f: Finding, n: int) -> List[int]:
    """Lines to search: the reported line first, then a +-2 window, then the whole file."""
    order: List[int] = []
    if f.line_start:
        ls = f.line_start - 1
        le = (f.line_end or f.line_start) - 1
        order += list(range(ls, le + 1))
        for d in (1, 2):
            order += [ls - d, le + d]
    order += list(range(n))
    seen, out = set(), []
    for i in order:
        if 0 <= i < n and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _apply_one(lines: List[str], f: Finding, action: ActionType, replacement: str) -> bool:
    snippet = f.offending_snippet or ""
    full_line_mode = action in (ActionType.CODE_PATCH, ActionType.ENV_EXTRACT)
    cands = _candidate_lines(f, len(lines))
    if snippet.strip() and "\n" not in snippet.strip():
        s = snippet.strip()
        # env_extract on a bare value: swap the whole quoted literal for the getenv call
        if action == ActionType.ENV_EXTRACT and not _ASSIGN_RE.match(s):
            for i in cands:
                for q in ('"', "'", "`"):
                    lit = f"{q}{s}{q}"
                    if lit in lines[i]:
                        lines[i] = lines[i].replace(lit, replacement.strip(), 1)
                        return True
        for i in cands:
            col = lines[i].find(s)
            if col < 0:
                continue
            line = lines[i]
            prefix, rest = line[:col], line[col + len(s):]
            if full_line_mode and not prefix.strip() and not rest.strip():
                lines[i: i + 1] = _reindent(replacement, prefix)
            else:
                rep_lines = replacement.split("\n")
                if len(rep_lines) > 1:
                    ind = _indent_of(line)
                    rep_lines = [rep_lines[0]] + [(ind + r.lstrip()) if r.strip() else "" for r in rep_lines[1:]]
                new = (prefix + "\n".join(rep_lines) + rest).split("\n")
                lines[i: i + 1] = new
            return True
    elif snippet.strip():
        snip_lines = snippet.strip("\n").split("\n")
        start = _find_block(lines, snip_lines, cands)
        if start is not None:
            # find end of the matched block (skipping blank lines like _find_block)
            want = len([s for s in snip_lines if s.strip()])
            j, k = start, 0
            while k < want:
                if lines[j].strip():
                    k += 1
                j += 1
            lines[start:j] = _reindent(replacement, _indent_of(lines[start]))
            return True
    # Fallback: replace the reported line range (pitfall #5: callers apply in reverse order)
    if f.line_start and 1 <= f.line_start <= len(lines) and action != ActionType.SYNTHETIC_TWIN and full_line_mode:
        ls = f.line_start - 1
        le = min(len(lines), f.line_end or f.line_start)
        lines[ls:le] = _reindent(replacement, _indent_of(lines[ls]))
        return True
    return False


def _ensure_import_os(lines: List[str]) -> List[str]:
    if any(re.match(r"^\s*import\s+os\b|^\s*from\s+os\s+import\b|^import\s+.*\bos\b", ln) for ln in lines):
        return lines
    i = 0
    # skip shebang / encoding comments
    while i < len(lines) and lines[i].startswith("#"):
        i += 1
    # skip module docstring
    if i < len(lines) and lines[i].lstrip().startswith(('"""', "'''", 'r"""', "r'''")):
        quote = '"""' if '"""' in lines[i] else "'''"
        first = lines[i]
        if first.count(quote) >= 2:
            i += 1
        else:
            i += 1
            while i < len(lines) and quote not in lines[i]:
                i += 1
            i += 1
    while i < len(lines) and lines[i].startswith("from __future__"):
        i += 1
    return lines[:i] + ["import os"] + lines[i:]


def _apply(text: str, findings: List[Finding], decisions: Dict[str, Any]
           ) -> Tuple[str, List[str], List[str], List[Tuple[str, str]]]:
    lines = text.split("\n")
    applied: List[str] = []
    skipped: List[str] = []
    env_vars: List[Tuple[str, str]] = []
    selected = []
    for f in findings:
        act = _action(decisions.get(f.id))
        if act is None or act == ActionType.WHITELIST or act not in _TEXT_ACTIONS or f.target_type == "image":
            skipped.append(f.id)
            continue
        selected.append((f, act))
    # Pitfall #5: reverse line order; line-less findings last (they search the whole file).
    selected.sort(key=lambda fa: (fa[0].line_start is not None, fa[0].line_start or 0), reverse=True)
    needs_os = False
    for f, act in selected:
        replacement, env = _replacement_for(f, act)
        if replacement is None or not _apply_one(lines, f, act, replacement):
            skipped.append(f.id)
            continue
        applied.append(f.id)
        if env and env[0] and env[1] and env[0] not in [e[0] for e in env_vars]:
            env_vars.append(env)
        if ("os.getenv" in replacement or "os.environ" in replacement) and _language_for(f.file_path) == "python":
            needs_os = True
    if needs_os:
        lines = _ensure_import_os(lines)
    return "\n".join(lines), applied, skipped, env_vars


def apply_text_fixes(text: str, findings: List[Finding], decisions: Dict[str, ActionType | str]) -> str:
    """Apply the human-selected actions (finding.id -> ActionType) to `text`."""
    return _apply(text, findings, decisions)[0]


def preview_patch(text: str, findings: List[Finding], decisions: Dict[str, ActionType | str],
                  filename: str = "file") -> str:
    patched = apply_text_fixes(text, findings, decisions)
    return "".join(difflib.unified_diff(
        text.splitlines(keepends=True), patched.splitlines(keepends=True),
        fromfile=f"a/{filename}", tofile=f"b/{filename}",
    ))


def _project_root_for(path: Path) -> Path:
    for d in [path.parent, *path.parent.parents]:
        if (d / ".git" / "HEAD").is_file() or (d / ".git").is_file() or (d / ".plutonium.yaml").is_file():
            return d
    return path.parent


def _append_env(env_path: Path, env_vars: List[Tuple[str, str]]) -> List[str]:
    existing: Dict[str, str] = {}
    content = env_path.read_text(encoding="utf-8") if env_path.is_file() else ""
    for line in content.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            existing[s.removeprefix("export ").split("=", 1)[0].strip()] = s
    added = []
    new_lines = []
    for name, value in env_vars:
        if name in existing or name in added:
            continue
        v = value.replace("\n", "\\n")
        new_lines.append(f'{name}="{v}"' if re.search(r"[\s#'\"]", v) else f"{name}={v}")
        added.append(name)
    if new_lines:
        env_path.parent.mkdir(parents=True, exist_ok=True)
        if content and not content.endswith("\n"):
            content += "\n"
        if not content:
            content = "# Secrets extracted by Plutonium - never commit this file\n"
        env_path.write_text(content + "\n".join(new_lines) + "\n", encoding="utf-8")
    return added


def apply_to_disk(path: str, findings: List[Finding], decisions: Dict[str, ActionType | str],
                  env_path: Optional[str] = None, root: Optional[str] = None) -> Dict[str, Any]:
    """Patch `path` in place (backup under `<root>/.plutonium/backups/`) and append `.env` vars."""
    p = Path(path)
    original = p.read_text(encoding="utf-8")
    patched, applied, skipped, env_vars = _apply(original, findings, decisions)
    base = Path(root) if root else _project_root_for(p.resolve())
    backup = None
    if patched != original:
        bdir = base / ".plutonium" / "backups"
        bdir.mkdir(parents=True, exist_ok=True)
        backup = bdir / f"{p.name}.{time.strftime('%Y%m%d-%H%M%S')}.bak"
        shutil.copy2(p, backup)
        p.write_text(patched, encoding="utf-8")
    env_file = Path(env_path) if env_path else base / ".env"
    added = _append_env(env_file, env_vars) if env_vars else []
    diff = "".join(difflib.unified_diff(
        original.splitlines(keepends=True), patched.splitlines(keepends=True),
        fromfile=f"a/{p.name}", tofile=f"b/{p.name}",
    ))
    return {
        "file": str(p), "applied": applied, "skipped": skipped,
        "env_vars": [n for n, _ in env_vars], "env_added": added,
        "env_path": str(env_file) if env_vars else None,
        "backup": str(backup) if backup else None, "diff": diff,
    }


# --------------------------------------------------------------------------- images

def bbox_to_pixels(bbox_2d: List[float], width: int, height: int, pad: float = 0.15) -> Tuple[int, int, int, int]:
    """Gemma `[ymin, xmin, ymax, xmax]` (0-1000) -> padded, clamped pixel `(x1, y1, x2, y2)`.

    Padding is `pad` x box size on each side (pitfall #4); horizontal padding is capped at
    0.75 x box height so wide one-line text boxes don't swallow the neighbouring label.
    """
    if not bbox_2d or len(bbox_2d) != 4:
        raise ValueError("bbox_2d must be [ymin, xmin, ymax, xmax]")
    ymin, xmin, ymax, xmax = [max(0.0, min(1000.0, float(v))) for v in bbox_2d]
    ymin, ymax = sorted((ymin, ymax))
    xmin, xmax = sorted((xmin, xmax))
    x1, x2 = xmin / 1000 * width, xmax / 1000 * width
    y1, y2 = ymin / 1000 * height, ymax / 1000 * height
    py = (y2 - y1) * pad
    px = min((x2 - x1) * pad, (y2 - y1) * 0.75)
    x1 = max(0, int(x1 - px))
    y1 = max(0, int(y1 - py))
    x2 = min(width, int(round(x2 + px + 0.4999)))
    y2 = min(height, int(round(y2 + py + 0.4999)))
    if x2 <= x1:
        x2 = min(width, x1 + 1)
    if y2 <= y1:
        y2 = min(height, y1 + 1)
    return x1, y1, x2, y2


def _font(size: int):
    from PIL import ImageFont
    for cand in ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "DejaVuSans-Bold.ttf", "Arial.ttf"):
        try:
            return ImageFont.truetype(cand, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # Pillow < 10.1
        return ImageFont.load_default()


def redact_image(path: str, boxes: List[List[int]], style: str = "gaussian_blur",
                 out_path: Optional[str] = None) -> str:
    """Blur or mask every `[ymin, xmin, ymax, xmax]` (0-1000) box; returns the output path."""
    from PIL import Image, ImageDraw, ImageFilter

    style = _action(style).value if _action(style) else "gaussian_blur"
    img = Image.open(path).convert("RGB")
    w, h = img.size
    draw = ImageDraw.Draw(img)
    for bbox in boxes or []:
        x1, y1, x2, y2 = bbox_to_pixels(bbox, w, h)
        bw, bh = x2 - x1, y2 - y1
        if bw <= 0 or bh <= 0:
            continue
        if style == ActionType.SOLID_MASK.value:
            draw.rectangle([x1, y1, x2 - 1, y2 - 1], fill=(0, 0, 0))
        else:
            region = img.crop((x1, y1, x2, y2))
            # pixelate then blur: unreadable even for large OCR-friendly fonts
            small = region.resize((max(1, bw // 10), max(1, bh // 10)), Image.BILINEAR)
            region = small.resize((bw, bh), Image.BILINEAR)
            region = region.filter(ImageFilter.GaussianBlur(radius=max(12, bh / 3)))
            img.paste(region, (x1, y1))
    if out_path is None:
        p = Path(path)
        out_path = str(p.with_name(f"{p.stem}.redacted.png"))
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    img.save(out_path, format="PNG")
    return out_path


# --------------------------------------------------------------------------- Safe-to-Prompt firewall

_TOKEN_RE = re.compile(r"\[[A-Z]+(?:_[A-Z]+)*_(?:TOKEN|KEY)_\d+\]")

_PRIVATE_IP = (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
               r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}")
_HOST_END = r"(?![A-Za-z0-9-]|\.[A-Za-z0-9])"
# URL form: any host under a private suffix; bare form: needs at least one sub-label.
_PRIVATE_HOST = r"(?:(?:[a-z0-9-]+\.)*(?:um6p\.ma|internal|local|corp|lan)|localhost|" + _PRIVATE_IP + ")" + _HOST_END
_PRIVATE_HOST_BARE = r"(?:(?:[a-z0-9-]+\.)+(?:um6p\.ma|internal|corp|lan)|" + _PRIVATE_IP + ")" + _HOST_END

# (token prefix, pattern, group carrying the sensitive value). ORDER MATTERS.
_SANITIZE_RULES: List[Tuple[str, re.Pattern, int]] = [
    ("SECRET_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), 0),
    ("SECRET_KEY", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"), 0),
    ("SECRET_KEY", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@[^\s\"'<>]+"), 0),
    ("URL_TOKEN", re.compile(r"\bhttps?://(?:" + _PRIVATE_HOST + r")(?::\d+)?(?:/[^\s\"'<>)\]]*)?", re.I), 0),
    ("SECRET_KEY", re.compile(r"\b(?:cmi_live_[A-Za-z0-9_]{6,}|sk_live_[A-Za-z0-9]{10,}|pz_live_[A-Za-z0-9]{8,}"
                              r"|(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}"
                              r"|hpc_tok_[A-Za-z0-9]{8,}|xox[baprs]-[A-Za-z0-9-]{10,})"), 0),
    ("SECRET_KEY", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})"), 1),
    ("SECRET_KEY", re.compile(r"(?i)\b[A-Za-z0-9_]*(?:secret|passw(?:or)?d|pwd|api[_-]?key|token|store[_-]?key)"
                              r"[A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,})"), 1),
    ("IBAN_TOKEN", re.compile(r"\bMA\d{2}[ ]?(?:\d[ ]?){23}\d\b"), 0),
    ("RIB_TOKEN", re.compile(r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{16}[ -]?\d{2}(?!\d)"), 0),
    ("EMAIL_TOKEN", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0),
    ("PHONE_TOKEN", re.compile(r"(?<![\d+])(?:\+212[ -]?|00212[ -]?|0)[5-7](?:[ .-]?\d){8}(?!\d)"), 0),
    ("URL_TOKEN", re.compile(r"(?<![A-Za-z0-9.-])" + _PRIVATE_HOST_BARE + r"(?::\d+)?", re.I), 0),
    ("CNE_TOKEN", re.compile(r"(?<![A-Za-z0-9_])[A-Z]\d{9}(?![A-Za-z0-9])"), 0),
    ("CIN_TOKEN", re.compile(r"(?<![A-Za-z0-9_])[A-Z]{1,2}\d{5,6}(?![A-Za-z0-9])"), 0),
]


class _Vault:
    def __init__(self, vault: Optional[Dict[str, str]] = None):
        self.vault: Dict[str, str] = dict(vault or {})
        self.reverse: Dict[str, str] = {v: k for k, v in self.vault.items()}
        self.counters: Dict[str, int] = {}
        for tok in self.vault:
            m = re.match(r"\[(.+)_(\d+)\]$", tok)
            if m:
                self.counters[m.group(1)] = max(self.counters.get(m.group(1), 0), int(m.group(2)))

    def token(self, prefix: str, value: str) -> str:
        if value in self.reverse:
            return self.reverse[value]
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        tok = f"[{prefix}_{self.counters[prefix]}]"
        self.vault[tok] = value
        self.reverse[value] = tok
        return tok


def _sub_outside_tokens(text: str, pattern: re.Pattern, repl: Callable[[re.Match], str]) -> str:
    out, pos = [], 0
    for m in _TOKEN_RE.finditer(text):
        out.append(pattern.sub(repl, text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(pattern.sub(repl, text[pos:]))
    return "".join(out)


def sanitize_prompt(text: str, config=None, vault: Optional[Dict[str, str]] = None) -> Tuple[str, Dict[str, str]]:
    """Deterministic on-device tokenization. Same value -> same token. Returns (sanitized, vault)."""
    v = _Vault(vault)
    allow = (lambda s: config.is_allowlisted(s)) if config is not None else (lambda s: "SYNTH" in s)

    for prefix, pattern, group in _SANITIZE_RULES:
        def repl(m: re.Match, prefix=prefix, group=group) -> str:
            value = m.group(group) if group else m.group(0)
            if not value or allow(value):
                return m.group(0)
            tok = v.token(prefix, value)
            if group:
                s, e = m.start(group) - m.start(0), m.end(group) - m.start(0)
                return m.group(0)[:s] + tok + m.group(0)[e:]
            return tok
        text = _sub_outside_tokens(text, pattern, repl)
    return text, v.vault


_LLM_SCHEMA = {
    "type": "object",
    "properties": {"entities": {"type": "array", "items": {
        "type": "object",
        "properties": {"text": {"type": "string"}, "type": {"type": "string"}},
        "required": ["text", "type"]}}},
    "required": ["entities"],
}

_LLM_SYSTEM = (
    "You are an on-device privacy filter. List every remaining personal or sensitive entity in the text: "
    "person names, home addresses, card numbers, national IDs, student IDs, medical notes, and PII written in "
    "Moroccan Darija (Latin or Arabic script), French or Arabic. Ignore placeholders like [CIN_TOKEN_1]. "
    "Copy each entity EXACTLY as it appears. type is one of: name, address, id, financial, health, other."
)


def sanitize_prompt_llm(text: str, router=None, config=None) -> Tuple[str, Dict[str, str]]:
    """Regex tokenization + local Ollama gemma4:e4b NER pass. Never leaves the machine;
    silently falls back to the regex result when Ollama is unavailable."""
    sanitized, vault = sanitize_prompt(text, config)
    try:
        if router is None:
            from plutonium.llm_router import GemmaRouter
            router = GemmaRouter()
        if not router.ollama_available():
            return sanitized, vault
        data = router.call_local_ollama(sanitized, _LLM_SYSTEM, [], _LLM_SCHEMA)
        v = _Vault(vault)
        prefixes = {"name": "NAME_TOKEN", "address": "ADDRESS_TOKEN", "id": "ID_TOKEN",
                    "financial": "FIN_TOKEN", "health": "HEALTH_TOKEN"}
        ents = sorted((data or {}).get("entities", []) or [], key=lambda e: -len(str(e.get("text", ""))))
        for ent in ents:
            val = str(ent.get("text", "")).strip()
            if len(val) < 3 or val not in sanitized or _TOKEN_RE.search(val) or val in v.reverse:
                continue
            tok = v.token(prefixes.get(str(ent.get("type", "")).lower(), "PII_TOKEN"), val)
            sanitized = _sub_outside_tokens(sanitized, re.compile(re.escape(val)), lambda m, t=tok: t)
        return sanitized, v.vault
    except Exception:  # noqa: BLE001 - local model is best-effort
        return sanitize_prompt(text, config)


def rehydrate(text: str, vault: Dict[str, str]) -> str:
    """Swap `[CIN_TOKEN_1]` (or a bracket-less `CIN_TOKEN_1` echoed by an LLM) back to the original."""
    for tok in sorted(vault, key=len, reverse=True):
        text = text.replace(tok, vault[tok])
    for tok in sorted(vault, key=len, reverse=True):
        bare = tok.strip("[]")
        text = re.sub(r"(?<![A-Za-z0-9_\[])" + re.escape(bare) + r"(?![0-9\]])", lambda m, v=vault[tok]: v, text)
    return text
