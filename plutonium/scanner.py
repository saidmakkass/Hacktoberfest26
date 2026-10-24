"""Plutonium scanner: regex baseline + cross-file heuristics + Gemma 4 analysis.

Snippet / patch convention (consumed by ``redactor.apply_text_fixes``, which substring-
replaces ``offending_snippet`` -> ``replacement_snippet`` and re-indents block patches):

* ``synthetic_twin``  -> ``offending_snippet`` is the exact matched value (e.g. ``BE847291``)
  and ``replacement_snippet`` the format-valid twin value.
* ``env_extract``     -> ``offending_snippet`` is the full source line stripped of its
  indentation (``CMI_WEBHOOK_SECRET = "cmi_live_..."``) and ``replacement_snippet`` the
  rewritten line (``CMI_WEBHOOK_SECRET = os.getenv("CMI_WEBHOOK_SECRET", "")``). When the
  secret is a standalone literal that is not assigned to a name (dict value, call argument)
  the snippet is the literal's content and the replacement the bare ``os.getenv(...)`` call.
* ``code_patch``      -> ``offending_snippet`` is the exact source line(s); multi-line
  snippets keep their relative indentation (first line stripped). ``replacement_snippet``
  is a drop-in, dedented block relative to the first offending line's indentation.

In notebooks (``.ipynb``) secrets are twinned rather than env-extracted so the raw JSON
stays valid, and line numbers refer to the raw JSON file.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from plutonium.config import PlutoniumConfig, load_config
from plutonium.indexer import CodebaseIndexer, render_notebook
from plutonium.models import (
    ActionType, CodeChunk, EngineMode, Finding, FindingCategory, ScanResult, Severity,
)

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CLOUD_MODES = (EngineMode.CLOUD_FAST, EngineMode.CLOUD_DEEP)

# --------------------------------------------------------------------------- schemas
_FINDING_PROPS = {
    "category": {"type": "string", "enum": ["security_leak", "privacy_pii", "logical_bug"]},
    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
    "file_path": {"type": "string"},
    "line_start": {"type": "integer"},
    "line_end": {"type": "integer"},
    "rule_id": {"type": "string"},
    "title": {"type": "string"},
    "reason": {"type": "string"},
    "confidence": {"type": "number"},
    "cross_file_context_used": {"type": "string"},
    "offending_snippet": {"type": "string"},
    "recommended_action": {"type": "string", "enum": ["synthetic_twin", "env_extract", "code_patch"]},
    "replacement_snippet": {"type": "string"},
    "env_var_name": {"type": "string"},
    "env_var_value": {"type": "string"},
}

SCAN_RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "thinking_trace": {"type": "string"},
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": _FINDING_PROPS,
                "required": ["category", "severity", "file_path", "line_start", "title", "reason",
                             "offending_snippet", "recommended_action", "replacement_snippet"],
            },
        },
    },
    "required": ["thinking_trace", "summary", "findings"],
}

IMAGE_RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "text": {"type": "string"},
                    "category": {"type": "string", "enum": ["security_leak", "privacy_pii", "logical_bug"]},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    "bbox_2d": {"type": "array", "items": {"type": "integer"}},
                    "reason": {"type": "string"},
                },
                "required": ["label", "text", "category", "severity", "bbox_2d", "reason"],
            },
        },
    },
    "required": ["summary", "findings"],
}


# --------------------------------------------------------------------------- small helpers
def _fid(*parts: Any) -> str:
    return hashlib.sha1(":".join(str(p) for p in parts).encode("utf-8", "ignore")).hexdigest()[:10]


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _block(lines: List[str], a: int, b: int) -> str:
    """Exact source lines a..b (1-based, inclusive) with the common indentation removed."""
    return textwrap.dedent("\n".join(lines[a - 1:b])).strip("\n")


def _label(c: CodeChunk) -> str:
    return f"{c.file_path}:{c.symbol_name}"


def _mk(file_path: str, line_start: Optional[int], line_end: Optional[int], rule_id: str,
        category: FindingCategory, severity: Severity, title: str, reason: str,
        offending: Optional[str], replacement: Optional[str], action: ActionType,
        confidence: float = 0.85, xfile: Optional[str] = None, regex: bool = False,
        env_name: Optional[str] = None, env_value: Optional[str] = None,
        target_type: str = "text", bbox: Optional[List[int]] = None) -> Finding:
    return Finding(
        id=_fid(file_path, line_start, rule_id, offending or title),
        category=category, target_type=target_type, file_path=file_path,
        line_start=line_start, line_end=line_end if line_end is not None else line_start,
        rule_id=rule_id, severity=severity, confidence=max(0.0, min(1.0, confidence)),
        title=title, reason=reason, cross_file_context_used=xfile, offending_snippet=offending,
        recommended_action=action, replacement_snippet=replacement, env_var_name=env_name,
        env_var_value=env_value, bbox_2d=bbox, caught_by_regex_baseline=regex,
    )


def _twin(rule_or_kind: str, value: str, index: int) -> str:
    try:
        from plutonium.redactor import synthetic_twin  # written concurrently; optional
        return synthetic_twin(rule_or_kind, value, index)
    except Exception:  # noqa: BLE001
        kind = re.sub(r"[^A-Z0-9]+", "_", rule_or_kind.split(".")[-1].upper()).strip("_") or "VALUE"
        return f"[SYNTH_{kind}_{index}]"


# --------------------------------------------------------------------------- regex baseline
_ASSIGN = re.compile(
    r"""^(?P<decl>(?:export\s+)?(?:const|let|var)\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"""
    r"""(?::\s*[\w\[\], .|]+)?=\s*(?P<q>["'`])(?P<value>.*)(?P=q)\s*;?\s*(?:(?:#|//).*)?$""")
_LITERAL = re.compile(r"""(?P<prefix>(?<![\w"'])[rRbBuU]?[fF]?)(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""")
_ENV_SAFE_MARKERS = ("os.getenv", "os.environ", "process.env")
_LAW = {"ma": "Moroccan Law 09-08 / CNDP", "lab": "student-privacy (Law 09-08) and lab security policy",
        "gen": "DevSecOps secret-hygiene policy"}


_SYNTHETIC_TWIN = re.compile(r"^(ZZ\d{5,6}|Z\d{9}|999[ -]?\d{3}[ -]?\d{16}[ -]?\d{2}|\+?(212)?0?6000000\d{2}|"
                             r"MA\d{2}999\d{21}|cmi_test_SYNTH_\w+|AKIASYNTH\w+)$")


def _allowlisted(cfg: PlutoniumConfig, value: str, line: str) -> bool:
    if cfg.is_allowlisted(value) or _SYNTHETIC_TWIN.match(value.strip()):
        return True  # explicit allowlist, or a reserved-prefix synthetic twin we generated
    return any(a in line for a in cfg.allowlist if a in _ENV_SAFE_MARKERS)


def _env_name_from(text: str, fallback: str) -> str:
    name = re.sub(r"[^A-Za-z0-9]+", "_", text or "").strip("_").upper()
    if not name:
        name = fallback
    if name[0].isdigit():
        name = "SECRET_" + name
    return name[:60]


def regex_baseline(text: str, file_path: str, preset: str = "all",
                   config: Optional[PlutoniumConfig] = None) -> List[Finding]:
    """Gitleaks/Presidio-style deterministic baseline: one finding per (line, value)."""
    cfg = config or load_config()
    rules = cfg.regex_rules(preset)
    is_nb = file_path.lower().endswith(".ipynb")
    is_js = file_path.lower().endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    out: List[Finding] = []
    counters: Counter = Counter()
    for ln, line in enumerate((text or "").splitlines(), 1):
        hits = []
        for r in rules:
            for m in r.compiled.finditer(line):
                val = m.group(0)
                if val.strip() and not _allowlisted(cfg, val, line):
                    hits.append((r, m.start(), m.end(), val))
        hits.sort(key=lambda h: (SEV_RANK.get(h[0].severity, 9), "generic" in h[0].id, -(h[2] - h[1])))
        kept: List[list] = []
        for h in hits:
            over = next((k for k in kept if h[1] < k[2] and k[1] < h[2]), None)
            if over is None:
                kept.append([*h, []])
            elif h[0].id != over[0].id and h[0].title not in over[4]:
                over[4].append(h[0].title)
        for r, s, e, val, also in sorted(kept, key=lambda k: k[1]):
            counters[r.id] += 1
            idx = counters[r.id]
            try:
                sev = Severity(str(r.severity).upper())
                cat = FindingCategory(r.category)
            except ValueError:
                continue
            law = _LAW.get(r.id.split(".")[0], "policy")
            reason = f"{r.title} matched by the deterministic regex baseline ({r.id}); violates {law}."
            if also:
                reason += " Same value also matches: " + ", ".join(also) + "."
            action = ActionType(r.action) if r.action in ActionType._value2member_map_ else ActionType.SYNTHETIC_TWIN
            env_name = env_value = None
            offending, replacement = val, None
            if action == ActionType.ENV_EXTRACT and not is_nb:
                stripped = line.strip()
                am = _ASSIGN.match(stripped)
                if am and (val in am.group("value") or am.group("value") in val):
                    var = am.group("name")
                    env_name = _env_name_from(var, f"PLUTONIUM_SECRET_{idx}")
                    env_value = am.group("value")
                    offending = stripped
                    if is_js or am.group("decl"):
                        replacement = f"{am.group('decl') or 'const '}{var} = process.env.{env_name};"
                    else:
                        replacement = f'{var} = os.getenv("{env_name}", "")'
                else:
                    lit = next((lm for lm in _LITERAL.finditer(line)
                                if lm.start("body") <= s and e <= lm.end("body")), None)
                    if lit is not None and "f" not in lit.group("prefix").lower():
                        key = re.search(r"""["'](\w+)["']\s*:\s*$""", line[:lit.start()])
                        env_name = _env_name_from(key.group(1) if key else "",
                                                  f"PLUTONIUM_{r.id.split('.')[-1].upper()}_{idx}")
                        env_value = lit.group("body")
                        offending = env_value
                        replacement = f"process.env.{env_name}" if is_js else f'os.getenv("{env_name}", "")'
                    else:
                        action = ActionType.SYNTHETIC_TWIN
            elif action == ActionType.ENV_EXTRACT:
                action = ActionType.SYNTHETIC_TWIN
                reason += " Rotate this credential; it is persisted inside the notebook JSON."
            if action == ActionType.SYNTHETIC_TWIN:
                inner = re.search(r"""["'`]([^"'`]{6,})["'`]?""", val) if re.search(r"[=:]", val) else None
                offending = inner.group(1) if inner else val
                replacement = _twin(r.id, offending, idx)
            out.append(_mk(file_path, ln, ln, r.id, cat, sev, r.title, reason, offending, replacement,
                           action, confidence=0.85 if "cin" in r.id else 0.9, regex=True,
                           env_name=env_name, env_value=env_value))
    return out


# --------------------------------------------------------------------------- code structure
_DEF_RE = re.compile(r"^(\s*)(async\s+)?def\s+(\w+)\s*\(")


def _functions(lines: List[str]) -> List[dict]:
    """Regex-based function scopes (works on partial code and rendered notebooks)."""
    funcs = []
    for i, line in enumerate(lines):
        m = _DEF_RE.match(line)
        if not m:
            continue
        ind = len(m.group(1))
        header = line
        j = i
        while not header.rstrip().endswith(":") and j + 1 < len(lines) and j - i < 12:
            j += 1
            header += " " + lines[j].strip()
        end = j
        k = j + 1
        while k < len(lines):
            s = lines[k]
            if s.strip() and not s.lstrip().startswith("#") and len(_indent(s)) <= ind:
                break
            if s.strip():
                end = k
            k += 1
        decos, d = [], i - 1
        while d >= 0 and lines[d].strip().startswith("@") and len(_indent(lines[d])) == ind:
            decos.insert(0, lines[d].strip()[1:].split("(")[0].strip())
            d -= 1
        params = dict(re.findall(r"(\w+)\s*:\s*([A-Za-z_][\w.\[\]]*)", header.split("(", 1)[1].rsplit(")", 1)[0])) \
            if "(" in header else {}
        param_names = re.findall(r"[(,]\s*\*{0,2}(\w+)", "(" + header.split("(", 1)[1].rsplit(")", 1)[0]) \
            if "(" in header else []
        funcs.append({"name": m.group(3), "def": i + 1, "body_start": j + 2, "end": end + 1, "indent": ind,
                      "async": bool(m.group(2)), "decorators": decos, "params": params,
                      "param_names": param_names, "start": d + 2})
    return funcs


def _enclosing(funcs: List[dict], ln: int) -> Optional[dict]:
    best = None
    for f in funcs:
        if f["def"] <= ln <= f["end"] and (best is None or f["def"] > best["def"]):
            best = f
    return best


def _body(lines: List[str], f: Optional[dict]) -> str:
    if f is None:
        return "\n".join(lines)
    return "\n".join(lines[f["def"] - 1:f["end"]])


def _ctx_find(ctx: List[CodeChunk], pred: Callable[[CodeChunk], bool]) -> Optional[CodeChunk]:
    return next((c for c in ctx if pred(c)), None)


def _module_of(c: CodeChunk) -> str:
    return Path(c.file_path).stem


_PII_FIELD = re.compile(r"(cin|rib|iban|phone|tel|cne|massar|password|passwd|passport|ssn|email|national|"
                        r"card|address|birth|dob|full_name|first_name|last_name|^name$|salary|medical)", re.I)
_MONEY = re.compile(r"(amount|mad|eur|price|total|tva|vat|fee|balance|cost|subtotal|montant|prix)", re.I)


def _class_fields(code: str) -> List[str]:
    fields = re.findall(r"^\s+(\w+)\s*:\s*[^=\n(]+(?:=.*)?$", code, re.M)
    fields += re.findall(r"self\.(\w+)\s*=", code)
    return list(dict.fromkeys(f for f in fields if not f.startswith("_")))


# --------------------------------------------------------------------------- heuristics
_NON_CODE_SUFFIXES = {".yaml", ".yml", ".json", ".md", ".txt", ".csv", ".toml", ".env", ".ini", ".cfg", ".log", ".sql"}


def heuristic_logic_scan(text: str, file_path: str, context_chunks: List[CodeChunk]) -> List[Finding]:
    """Deterministic cross-file detectors that power the offline engine (and seed the LLM)."""
    lines = (text or "").splitlines()
    funcs = _functions(lines)
    ctx = list(context_chunks or [])
    out: List[Finding] = []
    detectors = [_det_darija]
    # Code detectors only make sense on source; data/config/prose files only get PII detectors.
    if Path(file_path or "").suffix.lower() not in _NON_CODE_SUFFIXES:
        detectors += [_det_object_dump, _det_float_currency, _det_toctou, _det_webhook,
                      _det_discount_stack, _det_negative_qty, _det_ml_leakage, _det_seed, _det_sentinel,
                      _det_sqli, _det_off_by_one, _det_none_deref, _det_missing_auth]
    for det in detectors:
        try:
            out.extend(det(lines, funcs, ctx, file_path))
        except Exception:  # noqa: BLE001 - one broken detector must never kill the gate
            continue
    return out


def _det_object_dump(lines, funcs, ctx, fp):
    out = []
    sink = re.compile(r"\b(logger|logging|log|LOGGER|print|console)\b[\w.]*\s*\(")
    dump = re.compile(r"(\w+)\.__dict__|vars\((\w+)\)|(\w+)\.(?:to_dict|dict|model_dump|asdict)\(\)|"
                      r"asdict\((\w+)\)|json\.dumps\((\w+)[,)]")
    for ln, line in enumerate(lines, 1):
        if not sink.search(line) or ".items() if" in line or "not in (" in line:
            continue
        m = dump.search(line)
        if not m:
            continue
        var = next(g for g in m.groups() if g)
        f = _enclosing(funcs, ln)
        cls = (f or {}).get("params", {}).get(var) if f else None
        if not cls:
            am = re.search(rf"\b{re.escape(var)}\s*:\s*([A-Z]\w*)", "\n".join(lines))
            cls = am.group(1) if am else None
        if not cls:
            am = re.search(rf"\b{re.escape(var)}\s*=\s*([A-Z]\w*)\(", "\n".join(lines))
            cls = am.group(1) if am else None
        if not cls:
            continue
        cls = cls.split(".")[-1].strip("[]")
        chunk = _ctx_find(ctx, lambda c: c.symbol_name == cls and c.chunk_type == "class")
        xfile = _label(chunk) if chunk else None
        code = chunk.code if chunk else ""
        if not chunk:
            local = re.search(rf"^class\s+{cls}\b[\s\S]*?(?=^\S|\Z)", "\n".join(lines), re.M)
            code = local.group(0) if local else ""
        fields = _class_fields(code)
        pii = [x for x in fields if _PII_FIELD.search(x)]
        if not pii:
            continue
        expr = m.group(0).rstrip(",)") if m.group(5) else m.group(0)
        pii_tuple = "(" + ", ".join(f"'{p}'" for p in pii) + ("," if len(pii) == 1 else "") + ")"
        safe = f"{{k: v for k, v in vars({var}).items() if k not in {pii_tuple}}}"
        in_fstring = re.search(r"\bf[\"']", line) and re.search(r"\{[^{}]*" + re.escape(expr), line)
        new_line = line.replace(expr, (" " + safe + " ") if in_fstring else safe, 1)
        out.append(_mk(
            fp, ln, ln, "heur.pii_object_dump", FindingCategory.PRIVACY_PII, Severity.CRITICAL,
            f"Logging full {cls} object leaks PII ({', '.join(pii)})",
            f"`{expr}` serializes every attribute of `{var}`. The codebase index resolves `{cls}`"
            + (f" in {chunk.file_path}" if chunk else "") + f", which holds PII fields {', '.join(pii)}. "
            "Writing them to logs violates Moroccan Law 09-08 / CNDP data minimisation. Patch logs only non-PII fields.",
            line.strip(), new_line.strip(), ActionType.CODE_PATCH, 0.93, xfile))
    return out


def _decimal_expr(expr: str) -> str:
    expr = expr.strip()
    if re.fullmatch(r"\d+(\.\d+)?", expr):
        return f'Decimal("{expr}")'
    return f"Decimal(str({expr}))"


def _det_float_currency(lines, funcs, ctx, fp):
    out = []
    rx = re.compile(r"round\(\s*(?P<a>[\w.\[\]\"']+)\s*\*\s*(?P<b>[\w.\[\]\"']+)\s*,\s*2\s*\)")
    for ln, line in enumerate(lines, 1):
        m = rx.search(line)
        if not m or not (_MONEY.search(m.group("a")) or _MONEY.search(m.group("b")) or _MONEY.search(line)):
            continue
        if "Decimal" in line:
            continue
        dec = (f"({_decimal_expr(m.group('a'))} * {_decimal_expr(m.group('b'))})"
               f'.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)')
        ind = _indent(line)
        patched = line.replace(m.group(0), dec, 1)
        repl = "from decimal import Decimal, ROUND_HALF_UP\n" + patched[len(ind):]
        f = _enclosing(funcs, ln)
        body = _body(lines, f)
        called = set(re.findall(r"\b(\w+)\s*\(", body))
        chunk = _ctx_find(ctx, lambda c: c.symbol_name in called and "float" in c.code
                          and c.chunk_type == "function")
        if chunk is None:
            joined = "\n".join(lines)
            chunk = _ctx_find(ctx, lambda c: c.chunk_type == "class" and re.search(rf"\b{c.symbol_name}\b", joined)
                              and re.search(r"_mad\s*:\s*float|amount\s*:\s*float", c.code))
        xfile = _label(chunk) if chunk else None
        out.append(_mk(
            fp, ln, ln, "heur.float_currency", FindingCategory.LOGICAL_BUG, Severity.HIGH,
            "Float arithmetic on MAD/EUR currency (ledger drift)",
            "IEEE-754 float multiplication + round(x, 2) uses banker's rounding on binary floats "
            "(e.g. 0.125 -> 0.12), producing 1-centime reconciliation mismatches between checkout, "
            "refunds and the CMI settlement file."
            + (f" The amount flows from `{chunk.symbol_name}` ({chunk.file_path}) which already returns a float." if chunk else "")
            + " Use Decimal with ROUND_HALF_UP (or integer centimes).",
            line.strip(), repl, ActionType.CODE_PATCH, 0.9, xfile))
    return out


def _det_toctou(lines, funcs, ctx, fp):
    out = []
    rx = re.compile(r"^\s*if\s+(?P<lhs>[\w.\[\]\"']*balance[\w.\[\]\"']*)\s*>=?\s*(?P<amt>[^:]+):")
    for ln, line in enumerate(lines, 1):
        m = rx.match(line)
        if not m:
            continue
        lhs = m.group("lhs")
        ind = len(_indent(line))
        end, deduct = ln, None
        for k in range(ln, min(len(lines), ln + 15)):
            s = lines[k]
            if s.strip() and len(_indent(s)) <= ind:
                break
            if s.strip():
                end = k + 1
            if re.search(re.escape(lhs) + r"\s*-=", s):
                deduct = k + 1
        if deduct is None:
            continue
        f = _enclosing(funcs, ln)
        body = _body(lines, f)
        if re.search(r"lock|transaction|select_for_update|for update|atomic|F\(", body, re.I):
            continue
        block = _block(lines, ln, end)
        repl = ('with globals().setdefault("_WALLET_LOCK", __import__("threading").Lock()):'
                "  # serialize check+debit (use SELECT ... FOR UPDATE in the DB)\n"
                + textwrap.indent(block, "    "))
        cls_chunk = _ctx_find(ctx, lambda c: c.chunk_type == "class" and lhs.split(".")[-1] in c.code)
        out.append(_mk(
            fp, ln, end, "heur.toctou_double_spend", FindingCategory.LOGICAL_BUG, Severity.HIGH,
            "TOCTOU wallet double-spend (check-then-debit without lock)",
            f"`{lhs}` is checked and then decremented in separate steps with no transaction lock, "
            "row lock (SELECT ... FOR UPDATE) or atomic UPDATE. Two concurrent checkouts can both pass "
            "the balance check and overdraw the wallet.",
            _block(lines, ln, end), repl, ActionType.CODE_PATCH, 0.85,
            _label(cls_chunk) if cls_chunk else None))
    return out


def _det_webhook(lines, funcs, ctx, fp):
    out = []
    for f in funcs:
        if not re.search(r"callback|webhook|ipn|notify", f["name"], re.I):
            continue
        body = _body(lines, f)
        if re.search(r"hmac|compare_digest|signature|verify|check_hash|hashlib", body, re.I):
            continue
        status_ln = None
        for ln in range(f["def"], f["end"] + 1):
            if re.search(r"""(APPROVED|["'](success|paid|captured|approved|ok)["'])""", lines[ln - 1]) and \
                    re.match(r"\s*(if|elif)\b", lines[ln - 1]):
                status_ln = ln
                break
        if status_ln is None or not re.search(r"\+=|credit|mark_paid|set_paid|fulfil", body):
            continue
        secret = _ctx_find(ctx, lambda c: c.chunk_type == "module" and "WEBHOOK_SECRET" in c.symbol_name)
        if secret is None:
            secret = _ctx_find(ctx, lambda c: c.chunk_type == "module" and
                               re.search(r"SECRET|MERCHANT_KEY|STORE_KEY|SIGNING", c.symbol_name))
        secret_name = secret.symbol_name if secret else "WEBHOOK_SECRET"
        req = (f["param_names"] or ["request"])[0]
        raw = f"await {req}.body()" if f["async"] else f"{req}.body"
        line = lines[status_ln - 1]
        repl = ("import hmac, hashlib\n"
                f"expected_sig = hmac.new({secret_name}.encode(), {raw}, hashlib.sha512).hexdigest()\n"
                f'if not hmac.compare_digest({req}.headers.get("X-CMI-Signature", ""), expected_sig):\n'
                '    return {"ok": False, "error": "invalid signature"}\n'
                + line.strip())
        imported = re.search(rf"import[^\n]*\b{secret_name}\b", "\n".join(lines))
        out.append(_mk(
            fp, status_ln, status_ln, "heur.webhook_no_hmac", FindingCategory.LOGICAL_BUG,
            Severity.CRITICAL if secret else Severity.HIGH,
            "Payment callback trusts payload without HMAC signature check",
            f"`{f['name']}` credits funds when the payload says APPROVED but never verifies the gateway "
            f"signature. " + (f"The merchant secret `{secret_name}` is defined in {secret.file_path}"
                              + (" and even imported here" if imported else "") + ", yet unused. " if secret else "")
            + "Anyone can POST a forged callback and credit arbitrary amounts; the credit is also a "
            "non-atomic read-modify-write (race condition).",
            line.strip(), repl, ActionType.CODE_PATCH, 0.92, _label(secret) if secret else None))
    return out


_ARABIC = re.compile(r"[؀-ۿ]")
_DARIJA = re.compile(r"\b(khouya|khoya|salam|rqm|raqm|l'?compte|dyali|diali|bghit|lflous|lbitaqa|wach|3afak|"
                     r"chouf|dial|hak|smiti|bghiti|bach|tsewelni|wakha|daba|mzyan|dyal|lia|liya)\b", re.I)
_PII_HINT = re.compile(r"(cin|rib|iban|phone|tel|carte|compte|card|account|smiti|adresse|\bhay\b|البطاقة|الحساب|رقم|بطاقة|هاتف)", re.I)


def _det_darija(lines, funcs, ctx, fp):
    out = []
    for ln, line in enumerate(lines, 1):
        if not (_ARABIC.search(line) or _DARIJA.search(line)):
            continue
        window = "\n".join(lines[max(0, ln - 3):ln + 2])
        if not _PII_HINT.search(window):
            continue
        lit = next((lm for lm in _LITERAL.finditer(line)
                    if _ARABIC.search(lm.group("body")) or _DARIJA.search(lm.group("body"))), None)
        if lit is None and Path(fp or "").suffix.lower() in _NON_CODE_SUFFIXES - {".json", ".yaml", ".yml", ".toml"}:
            offending = line.strip()  # plain-text logs / tickets: the whole line is the note
        elif lit is None:
            if not line.lstrip().startswith("#"):
                continue
            offending = line.strip().lstrip("#").strip()
        else:
            offending = lit.group("body")
        out.append(_mk(
            fp, ln, ln, "heur.darija_pii_note", FindingCategory.PRIVACY_PII, Severity.MEDIUM,
            "Darija / Arabic customer-support note with card & bank details",
            "Free-text customer note in Moroccan Darija (Latin/Arabic script) references card and bank "
            "account numbers; regex scanners ignore multilingual context. Personal data under Law 09-08 "
            "must not live in fixtures or logs.",
            offending, "[SYNTH_DARIJA_NOTE_1] synthetic support note (redacted)",
            ActionType.SYNTHETIC_TWIN, 0.8))
    return out


def _det_discount_stack(lines, funcs, ctx, fp):
    out = []
    rx = re.compile(r"^\s*(?P<var>\w+)\s*=\s*sum\((?P<arg>[^)]*(disc|promo|coupon|pct|percent|rebate)[^)]*)\)", re.I)
    for ln, line in enumerate(lines, 1):
        m = rx.match(line)
        if not m:
            continue
        f = _enclosing(funcs, ln)
        body = _body(lines, f)
        var = m.group("var")
        if re.search(rf"(min|max|clamp)\s*\([^)]*{var}|{var}\s*[<>]=?|assert", body):
            continue
        out.append(_mk(
            fp, ln, ln, "heur.promo_bypass", FindingCategory.LOGICAL_BUG, Severity.MEDIUM,
            "Stacked percentage discounts are never clamped (promo bypass)",
            f"`{var}` sums every discount percentage with no upper/lower bound: two 60% coupons yield "
            "a negative price (the merchant pays the customer); negative discounts inflate prices.",
            line.strip(), f"{var} = min(max(sum({m.group('arg')}), 0), 100)  # clamp stacked promos to [0, 100] %",
            ActionType.CODE_PATCH, 0.85))
    return out


def _det_negative_qty(lines, funcs, ctx, fp):
    out = []
    for f in funcs:
        qty = next((p for p in f["param_names"] if re.fullmatch(r"(quantity|qty|count|units|nb_items)", p, re.I)), None)
        if not qty:
            continue
        body = _body(lines, f)
        if re.search(rf"{qty}\s*(<=|<|>|>=)|(<=|<|>|>=)\s*{qty}\b|max\([^)]*{qty}|assert", body):
            continue
        use_ln = next((ln for ln in range(f["body_start"], f["end"] + 1)
                       if re.search(rf"\b{qty}\b", lines[ln - 1]) and re.search(r"\*", lines[ln - 1])), None)
        if use_ln is None:
            continue
        line = lines[use_ln - 1]
        called = set(re.findall(r"\b(\w+)\s*\(", line))
        chunk = _ctx_find(ctx, lambda c: c.symbol_name in called and c.chunk_type == "function")
        repl = (f"if not isinstance({qty}, int) or {qty} <= 0:\n"
                f'    raise ValueError("{qty} must be a positive integer")\n' + line.strip())
        out.append(_mk(
            fp, use_ln, use_ln, "heur.negative_quantity", FindingCategory.LOGICAL_BUG, Severity.MEDIUM,
            f"Missing bounds check on `{qty}` (negative quantity)",
            f"`{f['name']}` multiplies the price by `{qty}` without validating it is a positive integer; "
            "a negative quantity yields a negative total (credit / refund abuse)."
            + (f" `{chunk.symbol_name}` in {chunk.file_path} does not clamp its input either." if chunk else ""),
            line.strip(), repl, ActionType.CODE_PATCH, 0.8, _label(chunk) if chunk else None))
    return out


def _det_ml_leakage(lines, funcs, ctx, fp):
    out = []
    fit_rx = re.compile(r"^\s*(?P<out>\w+)\s*=\s*(?P<tr>.+?)\.fit_transform\(\s*(?P<inp>\w+)\s*\)")
    for ln, line in enumerate(lines, 1):
        m = fit_rx.match(line)
        if not m:
            continue
        f = _enclosing(funcs, ln)
        end = f["end"] if f else len(lines)
        split_ln = next((k for k in range(ln + 1, end + 1) if "train_test_split(" in lines[k - 1]), None)
        if split_ln is None:
            continue
        xs, inp, tr = m.group("out"), m.group("inp"), m.group("tr")
        split_line = lines[split_ln - 1]
        lhs = split_line.split("=", 1)[0]
        names = [n.strip() for n in lhs.split(",")]
        if len(names) < 2:
            continue
        new_split = re.sub(rf"\b{re.escape(xs)}\b", inp, split_line.split("=", 1)[1], count=1).strip()
        middle = [lines[k - 1].strip() for k in range(ln + 1, split_ln)]
        tr_name = re.sub(r"\W", "", tr.split("(")[0]).lower() or "scaler"
        tr_name = "scaler" if "scal" in tr_name else tr_name.replace("standardscaler", "scaler")
        repl_lines = [f"{lhs.strip()} = {new_split}", *[x for x in middle if x],
                      f"{tr_name} = {tr}.fit({names[0]})  # fit on the training split only",
                      f"{names[0]}, {names[1]} = {tr_name}.transform({names[0]}), {tr_name}.transform({names[1]})"]
        out.append(_mk(
            fp, ln, split_ln, "heur.ml_train_test_leakage", FindingCategory.LOGICAL_BUG, Severity.HIGH,
            "ML train/test leakage: transformer fitted before train_test_split",
            f"`{tr}.fit_transform({inp})` learns scaling statistics from the full dataset (including the "
            "future test rows) before `train_test_split`, so the reported test score is optimistically "
            "biased. Split first, fit on the training split only, then transform both splits.",
            _block(lines, ln, split_ln), "\n".join(repl_lines), ActionType.CODE_PATCH, 0.9))
    return out


def _det_seed(lines, funcs, ctx, fp):
    text = "\n".join(lines)
    if re.search(r"random\.seed\(|np\.random\.seed\(|default_rng\(\s*\w|manual_seed\(|set_seed\(", text):
        return []
    rx = re.compile(r"\b(random\.(shuffle|random|choice|choices|randint|sample|uniform)|np\.random\.\w+|"
                    r"numpy\.random\.\w+|torch\.(rand|randn|randint|randperm))\s*\(")
    for ln, line in enumerate(lines, 1):
        m = rx.search(line)
        if not m or line.lstrip().startswith("#"):
            continue
        seed = _ctx_find(ctx, lambda c: c.chunk_type == "module" and re.search(r"(^|_)SEED$|RANDOM_STATE", c.symbol_name))
        call = m.group(1)
        seeder = "np.random.seed" if "random." in call and call.startswith(("np", "numpy")) else \
            "torch.manual_seed" if call.startswith("torch") else "random.seed"
        name = seed.symbol_name if seed else "SEED"
        imp = f"from {_module_of(seed)} import {name}  # global seed ({seed.file_path})\n" if seed else ""
        repl = f"{imp}{seeder}({name if seed else 42})\n{line.strip()}"
        return [_mk(
            fp, ln, ln, "heur.missing_seed", FindingCategory.LOGICAL_BUG,
            Severity.MEDIUM if seed else Severity.LOW,
            "Stochastic step without reproducibility seed",
            f"`{call}(...)` runs without seeding the RNG"
            + (f" although the project defines `{name}` in {seed.file_path}" if seed else "")
            + "; experiments are not reproducible and results cannot be audited.",
            line.strip(), repl, ActionType.CODE_PATCH, 0.8, _label(seed) if seed else None)]
    return []


def _det_sentinel(lines, funcs, ctx, fp):
    out = []
    gen_rx = re.compile(r"sum\(\s*(?P<expr>.+?)\s+for\s+(?P<v>\w+)\s+in\s+(?P<coll>\w+)\s*\)\s*/\s*len\(\s*(?P=coll)\s*\)")
    lst_rx = re.compile(r"sum\(\s*(?P<coll>\w+)\s*\)\s*/\s*len\(\s*(?P=coll)\s*\)")
    for ln, line in enumerate(lines, 1):
        m = gen_rx.search(line) or lst_rx.search(line)
        if not m:
            continue
        f = _enclosing(funcs, ln)
        body = _body(lines, f)
        coll = m.group("coll")
        sentinel = _ctx_find(ctx, lambda c: c.chunk_type == "module" and re.search(r"SENTINEL|MISSING|NODATA", c.symbol_name))
        if re.search(r"isnan|dropna|notna|!=\s*-?\d|not in \(|SENTINEL|MISSING", body):
            continue
        guarded = re.search(rf"if\s+(not\s+{coll}|len\({coll}\))", body)
        sname = sentinel.symbol_name if sentinel else "-999"
        imp = f"from {_module_of(sentinel)} import {sname}\n" if sentinel else ""
        if "expr" in m.groupdict() and m.groupdict().get("expr"):
            expr, v = m.group("expr"), m.group("v")
            comp = f"[{expr} for {v} in {coll} if {expr} not in ({sname}, None) and {expr} == {expr}]"
        else:
            comp = f"[x for x in {coll} if x not in ({sname}, None) and x == x]"
        prefix = line[:m.start()].strip()
        suffix = line[m.end():].rstrip()
        repl = f"{imp}valid = {comp}\n{prefix} (sum(valid) / len(valid) if valid else float(\"nan\")){suffix}"
        repl = repl.replace("return (", "return (", 1)
        out.append(_mk(
            fp, ln, ln, "heur.sentinel_average", FindingCategory.LOGICAL_BUG, Severity.MEDIUM,
            "Average includes missing-value sentinel / divides by zero",
            "The mean is computed over raw values without masking the missing-data sentinel"
            + (f" `{sname}` defined in {sentinel.file_path}" if sentinel else " (-999 / NaN)")
            + ", silently dragging the statistic"
            + ("" if guarded else f"; an empty `{coll}` also raises ZeroDivisionError") + ".",
            line.strip(), repl, ActionType.CODE_PATCH, 0.85, _label(sentinel) if sentinel else None))
    return out


def _det_sqli(lines, funcs, ctx, fp):
    out = []
    call_rx = re.compile(r"\.(execute|executemany|executescript|raw|query)\(\s*")
    style = "?"
    if any(re.search(r"psycopg|%s", c.code) for c in ctx) and not any("sqlite" in c.code for c in ctx):
        style = "%s"
    conn_chunk = _ctx_find(ctx, lambda c: c.chunk_type == "function" and re.search(r"connect\(", c.code))
    for ln, line in enumerate(lines, 1):
        cm = call_rx.search(line)
        if not cm:
            continue
        rest = line[cm.end():]
        fm = re.match(r"""[fF](?P<q>["'])(?P<sql>.*?)(?P=q)\s*\)""", rest)
        pm = re.match(r"""(?P<q>["'])(?P<sql>.*?)(?P=q)\s*%\s*(?P<args>\([^)]*\)|\w+)\s*\)""", rest)
        cc = re.match(r"""(?P<q>["'])(?P<sql>.*?)(?P=q)\s*\+""", rest)
        if not (fm or pm or cc):
            continue
        if not re.search(r"\b(select|insert|update|delete|where|from)\b", (fm or pm or cc).group("sql"), re.I):
            continue
        params: List[str] = []
        new_call = None
        if fm:
            sql = fm.group("sql")

            def sub(mm):
                params.append(mm.group(1).strip())
                return style
            psql = re.sub(r"""['"]?\{([^{}]+)\}['"]?""", sub, sql)
            new_call = f'{cm.group(0)}"{psql}", ({", ".join(params)},))'
            seg = line[cm.start():cm.end() + fm.end()]
        elif pm:
            sql = pm.group("sql")
            psql = re.sub(r"""['"]?%[sd]['"]?""", style, sql)
            args = pm.group("args").strip()
            args = args if args.startswith("(") else f"({args},)"
            new_call = f'{cm.group(0)}"{psql}", {args})'
            seg = line[cm.start():cm.end() + pm.end()]
        else:
            seg = None
        if seg and new_call:
            repl = line.replace(seg, new_call, 1).strip()
        else:
            repl = line.strip() + "  # TODO: use a parameterized query"
        out.append(_mk(
            fp, ln, ln, "heur.sql_injection", FindingCategory.LOGICAL_BUG, Severity.CRITICAL,
            "SQL injection via string interpolation",
            "User-controlled input is interpolated directly into the SQL string passed to execute(); "
            "an input such as `' OR '1'='1` dumps or drops the table. Use bound parameters"
            + (f" (`{conn_chunk.symbol_name}` in {conn_chunk.file_path} returns a DB-API connection)." if conn_chunk else "."),
            line.strip(), repl, ActionType.CODE_PATCH, 0.95, _label(conn_chunk) if conn_chunk else None))
    return out


def _det_off_by_one(lines, funcs, ctx, fp):
    out = []
    rx = re.compile(r"len\((?P<x>[\w.\[\]]+)\)\s*\+\s*1\b")
    le_rx = re.compile(r"\b(while|if)\b[^:\n]*<=\s*len\((?P<x>[\w.\[\]]+)\)")
    for ln, line in enumerate(lines, 1):
        m = rx.search(line)
        if m and "range(" in line:
            new = line.replace(m.group(0), f"len({m.group('x')})", 1)
        else:
            m = le_rx.search(line)
            if not m:
                continue
            new = re.sub(r"<=\s*len\(", "< len(", line, count=1)
        out.append(_mk(
            fp, ln, ln, "heur.off_by_one", FindingCategory.LOGICAL_BUG, Severity.MEDIUM,
            "Off-by-one loop bound",
            f"The bound goes one past `len({m.group('x')})`, producing an extra (empty) page/iteration or an "
            "IndexError on the last access.",
            line.strip(), new.strip(), ActionType.CODE_PATCH, 0.85))
    return out


def _det_none_deref(lines, funcs, ctx, fp):
    out = []
    nullable = {c.symbol_name: c for c in ctx if c.chunk_type == "function" and
                re.search(r"may be None|fetchone\(\)|return None|->\s*Optional|\.get\(|\|\s*None", c.code)}
    if not nullable:
        return out
    for f in funcs:
        for ln in range(f["body_start"], f["end"] + 1):
            line = lines[ln - 1]
            m = re.match(r"^\s*(?P<v>\w+)\s*=\s*(?:await\s+)?(?P<fn>\w+)\(", line)
            if not m or m.group("fn") not in nullable:
                continue
            v = m.group("v")
            rest = "\n".join(lines[ln:f["end"]])
            if re.search(rf"if\s+(not\s+)?{v}\b|{v}\s+is\s+(not\s+)?None|{v}\s+or\b", rest):
                continue
            if not re.search(rf"\b{v}\s*(\[|\.\w)", rest):
                continue
            chunk = nullable[m.group("fn")]
            repl = (f"{line.strip()}\nif {v} is None:\n"
                    f'    raise LookupError("{m.group("fn")} returned no row")')
            use_ln = next((k for k in range(ln + 1, f["end"] + 1) if re.search(rf"\b{v}\s*(\[|\.\w)", lines[k - 1])), ln)
            out.append(_mk(
                fp, ln, use_ln, "heur.none_dereference", FindingCategory.LOGICAL_BUG, Severity.MEDIUM,
                f"Unchecked None from `{m.group('fn')}()`",
                f"`{m.group('fn')}` ({chunk.file_path}) can return None (e.g. `fetchone()` with no row), but "
                f"`{v}` is subscripted without a None check -> TypeError / HTTP 500 for unknown users.",
                line.strip(), repl, ActionType.CODE_PATCH, 0.85, _label(chunk)))
    return out


_MUTATING = re.compile(r"^(delete|remove|update|create|add|set|insert|transfer|pay|refund|reset|grant|drop)_", re.I)
_AUTH_DECO = re.compile(r"auth|login|permission|require|jwt|token|admin|role|protected", re.I)


def _det_missing_auth(lines, funcs, ctx, fp):
    out = []
    top = [f for f in funcs if f["indent"] == 0]
    decos = Counter(d for f in top for d in f["decorators"] if _AUTH_DECO.search(d))
    defined = {f["name"] for f in top}
    if not decos:
        return out
    deco = decos.most_common(1)[0][0]
    sibling = next(f for f in top if deco in f["decorators"])
    for f in top:
        if f["name"] == deco.split(".")[-1] or deco in f["decorators"] or f["name"].startswith("_"):
            continue
        body = _body(lines, f)
        if not (_MUTATING.match(f["name"]) or re.search(r"""["'][^"']*\b(DELETE|UPDATE|INSERT)\b""", body)):
            continue
        def_line = lines[f["def"] - 1]
        out.append(_mk(
            fp, f["def"], f["def"], "heur.missing_auth", FindingCategory.LOGICAL_BUG, Severity.HIGH,
            f"State-mutating endpoint `{f['name']}` missing @{deco}",
            f"Sibling routes such as `{sibling['name']}` are protected with `@{deco}`, but `{f['name']}` "
            "mutates data without any authentication/authorization check (broken access control).",
            def_line.strip(), f"@{deco}\n{def_line.strip()}", ActionType.CODE_PATCH, 0.85,
            f"{fp}:{sibling['name']}"))
    return out


# --------------------------------------------------------------------------- normalization
def _norm_category(v: Any, action: str = "") -> FindingCategory:
    s = str(v or "").lower()
    if any(k in s for k in ("pii", "privacy", "personal", "gdpr", "cndp")):
        return FindingCategory.PRIVACY_PII
    if any(k in s for k in ("bug", "logic", "race", "inject", "sqli", "vuln", "toctou", "leakage_ml", "error")):
        return FindingCategory.LOGICAL_BUG
    if any(k in s for k in ("secret", "leak", "key", "credential", "token", "password", "security")):
        return FindingCategory.SECURITY_LEAK
    if "patch" in action:
        return FindingCategory.LOGICAL_BUG
    return FindingCategory.SECURITY_LEAK


def _norm_severity(v: Any) -> Severity:
    s = str(v or "").strip().upper()
    if s.startswith("CRIT") or s in ("BLOCKER", "P0"):
        return Severity.CRITICAL
    if s.startswith("HI") or s in ("MAJOR", "P1", "ERROR"):
        return Severity.HIGH
    if s.startswith(("MED", "MOD", "WARN")) or s == "P2":
        return Severity.MEDIUM
    if s.startswith(("LO", "INFO", "MIN")):
        return Severity.LOW
    return Severity.MEDIUM


def _norm_action(v: Any, cat: FindingCategory, target_type: str) -> ActionType:
    s = str(v or "").lower()
    if target_type == "image":
        return ActionType.SOLID_MASK if ("solid" in s or "mask" in s) else ActionType.GAUSSIAN_BLUR
    for key, act in (("env", ActionType.ENV_EXTRACT), ("twin", ActionType.SYNTHETIC_TWIN),
                     ("synth", ActionType.SYNTHETIC_TWIN), ("patch", ActionType.CODE_PATCH),
                     ("fix", ActionType.CODE_PATCH), ("code", ActionType.CODE_PATCH),
                     ("whitelist", ActionType.WHITELIST), ("ignore", ActionType.WHITELIST),
                     ("blur", ActionType.GAUSSIAN_BLUR), ("mask", ActionType.SYNTHETIC_TWIN),
                     ("redact", ActionType.SYNTHETIC_TWIN)):
        if key in s:
            return act
    return {FindingCategory.LOGICAL_BUG: ActionType.CODE_PATCH, FindingCategory.SECURITY_LEAK: ActionType.ENV_EXTRACT,
            FindingCategory.PRIVACY_PII: ActionType.SYNTHETIC_TWIN}[cat]


def _to_int(v: Any) -> Optional[int]:
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v)
    m = re.search(r"\d+", str(v))
    return int(m.group(0)) if m else None


def _norm_bbox(v: Any) -> Optional[List[int]]:
    if isinstance(v, dict):
        v = [v.get(k) for k in ("ymin", "xmin", "ymax", "xmax")]
    if isinstance(v, str):
        v = re.findall(r"-?\d+(?:\.\d+)?", v)
    if not isinstance(v, (list, tuple)) or len(v) < 4:
        return None
    try:
        nums = [float(x) for x in list(v)[:4]]
    except (TypeError, ValueError):
        return None
    if all(0 <= n <= 1.0 for n in nums) and any(n > 0 for n in nums):
        nums = [n * 1000 for n in nums]
    b = [int(max(0, min(1000, round(n)))) for n in nums]
    if b[2] < b[0]:
        b[0], b[2] = b[2], b[0]
    if b[3] < b[1]:
        b[1], b[3] = b[3], b[1]
    return b


def _first(d: dict, *keys: str) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def normalize_findings(raw: Any, default_file: str, target_type: str = "text") -> List[Finding]:
    """Tolerant LLM JSON -> List[Finding]. Unknown enums are mapped, junk items dropped."""
    if isinstance(raw, str):
        try:
            from plutonium.llm_router import repair_json
            raw = repair_json(raw)
        except Exception:  # noqa: BLE001
            return []
    items = raw.get("findings", raw.get("issues", raw.get("results", []))) if isinstance(raw, dict) else raw
    if isinstance(items, dict):
        items = [items]
    out: List[Finding] = []
    seen: set = set()
    for it in items or []:
        if not isinstance(it, dict):
            continue
        action_raw = str(_first(it, "recommended_action", "action", "fix_type") or "")
        cat = _norm_category(_first(it, "category", "type", "kind"), action_raw.lower())
        title = str(_first(it, "title", "label", "name") or "").strip()
        reason = str(_first(it, "reason", "description", "explanation", "details", "message") or "").strip()
        snippet = _first(it, "offending_snippet", "snippet", "offending", "text", "value", "code", "evidence")
        if not (title or reason or snippet):
            continue
        rule_id = str(_first(it, "rule_id", "rule", "id_rule") or f"gemma.{cat.value}")
        ls = _to_int(_first(it, "line_start", "line", "start_line", "lineno"))
        le = _to_int(_first(it, "line_end", "end_line")) or ls
        if isinstance(_first(it, "line", "lines"), str) and "-" in str(_first(it, "line", "lines")):
            nums = re.findall(r"\d+", str(_first(it, "line", "lines")))
            if len(nums) >= 2:
                ls, le = int(nums[0]), int(nums[1])
        if ls is not None and ls < 1:
            ls = None
        if ls is not None and (le is None or le < ls):
            le = ls
        try:
            conf = float(_first(it, "confidence", "score") if _first(it, "confidence", "score") is not None else 0.8)
        except (TypeError, ValueError):
            conf = 0.8
        if conf > 1.0:
            conf = conf / 100.0 if conf <= 100 else 1.0
        conf = max(0.0, min(1.0, conf))
        bbox = _norm_bbox(_first(it, "bbox_2d", "box_2d", "bbox", "box"))
        if target_type == "image" and bbox is None:
            continue
        repl = _first(it, "replacement_snippet", "replacement", "fix", "patch", "suggested_fix")
        xfile = _first(it, "cross_file_context_used", "cross_file_context", "context_used")
        if isinstance(xfile, list):
            xfile = ", ".join(map(str, xfile))
        fp = str(_first(it, "file_path", "file", "path") or default_file)
        action = _norm_action(action_raw, cat, target_type)
        sev = _norm_severity(_first(it, "severity", "level", "risk"))
        if not title:
            title = (reason[:80] or rule_id)
        f = Finding(
            id=_fid(fp, ls, rule_id, snippet or title, bbox),
            category=cat, target_type=target_type, file_path=fp, line_start=ls, line_end=le,
            rule_id=rule_id, severity=sev, confidence=conf, title=title, reason=reason or title,
            cross_file_context_used=str(xfile) if xfile and str(xfile).lower() not in ("none", "null", "n/a") else None,
            offending_snippet=str(snippet) if snippet is not None else None, recommended_action=action,
            replacement_snippet=str(repl) if repl is not None else None,
            env_var_name=_first(it, "env_var_name", "env_name"), env_var_value=_first(it, "env_var_value", "env_value"),
            bbox_2d=bbox,
        )
        if f.id in seen:
            continue
        seen.add(f.id)
        out.append(f)
    return out


def compute_verdict(findings: Iterable[Finding], config: Optional[PlutoniumConfig] = None) -> str:
    cfg = config or load_config()
    block = {s.upper() for s in cfg.block_on}
    warn = {s.upper() for s in cfg.warn_on}
    verdict = "PASS"
    for f in findings:
        if f.recommended_action == ActionType.WHITELIST:
            continue
        if f.offending_snippet and f.category != FindingCategory.LOGICAL_BUG and cfg.is_allowlisted(f.offending_snippet):
            continue
        if f.severity.value in block:
            return "BLOCK"
        if f.severity.value in warn:
            verdict = "WARN"
    return verdict


# --------------------------------------------------------------------------- prompts
def build_system_instruction(preset: str = "all", config: Optional[PlutoniumConfig] = None) -> str:
    cfg = config or load_config()
    rules = "Use the bracketed policy rule ID verbatim as rule_id for matching findings.\n" + "\n".join(f"- {r}" for r in cfg.nl_rules(preset)) or "- Any secret, PII or logical/security bug."
    return f"""You are Plutonium, a senior pre-commit security, privacy and correctness auditor (Gemma 4).
You audit code BEFORE it reaches production for three categories:
1. security_leak - secrets, API keys, tokens, credentials, internal hosts/URLs.
2. privacy_pii   - personal data (Moroccan CIN, 24-digit RIB, MA IBAN, +212 phones, student CNE/Massar,
                   names, addresses, Darija/French/Arabic free text containing personal data).
3. logical_bug   - correctness & security bugs, especially ones that are only provable with the
                   CROSS-FILE CONTEXT (imported models, helpers, config constants).

Active policy rules:
{rules}

Method (keep `thinking_trace` concise, numbered, max ~10 steps): read the target, resolve every imported
symbol against the cross-file context, check each policy rule, verify the regex/static hints (confirm,
correct severity, or add what they missed - especially logical bugs), then emit findings.

Strict output rules:
- `offending_snippet` MUST be copied VERBATIM from the TARGET file (no line-number prefix, no "| "),
  so it can be substring-replaced. For a secret/PII value give the exact value; for code bugs give the
  full offending line(s) without leading indentation.
- `replacement_snippet` MUST be drop-in code that replaces offending_snippet exactly (same indentation
  level, valid syntax, include any needed local import on its own line). For synthetic_twin give a
  format-valid fake value; for env_extract give the rewritten line using os.getenv("NAME", "") /
  process.env.NAME and set env_var_name/env_var_value.
- `line_start`/`line_end` are 1-based line numbers relative to the TARGET file named in `file_path`.
- `cross_file_context_used` = "file:symbol" of the context chunk that proves the issue, or "" if none.
- One finding per distinct issue; report EACH secret/PII value separately (never a whole line bundling
  several values). Do not report issues located only in the context chunks.
- Severity: CRITICAL = exploitable now / regulated PII exposure; HIGH = serious bug or secret;
  MEDIUM = correctness/privacy risk; LOW = hygiene.
- Respond ONLY with JSON matching the schema."""


def _numbered(text: str) -> str:
    return "\n".join(f"{i:4d} | {ln}" for i, ln in enumerate(text.splitlines(), 1))


def build_user_prompt(targets: List[Tuple[str, str]], context: List[CodeChunk],
                      hints: List[Finding], max_chars: int = 60000) -> str:
    parts = ["## TARGET FILE(S) (line-numbered; audit these)"]
    budget = max_chars
    for path, text in targets:
        body = _numbered(text)
        if len(body) > budget:
            body = body[:budget] + "\n... [truncated]"
        budget -= len(body)
        parts.append(f"### FILE: {path}\n```\n{body}\n```")
    parts.append("## CROSS-FILE CONTEXT FROM CODEBASE INDEX (symbol graph + BM25; do not audit, use as proof)")
    if not context:
        parts.append("(none)")
    for c in context:
        parts.append(f"### {c.file_path}:{c.symbol_name} ({c.chunk_type}, lines {c.start_line}-{c.end_line})\n"
                     f"```\n{c.code[:4000]}\n```")
    parts.append("## DETERMINISTIC REGEX / STATIC-ANALYSIS HINTS (verify; may be incomplete or wrong)")
    if not hints:
        parts.append("(none)")
    for h in hints[:60]:
        snip = (h.offending_snippet or "").replace("\n", " ")[:160]
        parts.append(f"- {h.file_path}:{h.line_start} [{h.rule_id}] {h.severity.value} {h.category.value}: "
                     f"{h.title} :: {snip}")
    parts.append("Return the JSON object now.")
    return "\n\n".join(parts)


def build_image_system(preset: str = "all", config: Optional[PlutoniumConfig] = None) -> str:
    cfg = config or load_config()
    rules = "Use the bracketed policy rule ID verbatim as rule_id for matching findings.\n" + "\n".join(f"- {r}" for r in cfg.nl_rules(preset))
    return ("You are Plutonium's vision auditor (Gemma 4). Read ALL text in the screenshot (OCR) and find every "
            "visible secret or personal datum: bearer/JWT tokens, API or merchant keys (cmi_live_...), passwords, "
            "Moroccan CIN (e.g. AB654321), 24-digit RIB, phone numbers, student CNE/Massar codes, names next to IDs, "
            "internal hostnames.\nPolicy rules:\n" + rules +
            "\nFor each item return label, the exact visible text, category, severity and a TIGHT bbox_2d around "
            "the sensitive value only, as [ymin, xmin, ymax, xmax] normalized to 0-1000. Respond ONLY with JSON.")


# --------------------------------------------------------------------------- merging
def _overlap(a: Finding, b: Finding) -> bool:
    if a.line_start is None or b.line_start is None:
        return False
    return a.line_start <= (b.line_end or b.line_start) and b.line_start <= (a.line_end or a.line_start)


def _same_file(a: str, b: str) -> bool:
    a, b = a.replace("\\", "/").lstrip("./"), b.replace("\\", "/").lstrip("./")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _norm_snip(s: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def merge_findings(llm: List[Finding], regex: List[Finding], heur: List[Finding]) -> List[Finding]:
    merged: List[Finding] = []
    absorbed: Dict[str, set] = {}
    precise = heur + regex
    for f in llm:
        # A coarse LLM leak finding (e.g. a whole fixture line) that bundles >= 2 values already
        # caught precisely by regex/heuristics is superseded by those value-level findings.
        if f.category != FindingCategory.LOGICAL_BUG and f.offending_snippet:
            fs = _norm_snip(f.offending_snippet)
            covered = {_norm_snip(p.offending_snippet) for p in precise
                       if p.category != FindingCategory.LOGICAL_BUG and _same_file(p.file_path, f.file_path)
                       and _overlap(p, f) and p.offending_snippet
                       and _norm_snip(p.offending_snippet) in fs and _norm_snip(p.offending_snippet) != fs}
            if len(covered) >= 2:
                continue
        if any(_same_file(f.file_path, g.file_path) and f.line_start == g.line_start and
               _norm_snip(f.offending_snippet) == _norm_snip(g.offending_snippet) for g in merged):
            continue
        merged.append(f.model_copy())
    llm_ids = {f.id for f in merged}

    for h in heur:
        hs = _norm_snip(h.offending_snippet)

        def similar(g: Finding) -> bool:
            gs = _norm_snip(g.offending_snippet)
            return h.category == FindingCategory.LOGICAL_BUG or not gs or not hs or gs in hs or hs in gs
        tgt = next((g for g in merged if g.id in llm_ids and "heur" not in absorbed.get(g.id, set())
                    and _same_file(g.file_path, h.file_path) and g.category == h.category and _overlap(g, h)
                    and similar(g)), None)
        if tgt is None:
            merged.append(h.model_copy())
            continue
        absorbed.setdefault(tgt.id, set()).add("heur")
        _fill(tgt, h)

    for r in regex:
        val = _norm_snip(r.offending_snippet)
        raw_val = _norm_snip(r.env_var_value) or val
        tgt = None
        for g in merged:
            if g.caught_by_regex_baseline and g.id not in llm_ids:
                continue
            if not _same_file(g.file_path, r.file_path) or not _overlap(g, r):
                continue
            gs = _norm_snip(g.offending_snippet)
            if gs and (gs == val or gs == raw_val):
                tgt = g
                break
            if gs and g.id in llm_ids and (raw_val in gs or gs in val) \
                    and not absorbed.get(g.id, set()) - {"heur"} and g.category != FindingCategory.LOGICAL_BUG:
                tgt = g
                break
        if tgt is None:
            merged.append(r.model_copy())
            continue
        absorbed.setdefault(tgt.id, set()).add(r.offending_snippet or r.id)
        tgt.caught_by_regex_baseline = True
        if SEV_RANK[r.severity.value] < SEV_RANK[tgt.severity.value]:
            tgt.severity = r.severity
        _fill(tgt, r)
    return merged


def _strip_comments(code: str) -> str:
    return "\n".join(ln.split("#", 1)[0].strip() for ln in (code or "").splitlines() if ln.split("#", 1)[0].strip())


def _patch_ok(offending: Optional[str], replacement: Optional[str], file_path: str) -> bool:
    """Is an LLM patch a real, drop-in change? (non-empty, no placeholders, not comment-only, parses)."""
    if not replacement or not replacement.strip():
        return False
    if "..." in replacement or re.search(r"#\s*(TODO|Note|FIXME|implement)", replacement, re.I):
        return False
    if _strip_comments(replacement) == _strip_comments(offending or ""):
        return False
    if file_path.lower().endswith(".py"):
        body = textwrap.dedent(replacement.strip("\n"))
        try:
            import ast as _ast
            _ast.parse("async def _bg():\n" + textwrap.indent(body, "    ") + "\n    pass\n")
        except SyntaxError:
            return False
    return True


def _fill(tgt: Finding, src: Finding) -> None:
    """Complete an LLM finding with deterministic data (never overwrite its reasoning).

    Value-level regex hits always supply the snippet/twin (reserved-prefix twins, exact values);
    heuristic patches replace LLM patches that are empty, placeholder-only or do not parse.
    """
    if not tgt.cross_file_context_used and src.cross_file_context_used:
        tgt.cross_file_context_used = src.cross_file_context_used
    if src.caught_by_regex_baseline and src.replacement_snippet:
        tgt.offending_snippet, tgt.replacement_snippet = src.offending_snippet, src.replacement_snippet
        tgt.recommended_action = src.recommended_action
        tgt.env_var_name, tgt.env_var_value = src.env_var_name, src.env_var_value
        tgt.line_start, tgt.line_end = src.line_start, src.line_end
    elif src.replacement_snippet and not _patch_ok(tgt.offending_snippet, tgt.replacement_snippet, tgt.file_path):
        tgt.offending_snippet, tgt.replacement_snippet = src.offending_snippet, src.replacement_snippet
        tgt.recommended_action = src.recommended_action
        tgt.line_start, tgt.line_end = src.line_start, src.line_end
    if tgt.recommended_action == ActionType.ENV_EXTRACT and not tgt.env_var_name and src.env_var_name:
        tgt.env_var_name, tgt.env_var_value = src.env_var_name, src.env_var_value
    if SEV_RANK[src.severity.value] < SEV_RANK[tgt.severity.value]:
        tgt.severity = src.severity


def _sort(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEV_RANK[f.severity.value], f.file_path, f.line_start or 0, f.rule_id))


# --------------------------------------------------------------------------- local sanitizer
def _local_sanitize(text: str, config: PlutoniumConfig, vault: Optional[Dict[str, str]] = None
                    ) -> Tuple[str, Dict[str, str]]:
    vault = dict(vault or {})
    reverse = {v: k for k, v in vault.items()}
    counters: Counter = Counter()
    for tok in vault:
        m = re.match(r"\[(.+)_(\d+)\]$", tok)
        if m:
            counters[m.group(1)] = max(counters[m.group(1)], int(m.group(2)))
    rules = sorted(config.regex_rules("all"), key=lambda r: SEV_RANK.get(r.severity, 9))
    for r in rules:
        prefix = re.sub(r"[^A-Z0-9]+", "_", r.id.split(".")[-1].upper()) + "_TOKEN"

        def repl(m: re.Match, prefix: str = prefix) -> str:
            val = m.group(0)
            if config.is_allowlisted(val) or re.fullmatch(r"\[[A-Z0-9_]+_\d+\]", val):
                return val
            if val not in reverse:
                counters[prefix] += 1
                tok = f"[{prefix}_{counters[prefix]}]"
                vault[tok] = val
                reverse[val] = tok
            return reverse[val]
        text = r.compiled.sub(repl, text)
    return text, vault


def _local_rehydrate(text: str, vault: Dict[str, str]) -> str:
    for tok in sorted(vault, key=len, reverse=True):
        text = text.replace(tok, vault[tok])
    return text


# --------------------------------------------------------------------------- diff parsing
def parse_unified_diff(diff_text: str) -> Dict[str, Dict[int, str]]:
    """{new_path: {new_line_number: added_line_text}} for every added line."""
    files: Dict[str, Dict[int, str]] = {}
    cur: Optional[str] = None
    new_ln = 0
    for line in (diff_text or "").splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip().split("\t")[0]
            cur = None if path == "/dev/null" else re.sub(r"^[ab]/", "", path)
            if cur is not None:
                files.setdefault(cur, {})
            continue
        if line.startswith("--- ") or line.startswith("diff --git") or line.startswith("index "):
            continue
        hm = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
        if hm:
            new_ln = int(hm.group(1))
            continue
        if cur is None:
            continue
        if line.startswith("+"):
            files[cur][new_ln] = line[1:]
            new_ln += 1
        elif line.startswith("-"):
            continue
        elif line.startswith("\\"):
            continue
        else:
            new_ln += 1
    return files


# --------------------------------------------------------------------------- scanner
class Scanner:
    def __init__(self, root: str | Path = ".", router=None, config: Optional[PlutoniumConfig] = None,
                 offline: bool = False):
        self.root = Path(root).resolve()
        self.config = config or load_config(self.root)
        self.offline = offline
        self._router = router
        self._indexer: Optional[CodebaseIndexer] = None
        self.last_context: List[CodeChunk] = []
        self.last_vault: Dict[str, str] = {}
        self.last_prompt: str = ""

    # ------------------------------------------------------------------ lazies
    @property
    def indexer(self) -> CodebaseIndexer:
        if self._indexer is None:
            self._indexer = CodebaseIndexer(self.root, self.config)
        return self._indexer

    @property
    def router(self):
        if self._router is None and not self.offline:
            from plutonium.llm_router import GemmaRouter
            self._router = GemmaRouter(ollama_url=self.config.models.get("ollama_url", "http://localhost:11434"))
        return self._router

    # ------------------------------------------------------------------ io
    def _resolve(self, path: str) -> Path:
        p = Path(path)
        if p.is_absolute():
            return p
        for cand in (Path.cwd() / p, self.root / p):
            if cand.exists():
                return cand.resolve()
        return (Path.cwd() / p).resolve()

    def _load_target(self, path: str) -> Tuple[str, str, str, List[str]]:
        """(display_path, scan_text, raw_text, image_paths)."""
        p = self._resolve(path)
        raw = p.read_text(encoding="utf-8", errors="replace")
        rel = self.indexer.rel(p)
        if p.suffix.lower() == ".ipynb":
            rendered, _, images = render_notebook(raw, p.stem, self.indexer.image_dir)
            return rel, rendered, raw, images
        return rel, raw, raw, []

    # ------------------------------------------------------------------ public API
    def scan_files(self, paths: List[str], mode: EngineMode = EngineMode.CLOUD_FAST, preset: str = "all") -> ScanResult:
        targets = []
        for p in paths:
            rp = self._resolve(p)
            if rp.is_dir():
                for child in sorted(rp.rglob("*")):
                    rel = child.relative_to(rp).as_posix()
                    if child.is_file() and self.indexer._supported(child) and not self.config.is_ignored_path(rel) \
                            and ".plutonium" not in rel and child.stat().st_size <= 1_000_000:
                        targets.append(self._load_target(str(child)))
            elif rp.is_file():
                targets.append(self._load_target(str(rp)))
        return self._scan(targets, mode, preset)

    def scan_text(self, text: str, file_path: str = "snippet.py", mode: EngineMode = EngineMode.CLOUD_FAST,
                  preset: str = "all") -> ScanResult:
        images: List[str] = []
        scan_text = text
        if file_path.lower().endswith(".ipynb"):
            scan_text, _, images = render_notebook(text, Path(file_path).stem, self.indexer.image_dir)
        return self._scan([(file_path, scan_text, text, images)], mode, preset)

    def scan_diff(self, diff_text: str, mode: EngineMode = EngineMode.CLOUD_FAST, preset: str = "all",
                  base_dir: Optional[str | Path] = None) -> ScanResult:
        added = parse_unified_diff(diff_text)
        targets, keep_lines = [], {}
        base = Path(base_dir).resolve() if base_dir else None
        for path, lines in added.items():
            if not lines:
                continue
            disk = None
            for cand in ([base / path] if base else []) + [self.root / path, Path.cwd() / path]:
                if cand.is_file():
                    disk = cand
                    break
            if disk is not None:
                rel, text, raw, images = self._load_target(str(disk))
                if disk.suffix.lower() == ".ipynb":
                    keep_lines[rel] = None  # line numbers in JSON vs rendered differ: keep all
                else:
                    keep_lines[rel] = set(lines)
                targets.append((rel, text, raw, images))
            else:
                n = max(lines)
                buf = [""] * n
                for ln, t in lines.items():
                    buf[ln - 1] = t
                text = "\n".join(buf) + "\n"
                targets.append((path, text, text, []))
                keep_lines[path] = None
        if not targets:
            return ScanResult(verdict="PASS", engine_used="none", preset_used=str(preset),
                              summary="Empty diff: no added lines to scan.",
                              indexed_chunks_count=len(self.indexer.chunks))

        def line_filter(f: Finding) -> bool:
            allowed = next((v for k, v in keep_lines.items() if _same_file(k, f.file_path)), None)
            if allowed is None or f.line_start is None:
                return True
            rng = set(range(f.line_start, (f.line_end or f.line_start) + 1))
            if rng & allowed:
                return True
            return f.severity == Severity.CRITICAL and bool(f.cross_file_context_used)
        return self._scan(targets, mode, preset, line_filter=line_filter)

    def scan_staged(self, mode: EngineMode = EngineMode.CLOUD_FAST, preset: str = "all") -> ScanResult:
        try:
            top = subprocess.run(["git", "-C", str(self.root), "rev-parse", "--show-toplevel"],
                                 capture_output=True, text=True, timeout=15).stdout.strip() or str(self.root)
            diff = subprocess.run(["git", "-C", str(self.root), "diff", "--cached", "-U0", "--no-color"],
                                  capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError) as e:
            return ScanResult(verdict="PASS", engine_used="none", preset_used=str(preset),
                              summary=f"git unavailable: {e}")
        return self.scan_diff(diff, mode, preset, base_dir=top)

    def scan_image(self, image_path: str, mode: EngineMode = EngineMode.CLOUD_FAST, preset: str = "all") -> ScanResult:
        p = self._resolve(image_path)
        disp = self.indexer.rel(p)
        sidecar = Path(str(p) + ".boxes.json")
        data, engine, err = None, "", ""
        if not self.offline and self.router is not None:
            try:
                img_mode = EngineMode.CLOUD_FAST if mode == EngineMode.HYBRID_SMART else mode
                data, engine = self.router.analyze(img_mode, f"Audit this screenshot ({p.name}) for visible secrets and PII.",
                                                   build_image_system(preset, self.config), IMAGE_RESPONSE_SCHEMA,
                                                   image_paths=[str(p)], cache_tag="image")
            except Exception as e:  # noqa: BLE001 - incl. AllEnginesFailed
                err = str(e)[:200]
                data = None
        findings: List[Finding] = []
        if data is not None:
            findings = normalize_findings(data, disp, target_type="image")
        if data is None and sidecar.is_file():
            try:
                findings = normalize_findings(json.loads(sidecar.read_text(encoding="utf-8")), disp, target_type="image")
                engine = "offline_vision_cache"
            except (json.JSONDecodeError, OSError):
                findings = []
        for f in findings:
            f.file_path = disp
        findings = _sort(findings)
        if data is None and not engine:
            return ScanResult(verdict="WARN", engine_used="offline_heuristic", preset_used=str(preset),
                              summary="vision engine unavailable: no Gemma 4 vision backend answered and no cached "
                                      "boxes exist for this image. Review it manually." + (f" ({err})" if err else ""),
                              thinking_trace="1. Vision scan requested\n2. All engines unavailable\n3. No sidecar cache",
                              findings=[])
        verdict = compute_verdict(findings, self.config)
        summary = (data or {}).get("summary") if isinstance(data, dict) else None
        if engine == "offline_vision_cache":
            summary = f"Offline vision cache: {len(findings)} sensitive region(s) from {sidecar.name}."
        return ScanResult(verdict=verdict, engine_used=engine, preset_used=str(preset),
                          summary=summary or f"{len(findings)} sensitive region(s) detected in {p.name}.",
                          thinking_trace=(data or {}).get("thinking_trace") if isinstance(data, dict) else None,
                          gemma_findings_count=len(findings), findings=findings)

    # ------------------------------------------------------------------ core
    def _scan(self, targets: List[Tuple[str, str, str, List[str]]], mode: EngineMode, preset: str,
              line_filter: Optional[Callable[[Finding], bool]] = None) -> ScanResult:
        mode = EngineMode(mode)
        preset = preset.value if hasattr(preset, "value") else str(preset)
        stats = self.indexer.build()
        target_names = [t[0] for t in targets]
        all_text = "\n".join(t[1] for t in targets)
        context = self.indexer.get_context_for_target(all_text, target_names, mode)
        self.last_context = context
        trace = [f"1. Indexed codebase: {stats.chunks} chunks / {stats.symbols} symbols "
                 f"({stats.files_indexed} re-chunked, {stats.files_reused} reused via sha256)."]
        trace.append(f"2. Retrieved {len(context)} cross-file chunk(s) for {mode.value}: "
                     + (", ".join(_label(c) for c in context[:8]) or "none")
                     + (f" (+{len(context) - 8} more)" if len(context) > 8 else "") + ".")

        regex_hits: List[Finding] = []
        heur_hits: List[Finding] = []
        fired: List[str] = []
        for disp, text, raw, _ in targets:
            rh = regex_baseline(text, disp, preset, self.config)
            hctx = self.indexer.get_context_for_target(text, [disp], EngineMode.CLOUD_DEEP, max_chunks=40)
            hh = heuristic_logic_scan(text, disp, hctx)
            if disp.lower().endswith(".ipynb"):
                rh = [self._remap_notebook(f, raw) for f in rh]
                hh = [self._remap_notebook(f, raw) for f in hh]
            regex_hits += rh
            heur_hits += hh
            fired += [f"{h.rule_id}@{Path(disp).name}:{h.line_start}" for h in hh]
        trace.append(f"3. Regex baseline: {len(regex_hits)} hit(s) "
                     f"({', '.join(sorted(Counter(r.rule_id for r in regex_hits)))}).")
        trace.append(f"4. Cross-file heuristics fired: {', '.join(fired) or 'none'}.")

        llm_findings: List[Finding] = []
        engine = "offline_heuristic"
        summary = ""
        llm_trace = None
        if not self.offline:
            system = build_system_instruction(preset, self.config)
            prompt = build_user_prompt([(t[0], t[1]) for t in targets], context, regex_hits + heur_hits)
            self.last_prompt = prompt
            images = [i for t in targets for i in t[3]] if mode in CLOUD_MODES else []
            try:
                if mode == EngineMode.HYBRID_SMART:
                    data, engine, vault = self.router.hybrid_redact_then_audit(
                        prompt, system, SCAN_RESPONSE_SCHEMA, self._sanitize, self._rehydrate, cache_tag="scan")
                    self.last_vault = vault
                else:
                    data, engine = self.router.analyze(mode, prompt, system, SCAN_RESPONSE_SCHEMA,
                                                       image_paths=images, cache_tag="scan")
                default = targets[0][0] if targets else "snippet"
                llm_findings = normalize_findings(data, default)
                llm_findings = [self._fix_llm_finding(f, targets) for f in llm_findings]
                llm_findings = [f for f in llm_findings if f is not None]
                if isinstance(data, dict):
                    summary = str(data.get("summary") or "")
                    llm_trace = data.get("thinking_trace")
                trace.append(f"5. {engine} returned {len(llm_findings)} finding(s).")
            except Exception as e:  # noqa: BLE001 - AllEnginesFailed or anything else -> offline
                engine = "offline_heuristic"
                trace.append(f"5. Gemma 4 engines unavailable ({type(e).__name__}); "
                             "falling back to deterministic offline heuristic engine.")
        else:
            trace.append("5. Offline mode: Gemma 4 call skipped; deterministic engine only.")

        findings = merge_findings(llm_findings, regex_hits, heur_hits)
        if line_filter is not None:
            findings = [f for f in findings if line_filter(f)]
        findings = _sort(findings)
        regex_count = sum(1 for f in regex_hits if line_filter is None or line_filter(f))
        gemma_count = sum(1 for f in findings if not f.caught_by_regex_baseline)
        verdict = compute_verdict(findings, self.config)
        sev = Counter(f.severity.value for f in findings)
        cats = Counter(f.category.value for f in findings)
        trace.append(f"6. Merged & deduplicated -> {len(findings)} finding(s); verdict {verdict}.")
        stats_line = (f"{len(findings)} finding(s) [{', '.join(f'{v} {k}' for k, v in sev.items()) or 'none'}] "
                      f"in {len(targets)} file(s): {cats.get('security_leak', 0)} secret leak(s), "
                      f"{cats.get('privacy_pii', 0)} PII, {cats.get('logical_bug', 0)} logical bug(s). "
                      f"Regex baseline caught {regex_count}; Plutonium added {gemma_count}.")
        if engine == "offline_heuristic":
            summary = ("Gemma 4 engines unavailable or offline: deterministic offline heuristic engine "
                       "(regex baseline + cross-file AST detectors) used. " + stats_line)
        else:
            summary = (summary.strip() + " " if summary else "") + stats_line
        thinking = "\n".join(trace)
        if llm_trace:
            thinking = str(llm_trace).strip() + "\n\n--- Plutonium pipeline ---\n" + thinking
        return ScanResult(
            verdict=verdict, engine_used=engine, preset_used=preset, summary=summary, thinking_trace=thinking,
            indexed_chunks_count=len(self.indexer.chunks),
            retrieved_context_Chunks=[_label(c) for c in context],
            regex_baseline_count=regex_count, gemma_findings_count=gemma_count, findings=findings,
        )

    # ------------------------------------------------------------------ helpers
    def _sanitize(self, text: str) -> Tuple[str, Dict[str, str]]:
        vault: Dict[str, str] = {}
        try:
            from plutonium.redactor import sanitize_prompt_llm
            text, vault = sanitize_prompt_llm(text, router=self.router, config=self.config)
        except Exception:  # noqa: BLE001
            try:
                from plutonium.redactor import sanitize_prompt
                text, vault = sanitize_prompt(text, self.config)
            except Exception:  # noqa: BLE001
                pass
        # Safety net: anything our own regex baseline still sees never leaves the machine.
        return _local_sanitize(text, self.config, vault)

    @staticmethod
    def _rehydrate(text: str, vault: Dict[str, str]) -> str:
        try:
            from plutonium.redactor import rehydrate
            return rehydrate(text, vault)
        except Exception:  # noqa: BLE001
            return _local_rehydrate(text, vault)

    @staticmethod
    def _remap_notebook(f: Finding, raw: str) -> Finding:
        """Map a finding on rendered notebook text to the raw .ipynb JSON line."""
        snip = f.offending_snippet or ""
        first = snip.split("\n")[0]
        for needle in (first, json.dumps(first, ensure_ascii=False)[1:-1]):
            if needle and needle in raw:
                ln = raw[:raw.index(needle)].count("\n") + 1
                span = (f.line_end or f.line_start or ln) - (f.line_start or ln)
                f.line_start, f.line_end = ln, ln + max(0, span)
                break
        return f

    def _fix_llm_finding(self, f: Finding, targets) -> Optional[Finding]:
        """Snap LLM file paths / line numbers onto the actual target text."""
        tgt = next((t for t in targets if _same_file(t[0], f.file_path)), None)
        if tgt is None:
            tgt = next((t for t in targets if Path(t[0]).name == Path(f.file_path).name), targets[0] if targets else None)
        if tgt is None:
            return f
        f.file_path = tgt[0]
        text = tgt[2] if tgt[0].lower().endswith(".ipynb") else tgt[1]
        snip = (f.offending_snippet or "").strip()
        if snip:
            snip = re.sub(r"^\s*\d+\s*\|\s?", "", snip, flags=re.M)
            f.offending_snippet = snip
            first = snip.split("\n")[0].strip()
            if first and first in text:
                positions = [m.start() for m in re.finditer(re.escape(first), text)]
                lns = [text[:p].count("\n") + 1 for p in positions]
                best = min(lns, key=lambda x: abs(x - (f.line_start or x)))
                span = snip.count("\n")
                f.line_start, f.line_end = best, best + span
        f.id = _fid(f.file_path, f.line_start, f.rule_id, f.offending_snippet or f.title)
        return f
