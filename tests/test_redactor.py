import re

import pytest
from PIL import Image, ImageDraw

from barakagate.config import load_config
from barakagate.models import ActionType, Finding
from barakagate.redactor import (
    apply_text_fixes, apply_to_disk, bbox_to_pixels, extract_to_env, is_valid_iban, is_valid_rib,
    preview_patch, redact_image, rehydrate, rib_key, sanitize_prompt, synthetic_twin,
)


def F(id, rule_id, snippet, action, line=None, line_end=None, replacement=None, file_path="app.py",
      category="privacy_pii", **kw):
    return Finding(id=id, category=category, target_type="text", file_path=file_path, line_start=line,
                   line_end=line_end or line, rule_id=rule_id, severity="HIGH", confidence=0.9, title=rule_id,
                   reason="test", offending_snippet=snippet, recommended_action=action,
                   replacement_snippet=replacement, **kw)


# --------------------------------------------------------------------------- twins

def test_rib_key_known_value():
    body = "0118100000123456789012"
    key = rib_key(body)
    assert key == f"{97 - (int(body) * 100) % 97:02d}" and len(key) == 2
    assert is_valid_rib(body + key)
    with pytest.raises(ValueError):
        rib_key("123")


@pytest.mark.parametrize("kind,value,pattern", [
    ("cin", "BE847291", r"^ZZ\d{6}$"),
    ("cin", "A12345", r"^ZZ\d{5}$"),
    ("rib", "230780123456789012345678", r"^999\d{21}$"),
    ("cne", "R139482710", r"^Z\d{9}$"),
    ("phone", "+212661234567", r"^\+2126000000\d\d$"),
    ("email", "youssef@atlaspay.ma", r"@example\.com$"),
    ("secret", "hunter2hunter2", r"^SYNTH_SECRET_"),
    ("ma.cmi_key", "cmi_live_123456", r"SYNTH"),
    ("jwt", "eyJ...", r"^eyJ[\w-]+\.[\w-]+\.SYNTH_SIGNATURE$"),
])
def test_twin_format_and_determinism(kind, value, pattern):
    t = synthetic_twin(kind, value)
    assert re.search(pattern, t), t
    assert synthetic_twin(kind, value) == t           # deterministic
    assert t != value


def test_twin_rib_and_iban_checksums_valid():
    for v in ("230780123456789012345678", "011810000012345678901234"):
        assert is_valid_rib(synthetic_twin("rib", v))
    iban = synthetic_twin("iban", "MA64011519000001205000534921")
    assert iban.startswith("MA999") is False and iban.startswith("MA") and is_valid_iban(iban)
    assert synthetic_twin("cin", "BE847291") != synthetic_twin("cin", "AB123456")


def test_twin_regex_interaction_documented():
    """Strict-format twins stay format-valid, so the CIN regex still matches them (by design: they are
    obviously fake via the ZZ prefix). Free-form secret twins carry SYNTH_ and are allowlisted."""
    cfg = load_config()
    cin_rule = next(r for r in cfg.regex_rules("fintech_morocco") if r.id == "ma.cin")
    assert cin_rule.compiled.search(synthetic_twin("cin", "BE847291"))
    assert cfg.is_allowlisted(synthetic_twin("secret", "x"))
    assert cfg.is_allowlisted(synthetic_twin("cmi_key", "cmi_live_123456"))
    assert cfg.is_allowlisted(synthetic_twin("email", "a@b.ma"))


# --------------------------------------------------------------------------- text fixes

CODE = '''"""Checkout."""
import logging

SECRET_KEY = "cmi_live_sk_9988776655443322"
TEST_CLIENT = {"cin": "BE847291", "rib": "230780123456789012345678"}


def compute_total(amount_mad, quantity):
    tva = round(amount_mad * 0.20, 2)
    return amount_mad + tva


def pay(customer, total):
    if customer.balance >= total:
        customer.balance -= total
    return total
'''


def test_apply_multiple_fixes_with_multiline_patch_and_line_shift():
    findings = [
        F("cin", "ma.cin", "BE847291", ActionType.SYNTHETIC_TWIN, line=5),
        F("rib", "ma.rib", "230780123456789012345678", ActionType.SYNTHETIC_TWIN, line=5),
        # multi-line patch at line 9 shifts everything below by +2 ...
        F("tva", "gemma.float", "tva = round(amount_mad * 0.20, 2)", ActionType.CODE_PATCH, line=9,
          replacement="from decimal import Decimal, ROUND_HALF_UP\ntva = (Decimal(str(amount_mad)) * Decimal('0.20'))"
                      "\ntva = tva.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)", category="logical_bug"),
        # ... but this one (line 14-15) must still hit the right lines
        F("race", "gemma.toctou", "if customer.balance >= total:\n    customer.balance -= total", ActionType.CODE_PATCH,
          line=14, line_end=15, category="logical_bug",
          replacement="with customer.lock:\n    if customer.balance >= total:\n        customer.balance -= total"),
    ]
    out = apply_text_fixes(CODE, findings, {f.id: f.recommended_action for f in findings})
    assert "BE847291" not in out and "230780123456789012345678" not in out
    assert synthetic_twin("cin", "BE847291") in out
    assert "    from decimal import Decimal, ROUND_HALF_UP\n    tva = (Decimal(" in out          # indented
    assert "    tva = tva.quantize(" in out
    assert "    with customer.lock:\n        if customer.balance >= total:\n            customer.balance -= total\n    return total" in out
    compile(out, "x.py", "exec")


def test_fallback_to_line_range_when_snippet_missing():
    f = F("x", "gemma.float", "tva = something_the_llm_paraphrased", ActionType.CODE_PATCH, line=9,
          replacement="tva = 0", category="logical_bug")
    out = apply_text_fixes(CODE, [f], {"x": "code_patch"})
    assert out.splitlines()[8] == "    tva = 0"


def test_whitelist_and_missing_decision_are_noops():
    f = F("cin", "ma.cin", "BE847291", ActionType.SYNTHETIC_TWIN, line=5)
    assert apply_text_fixes(CODE, [f], {"cin": ActionType.WHITELIST}) == CODE
    assert apply_text_fixes(CODE, [f], {}) == CODE
    assert preview_patch(CODE, [f], {}) == ""
    assert "-TEST_CLIENT" in preview_patch(CODE, [f], {"cin": "synthetic_twin"})


def test_solid_mask_on_text():
    f = F("cin", "ma.cin", "BE847291", ActionType.SYNTHETIC_TWIN, line=5)
    assert '"cin": "[REDACTED]"' in apply_text_fixes(CODE, [f], {"cin": "solid_mask"})


def test_extract_to_env_python_and_js():
    f = F("s", "gen.generic_secret", 'SECRET_KEY = "cmi_live_sk_9988776655443322"', ActionType.ENV_EXTRACT, line=4)
    code, name, value = extract_to_env(f)
    assert code == 'SECRET_KEY = os.getenv("SECRET_KEY", "")' and name == "SECRET_KEY"
    assert value == "cmi_live_sk_9988776655443322"
    fj = F("s", "gen.generic_secret", 'const apiKey = "sk_live_abcdefghijkl";', ActionType.ENV_EXTRACT, file_path="a.js")
    code, name, value = extract_to_env(fj, "javascript")
    assert code == "const apiKey = process.env.API_KEY;" or code == "const apiKey = process.env.APIKEY;"
    bare = F("b", "ma.cmi_key", "cmi_live_sk_9988776655443322", ActionType.ENV_EXTRACT, line=4)
    assert extract_to_env(bare)[1] == "CMI_MERCHANT_KEY"


def test_env_extract_adds_import_os_and_env_without_duplicates(tmp_path):
    src = tmp_path / "settings.py"
    src.write_text('"""Settings."""\nfrom pathlib import Path\n\nDB_PASSWORD = "S3cr3tPassw0rd!"\n'
                   'class C:\n    API_TOKEN = "tok_1234567890"\n')
    env = tmp_path / ".env"
    env.write_text("EXISTING=1\nDB_PASSWORD=old\n")
    findings = [
        F("a", "gen.generic_secret", 'DB_PASSWORD = "S3cr3tPassw0rd!"', ActionType.ENV_EXTRACT, line=4,
          category="security_leak"),
        F("b", "gen.generic_secret", 'API_TOKEN = "tok_1234567890"', ActionType.ENV_EXTRACT, line=6,
          category="security_leak"),
    ]
    decisions = {"a": "env_extract", "b": "env_extract"}
    summary = apply_to_disk(str(src), findings, decisions, env_path=str(env))
    out = src.read_text()
    assert out.startswith('"""Settings."""\nimport os\nfrom pathlib import Path')
    assert 'DB_PASSWORD = os.getenv("DB_PASSWORD", "")' in out
    assert '    API_TOKEN = os.getenv("API_TOKEN", "")' in out
    assert sorted(summary["applied"]) == ["a", "b"] and summary["env_added"] == ["API_TOKEN"]
    assert summary["backup"] and (tmp_path / ".barakagate" / "backups").is_dir()
    # second run: nothing new, no duplicate keys
    apply_to_disk(str(src), findings, decisions, env_path=str(env))
    keys = [ln.split("=")[0] for ln in env.read_text().splitlines() if "=" in ln]
    assert len(keys) == len(set(keys)) and set(keys) == {"EXISTING", "DB_PASSWORD", "API_TOKEN"}
    assert out.count("import os") == 1


def test_env_extract_bare_value_replaces_quoted_literal():
    code = 'conf = {"key": "cmi_live_9823749283", "x": 1}\n'
    f = F("k", "ma.cmi_key", "cmi_live_9823749283", ActionType.ENV_EXTRACT, line=1, category="security_leak")
    out = apply_text_fixes(code, [f], {"k": "env_extract"})
    assert out.startswith("import os\n")
    assert 'conf = {"key": os.getenv("CMI_MERCHANT_KEY", ""), "x": 1}' in out


# --------------------------------------------------------------------------- images

def test_bbox_to_pixels_math_padding_and_clamp():
    assert bbox_to_pixels([100, 200, 300, 400], 1000, 1000, pad=0) == (200, 100, 400, 300)
    # [ymin, xmin, ymax, xmax] -> (x1, y1, x2, y2); 15% pad of a 200x200 box = 30px
    assert bbox_to_pixels([100, 200, 300, 400], 1000, 1000) == (170, 70, 430, 330)
    assert bbox_to_pixels([0, 0, 1000, 1000], 640, 480) == (0, 0, 640, 480)       # clamped
    x1, y1, x2, y2 = bbox_to_pixels([500, 500, 500, 500], 100, 100)
    assert x2 > x1 and y2 > y1
    with pytest.raises(ValueError):
        bbox_to_pixels([1, 2, 3], 10, 10)


@pytest.mark.parametrize("style", ["gaussian_blur", "solid_mask"])
def test_redact_image_changes_only_inside_box(tmp_path, style):
    src = tmp_path / "shot.png"
    img = Image.new("RGB", (400, 200), (30, 30, 30))
    d = ImageDraw.Draw(img)
    for x in range(0, 400, 6):
        d.line([x, 0, x, 200], fill=(250, 250, 250), width=2)
    img.save(src)
    box = [250, 250, 750, 750]  # center region
    out = redact_image(str(src), [box], style=style)
    assert out.endswith("shot.redacted.png")
    a, b = Image.open(src).convert("RGB"), Image.open(out).convert("RGB")
    x1, y1, x2, y2 = bbox_to_pixels(box, 400, 200)
    inside = sum(a.getpixel((x, y)) != b.getpixel((x, y)) for x in range(x1, x2) for y in range(y1, y2))
    assert inside > 0.5 * (x2 - x1) * (y2 - y1)
    for (x, y) in [(0, 0), (x1 - 1, y1 - 1), (x2 + 1, y2 + 1), (399, 199), (10, 100)]:
        assert a.getpixel((x, y)) == b.getpixel((x, y))


# --------------------------------------------------------------------------- safe-to-prompt

MESSY = """salam khouya, l'API kat crashi. Client CIN BE847291 (w akhoh AB123456), RIB 230780123456789012345678.
Student R139482710 ma9drch ydkhol. Call +212661234567. Endpoint: https://hpc-staging.internal.um6p.ma/api/v1/jobs
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.dGVzdHNpZ25hdHVyZTEyMw
merchant key cmi_live_9823749283 — هاك رقم البطاقة ديالي. Again: BE847291 / R139482710.
Traceback: KeyError 'wallet_balance_mad' in checkout.py line 31
"""


def test_sanitize_rehydrate_roundtrip():
    s, vault = sanitize_prompt(MESSY)
    for secret in ("BE847291", "AB123456", "230780123456789012345678", "R139482710", "+212661234567",
                   "hpc-staging.internal.um6p.ma", "eyJhbGciOiJIUzI1NiIs", "cmi_live_9823749283"):
        assert secret not in s, secret
    for tok in ("[CIN_TOKEN_1]", "[CIN_TOKEN_2]", "[RIB_TOKEN_1]", "[CNE_TOKEN_1]", "[PHONE_TOKEN_1]",
                "[URL_TOKEN_1]", "[SECRET_KEY_1]", "[SECRET_KEY_2]"):
        assert tok in s, tok
    assert s.count("[CIN_TOKEN_1]") == 2 and s.count("[CNE_TOKEN_1]") == 2   # same value -> same token
    assert "salam khouya" in s and "هاك رقم البطاقة" in s and "checkout.py line 31" in s
    assert rehydrate(s, vault) == MESSY
    assert sanitize_prompt(MESSY) == (s, vault)                               # deterministic
    # LLM echoing a token without brackets is still rehydrated
    assert rehydrate("fix CIN_TOKEN_1 now", vault) == "fix BE847291 now"


def test_sanitize_does_not_touch_tokens_or_plain_words():
    s, vault = sanitize_prompt("an internal error happened; already [CIN_TOKEN_7] here")
    assert s == "an internal error happened; already [CIN_TOKEN_7] here" and vault == {}
