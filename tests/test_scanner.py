import json
import shutil

import pytest

from barakagate.config import load_config
from barakagate.llm_router import AllEnginesFailed, GemmaRouter
from barakagate.models import ActionType, EngineMode, FindingCategory, Severity
from barakagate.scanner import (
    IMAGE_RESPONSE_SCHEMA, SCAN_RESPONSE_SCHEMA, Scanner, build_system_instruction, compute_verdict,
    heuristic_logic_scan, normalize_findings, parse_unified_diff, regex_baseline,
)


@pytest.fixture
def samples(tmp_path, project_root):
    dst = tmp_path / "samples"
    shutil.copytree(project_root / "samples", dst, ignore=shutil.ignore_patterns(".barakagate", "__pycache__"))
    return dst


@pytest.fixture
def cfg(project_root):
    return load_config(project_root)


def _rules(findings):
    return {f.rule_id for f in findings}


def _by_rule(findings, rule):
    return [f for f in findings if f.rule_id == rule]


# --------------------------------------------------------------------------- regex baseline
def test_regex_baseline_fintech(samples, cfg):
    text = (samples / "fintech_morocco" / "checkout.py").read_text()
    hits = regex_baseline(text, "checkout.py", "fintech_morocco", cfg)
    assert {"ma.cin", "ma.rib", "ma.phone"} <= _rules(hits)
    assert all(h.caught_by_regex_baseline and h.line_start == 10 for h in hits)
    cin = _by_rule(hits, "ma.cin")[0]
    assert cin.offending_snippet == "BE847291" and cin.recommended_action == ActionType.SYNTHETIC_TWIN
    assert cin.replacement_snippet and cin.replacement_snippet != "BE847291"
    models = regex_baseline((samples / "fintech_morocco" / "models.py").read_text(), "models.py", "fintech_morocco", cfg)
    cmi = _by_rule(models, "ma.cmi_key")
    assert len(cmi) == 1 and cmi[0].severity == Severity.CRITICAL
    assert cmi[0].offending_snippet == 'CMI_WEBHOOK_SECRET = "cmi_live_sk_9988776655443322"'
    assert cmi[0].replacement_snippet == 'CMI_WEBHOOK_SECRET = os.getenv("CMI_WEBHOOK_SECRET", "")'
    assert cmi[0].env_var_name == "CMI_WEBHOOK_SECRET" and cmi[0].env_var_value == "cmi_live_sk_9988776655443322"
    assert not _by_rule(models, "gen.generic_secret")  # overlapping weaker rule folded into the CMI hit


def test_regex_baseline_research(samples, cfg):
    loader = regex_baseline((samples / "research_lab_um6p" / "loader.py").read_text(), "loader.py", "research_lab", cfg)
    assert {f.offending_snippet for f in _by_rule(loader, "lab.cne")} == {"R139482710", "G130045892"}
    conf = regex_baseline((samples / "research_lab_um6p" / "config.py").read_text(), "config.py", "research_lab", cfg)
    assert {"lab.internal_host", "lab.hpc_token"} <= _rules(conf)
    tok = _by_rule(conf, "lab.hpc_token")[0]
    assert tok.recommended_action == ActionType.ENV_EXTRACT and tok.env_var_name == "HPC_TOKEN"


def test_regex_baseline_general(samples, cfg):
    hits = regex_baseline((samples / "general_devsecops" / "settings.py").read_text(), "settings.py", "all", cfg)
    assert {"gen.aws_access_key", "gen.db_uri", "gen.jwt"} <= _rules(hits)
    db = _by_rule(hits, "gen.db_uri")[0]
    assert "Internal IPv4" in db.reason  # IP folded into the same line finding


def test_regex_allowlist_and_synthetic_twins_skipped(cfg):
    text = 'a = "AB000000"\nb = "ZZ123456"\nc = os.getenv("X", "cmi_live_abcdefgh")\nd = "BE847291"\n'
    hits = regex_baseline(text, "x.py", "fintech_morocco", cfg)
    assert [h.line_start for h in hits] == [4]


def test_regex_ids_deterministic(cfg):
    t = 'x = "BE847291"\n'
    assert [f.id for f in regex_baseline(t, "a.py", "all", cfg)] == [f.id for f in regex_baseline(t, "a.py", "all", cfg)]


# --------------------------------------------------------------------------- offline engine
def test_offline_fintech_finds_all_planted(samples):
    r = Scanner(samples, offline=True).scan_files([str(samples / "fintech_morocco")], preset="fintech_morocco")
    assert r.verdict == "BLOCK" and r.engine_used == "offline_heuristic"
    rules = _rules(r.findings)
    assert {"ma.cin", "ma.rib", "ma.phone", "ma.cmi_key", "heur.pii_object_dump", "heur.float_currency",
            "heur.toctou_double_spend", "heur.webhook_no_hmac", "heur.darija_pii_note",
            "heur.promo_bypass", "heur.negative_quantity"} <= rules

    dump = _by_rule(r.findings, "heur.pii_object_dump")[0]
    assert dump.severity == Severity.CRITICAL and dump.category == FindingCategory.PRIVACY_PII
    assert dump.cross_file_context_used == "fintech_morocco/models.py:MoroccanCustomer"
    assert dump.line_start == 21 and "cin_number" in dump.replacement_snippet

    hook = _by_rule(r.findings, "heur.webhook_no_hmac")[0]
    assert hook.severity == Severity.CRITICAL and hook.category == FindingCategory.LOGICAL_BUG
    assert hook.cross_file_context_used == "fintech_morocco/models.py:CMI_WEBHOOK_SECRET"
    assert "compare_digest" in hook.replacement_snippet and hook.line_start == 30

    floats = {(f.file_path, f.line_start) for f in _by_rule(r.findings, "heur.float_currency")}
    assert ("fintech_morocco/checkout.py", 15) in floats and ("fintech_morocco/fees.py", 7) in floats
    toctou = _by_rule(r.findings, "heur.toctou_double_spend")[0]
    assert toctou.severity == Severity.HIGH and (toctou.line_start, toctou.line_end) == (22, 24)
    assert _by_rule(r.findings, "heur.darija_pii_note")[0].category == FindingCategory.PRIVACY_PII
    assert _by_rule(r.findings, "heur.promo_bypass")[0].file_path == "fintech_morocco/fees.py"
    neg = _by_rule(r.findings, "heur.negative_quantity")[0]
    assert neg.line_start == 14 and neg.severity == Severity.MEDIUM

    assert r.regex_baseline_count >= 5 and r.gemma_findings_count >= 7
    assert r.indexed_chunks_count > 0 and "offline" in r.summary.lower()
    assert "Regex baseline" in r.thinking_trace
    sev = [f.severity for f in r.findings]
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    assert sev == sorted(sev, key=order.get)


def test_offline_research_finds_all_planted(samples):
    r = Scanner(samples, offline=True).scan_files([str(samples / "research_lab_um6p")], preset="research_lab")
    assert r.verdict == "BLOCK"
    rules = _rules(r.findings)
    assert {"lab.cne", "lab.internal_host", "lab.hpc_token", "heur.ml_train_test_leakage",
            "heur.missing_seed", "heur.sentinel_average"} <= rules
    leak = _by_rule(r.findings, "heur.ml_train_test_leakage")[0]
    assert leak.severity == Severity.HIGH and (leak.line_start, leak.line_end) == (18, 19)
    assert "fit(X_train)" in leak.replacement_snippet
    seed = _by_rule(r.findings, "heur.missing_seed")[0]
    assert seed.severity == Severity.MEDIUM and seed.cross_file_context_used.endswith("config.py:SEED")
    sent = _by_rule(r.findings, "heur.sentinel_average")[0]
    assert sent.cross_file_context_used.endswith("config.py:MISSING_SENTINEL") and sent.line_start == 13
    nb = [f for f in r.findings if f.file_path.endswith("exploration.ipynb")]
    assert {f.rule_id for f in nb} >= {"lab.hpc_token", "lab.cne"}
    # notebook findings point at raw JSON lines and are twin-able inside the JSON
    tok = _by_rule(nb, "lab.hpc_token")[0]
    assert tok.line_start == 25 and tok.offending_snippet == "hpc_tok_7f3a9b2c1d4e5f60718293a4"
    assert {f.line_start for f in _by_rule(nb, "lab.cne")} == {37, 38}


def test_offline_general_finds_all_planted(samples):
    r = Scanner(samples, offline=True).scan_files([str(samples / "general_devsecops")], preset="general_devsecops")
    assert r.verdict == "BLOCK"
    rules = _rules(r.findings)
    assert {"gen.aws_access_key", "gen.db_uri", "gen.jwt", "heur.sql_injection", "heur.off_by_one",
            "heur.none_dereference", "heur.missing_auth"} <= rules
    sqli = _by_rule(r.findings, "heur.sql_injection")[0]
    assert sqli.severity == Severity.CRITICAL
    assert sqli.replacement_snippet == 'return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()'
    assert _by_rule(r.findings, "heur.off_by_one")[0].replacement_snippet == "for i in range(0, len(items), page_size):"
    none = _by_rule(r.findings, "heur.none_dereference")[0]
    assert none.cross_file_context_used == "general_devsecops/db.py:find_user"
    auth = _by_rule(r.findings, "heur.missing_auth")[0]
    assert auth.severity == Severity.HIGH and auth.replacement_snippet.startswith("@require_auth\n")


def test_heuristics_quiet_on_fixed_code():
    fixed = '''
import threading
from decimal import Decimal, ROUND_HALF_UP
_LOCK = threading.Lock()

def require_auth(fn):
    return fn

@require_auth
def get_profile(email):
    user = find_user(email)
    if user is None:
        raise LookupError("no user")
    return {"id": user[0]}

@require_auth
def delete_user(user_id):
    conn = get_conn()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

def paginate(items, page_size):
    return [items[i:i + page_size] for i in range(0, len(items), page_size)]

def compute_total(amount_mad, quantity, discounts):
    if quantity <= 0:
        raise ValueError("bad qty")
    tva = (Decimal(str(amount_mad)) * Decimal("0.20")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return tva

def pay(customer, total):
    with _LOCK:
        if customer.wallet_balance_mad >= total:
            customer.wallet_balance_mad -= total

async def handle_cmi_callback(request):
    payload = await request.json()
    if not hmac.compare_digest(sig, expected):
        return
    if payload["status"] == "APPROVED":
        customer.balance += 1
'''
    from barakagate.indexer import CodebaseIndexer  # noqa: F401  (context-free run)
    assert heuristic_logic_scan(fixed, "fixed.py", []) == []


# --------------------------------------------------------------------------- normalization / verdict
def test_normalize_findings_messy_llm_json():
    raw = {"findings": [
        {"category": "PII", "severity": "high", "title": "CIN in fixture", "line": "10",
         "snippet": "BE847291", "confidence": 95, "action": "synthetic twin"},
        {"category": "bug", "severity": "Critical!", "description": "SQLi", "line_start": "17-18",
         "offending_snippet": "x", "recommended_action": "fix", "cross_file_context_used": "db.py:get_conn"},
        {"category": "secret", "severity": "weird", "reason": "key", "line_start": 0},
        "garbage", {}, {"category": "pii"},
    ]}
    out = normalize_findings(raw, "checkout.py")
    assert len(out) == 3
    a, b, c = out
    assert a.category == FindingCategory.PRIVACY_PII and a.severity == Severity.HIGH
    assert a.confidence == 0.95 and a.line_start == 10 and a.recommended_action == ActionType.SYNTHETIC_TWIN
    assert a.file_path == "checkout.py" and a.offending_snippet == "BE847291"
    assert b.category == FindingCategory.LOGICAL_BUG and b.severity == Severity.CRITICAL
    assert b.recommended_action == ActionType.CODE_PATCH and b.cross_file_context_used == "db.py:get_conn"
    assert c.category == FindingCategory.SECURITY_LEAK and c.severity == Severity.MEDIUM
    assert c.recommended_action == ActionType.ENV_EXTRACT and c.line_start is None
    assert len({f.id for f in out}) == 3


def test_normalize_image_bbox_coercion():
    raw = [{"label": "CIN", "text": "AB654321", "category": "privacy_pii", "severity": "HIGH",
            "bbox_2d": [100.6, -5, 2000, 300]},
           {"label": "frac", "bbox_2d": [0.1, 0.2, 0.3, 0.4]},
           {"label": "nobox", "text": "x"}]
    out = normalize_findings(raw, "shot.png", target_type="image")
    assert [f.bbox_2d for f in out] == [[101, 0, 1000, 300], [100, 200, 300, 400]]
    assert all(f.target_type == "image" and f.recommended_action == ActionType.GAUSSIAN_BLUR for f in out)


def test_normalize_from_string_json():
    out = normalize_findings('```json\n{"findings": [{"category": "logical_bug", "title": "t", "reason": "r",}]}\n```', "a.py")
    assert len(out) == 1


def test_compute_verdict_ignores_whitelisted(cfg):
    out = normalize_findings({"findings": [{"category": "bug", "severity": "HIGH", "title": "t"}]}, "a.py")
    assert compute_verdict(out, cfg) == "BLOCK"
    out[0].recommended_action = ActionType.WHITELIST
    assert compute_verdict(out, cfg) == "PASS"
    med = normalize_findings({"findings": [{"category": "bug", "severity": "MEDIUM", "title": "t"}]}, "a.py")
    assert compute_verdict(med, cfg) == "WARN"


def test_schemas_are_gemini_compatible():
    def walk(node):
        assert "additionalProperties" not in node and "$ref" not in node
        for v in node.get("properties", {}).values():
            walk(v)
        if "items" in node:
            walk(node["items"])
    walk(SCAN_RESPONSE_SCHEMA)
    walk(IMAGE_RESPONSE_SCHEMA)
    assert "thinking_trace" in SCAN_RESPONSE_SCHEMA["properties"]


def test_system_instruction_contains_preset_rules(cfg):
    s = build_system_instruction("fintech_morocco", cfg)
    assert "TOCTOU" in s and "VERBATIM" in s and "cross_file_context_used" in s


# --------------------------------------------------------------------------- LLM path (mocked)
class FakeRouter:
    def __init__(self, data=None, exc=None):
        self.data, self.exc, self.calls = data, exc, []

    def analyze(self, mode, prompt, system_instruction, response_schema, image_paths=None, cache_tag=""):
        self.calls.append({"mode": mode, "prompt": prompt, "system": system_instruction, "images": image_paths})
        if self.exc:
            raise self.exc
        return self.data, "gemini:gemma-4-26b-a4b-it"


def test_scan_text_merges_llm_with_regex_and_heuristics(samples):
    text = (samples / "fintech_morocco" / "checkout.py").read_text()
    llm = {"thinking_trace": "1. read\n2. resolved MoroccanCustomer", "summary": "Gemma found issues.",
           "findings": [
               {"category": "privacy_pii", "severity": "HIGH", "file_path": "checkout.py", "line_start": 10,
                "title": "CIN in QA fixture", "reason": "Gemma: real CIN in TEST_CLIENT",
                "offending_snippet": "BE847291", "recommended_action": "synthetic_twin",
                "replacement_snippet": "ZZ000001"},
               {"category": "logical_bug", "severity": "HIGH", "file_path": "checkout.py", "line_start": 3,
                "title": "Float TVA", "reason": "Gemma: float money", "offending_snippet": "tva = round(subtotal * 0.20, 2)",
                "recommended_action": "code_patch", "replacement_snippet": ""},
               {"category": "logical_bug", "severity": "LOW", "file_path": "checkout.py", "line_start": 32,
                "title": "Order id logged", "reason": "Gemma-only finding",
                "offending_snippet": 'logger.info("credited %s", payload["order_id"])',
                "recommended_action": "code_patch", "replacement_snippet": "pass"},
           ]}
    router = FakeRouter(llm)
    sc = Scanner(samples / "fintech_morocco", router=router)
    r = sc.scan_text(text, "checkout.py", EngineMode.CLOUD_FAST, "fintech_morocco")
    assert r.engine_used == "gemini:gemma-4-26b-a4b-it"
    assert r.thinking_trace.startswith("1. read")
    prompt = router.calls[0]["prompt"]
    assert "CROSS-FILE CONTEXT FROM CODEBASE INDEX" in prompt and "models.py:MoroccanCustomer" in prompt
    assert "  21 | " in prompt and "heur.pii_object_dump" in prompt

    cins = [f for f in r.findings if f.offending_snippet == "BE847291"]
    assert len(cins) == 1 and cins[0].caught_by_regex_baseline and cins[0].reason.startswith("Gemma")
    floats = [f for f in r.findings if f.line_start == 15 and f.category == FindingCategory.LOGICAL_BUG]
    assert len(floats) == 1 and floats[0].reason.startswith("Gemma")  # line snapped from 3 -> 15
    assert "Decimal" in floats[0].replacement_snippet  # empty LLM patch completed from heuristic
    assert floats[0].cross_file_context_used == "fees.py:apply_discounts"
    assert any(f.title == "Order id logged" for f in r.findings)
    assert _by_rule(r.findings, "heur.webhook_no_hmac")  # heuristic-only finding kept
    assert r.retrieved_context_Chunks[:2] == ["models.py:CMI_WEBHOOK_SECRET", "models.py:MoroccanCustomer"]
    assert sc.last_context and r.gemma_findings_count == sum(not f.caught_by_regex_baseline for f in r.findings)


def test_llm_failure_falls_back_to_offline_heuristic(samples):
    router = FakeRouter(exc=AllEnginesFailed(["gemma: 429"]))
    r = Scanner(samples / "general_devsecops", router=router).scan_files(
        [str(samples / "general_devsecops" / "api.py")], EngineMode.CLOUD_DEEP)
    assert router.calls and r.engine_used == "offline_heuristic"
    assert "offline" in r.summary.lower() and r.verdict == "BLOCK"
    assert "heur.sql_injection" in _rules(r.findings)


def test_offline_scanner_never_builds_router(samples):
    sc = Scanner(samples / "fintech_morocco", offline=True)
    sc.scan_files([str(samples / "fintech_morocco" / "checkout.py")])
    assert sc._router is None


def test_hybrid_never_sends_raw_pii(samples, tmp_path, monkeypatch):
    router = GemmaRouter(cache_path=tmp_path / "cache.json")
    sent = []

    def fake_analyze(mode, prompt, system_instruction, response_schema, image_paths=None, cache_tag="", **kw):
        sent.append(prompt + system_instruction)
        tok = next((t for t in ("[CIN_TOKEN_1]", "[CIN_1]") if t in prompt), None)
        snippet = tok or "missing"
        return {"summary": "ok", "thinking_trace": "t", "findings": [
            {"category": "privacy_pii", "severity": "HIGH", "file_path": "checkout.py", "line_start": 10,
             "title": "CIN", "reason": f"token {snippet}", "offending_snippet": snippet,
             "recommended_action": "synthetic_twin", "replacement_snippet": "ZZ000001"}]}, "gemini:gemma-4-31b-it"

    monkeypatch.setattr(router, "analyze", fake_analyze)
    text = (samples / "fintech_morocco" / "checkout.py").read_text()
    sc = Scanner(samples / "fintech_morocco", router=router)
    r = sc.scan_text(text, "checkout.py", EngineMode.HYBRID_SMART, "fintech_morocco")
    assert sent, "cloud audit was not called"
    for raw in ("BE847291", "230780123456789012345678", "+212661234567", "cmi_live_sk_9988776655443322"):
        assert raw not in sent[0]
    assert r.engine_used.startswith("hybrid:")
    assert sc.last_vault and "BE847291" in sc.last_vault.values()
    cin = [f for f in r.findings if f.offending_snippet == "BE847291"]
    assert cin and cin[0].caught_by_regex_baseline  # rehydrated locally, merged with regex


# --------------------------------------------------------------------------- diffs / images
DIFF = """diff --git a/pay.py b/pay.py
new file mode 100644
--- /dev/null
+++ b/pay.py
@@ -0,0 +1,4 @@
+import os
+CUSTOMER_CIN = "BE847291"
+def f(conn, name):
+    return conn.execute(f"SELECT * FROM t WHERE n = '{name}'")
diff --git a/old.py b/old.py
--- a/old.py
+++ b/old.py
@@ -10,3 +10,4 @@ def g():
 a = 1
-b = 2
+b = 3
+KEY = "sk_live_abcdefghijklmnop"
 c = 4
"""


def test_parse_unified_diff_line_numbers():
    added = parse_unified_diff(DIFF)
    assert added["pay.py"] == {1: "import os", 2: 'CUSTOMER_CIN = "BE847291"', 3: "def f(conn, name):",
                               4: "    return conn.execute(f\"SELECT * FROM t WHERE n = '{name}'\")"}
    assert added["old.py"] == {11: "b = 3", 12: 'KEY = "sk_live_abcdefghijklmnop"'}


def test_scan_diff_maps_lines(tmp_path):
    r = Scanner(tmp_path, offline=True).scan_diff(DIFF)
    got = {(f.file_path, f.line_start, f.rule_id) for f in r.findings}
    assert ("pay.py", 2, "ma.cin") in got
    assert ("pay.py", 4, "heur.sql_injection") in got
    assert ("old.py", 12, "ma.cmi_key") in got
    assert r.verdict == "BLOCK"


def test_scan_diff_on_disk_file_keeps_only_added_lines(samples):
    diff = ("--- a/checkout.py\n+++ b/checkout.py\n@@ -14,1 +14,2 @@\n"
            " x\n+    tva = round(subtotal * 0.20, 2)\n")
    r = Scanner(samples / "fintech_morocco", offline=True).scan_diff(diff)
    lines = {f.line_start for f in r.findings}
    assert 15 in lines and 10 not in lines  # unchanged fixture line filtered out
    # cross-file CRITICAL findings are always kept
    assert _by_rule(r.findings, "heur.pii_object_dump") and _by_rule(r.findings, "heur.webhook_no_hmac")


def test_scan_empty_diff(tmp_path):
    assert Scanner(tmp_path, offline=True).scan_diff("").verdict == "PASS"


def test_scan_image_offline_sidecar_and_unavailable(tmp_path):
    img = tmp_path / "shot.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n")
    sc = Scanner(tmp_path, offline=True)
    r = sc.scan_image(str(img))
    assert r.verdict == "WARN" and "vision engine unavailable" in r.summary and r.findings == []
    (tmp_path / "shot.png.boxes.json").write_text(json.dumps([
        {"label": "Moroccan CIN", "category": "privacy_pii", "severity": "HIGH", "value": "AB654321",
         "reason": "id", "bbox_2d": [421, 175, 444, 263]}]))
    r = sc.scan_image(str(img))
    assert r.engine_used == "offline_vision_cache" and r.verdict == "BLOCK"
    f = r.findings[0]
    assert f.target_type == "image" and f.bbox_2d == [421, 175, 444, 263]
    assert f.recommended_action == ActionType.GAUSSIAN_BLUR and f.offending_snippet == "AB654321"


def test_scan_image_uses_router(tmp_path):
    img = tmp_path / "shot.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n")
    router = FakeRouter({"summary": "1 key", "findings": [
        {"label": "CMI key", "text": "cmi_live_9823749283", "category": "security_leak", "severity": "CRITICAL",
         "bbox_2d": [10, 20, 30, 40], "reason": "merchant key"}]})
    r = Scanner(tmp_path, router=router).scan_image(str(img))
    assert router.calls[0]["images"] == [str(img)]
    assert r.verdict == "BLOCK" and r.findings[0].bbox_2d == [10, 20, 30, 40]


def test_coarse_llm_line_finding_superseded_by_precise_hits(samples):
    text = (samples / "fintech_morocco" / "checkout.py").read_text()
    line10 = text.splitlines()[9]
    router = FakeRouter({"summary": "s", "thinking_trace": "t", "findings": [
        {"category": "privacy_pii", "severity": "CRITICAL", "file_path": "checkout.py", "line_start": 10,
         "title": "Hardcoded PII fixture", "reason": "whole line", "offending_snippet": line10,
         "recommended_action": "synthetic_twin", "replacement_snippet": "TEST_CLIENT = {}"}]})
    r = Scanner(samples / "fintech_morocco", router=router).scan_text(text, "checkout.py")
    line_10 = [f for f in r.findings if f.line_start == 10]
    assert {f.rule_id for f in line_10} >= {"ma.cin", "ma.rib", "ma.phone", "heur.darija_pii_note"}
    assert not any(f.title == "Hardcoded PII fixture" for f in r.findings)


def test_bad_llm_patch_replaced_by_heuristic_patch(samples):
    text = (samples / "fintech_morocco" / "checkout.py").read_text()
    router = FakeRouter({"summary": "s", "thinking_trace": "t", "findings": [
        {"category": "logical_bug", "severity": "HIGH", "file_path": "checkout.py", "line_start": 22,
         "title": "Race", "reason": "Gemma: TOCTOU", "offending_snippet": "if customer.wallet_balance_mad >= total:",
         "recommended_action": "code_patch",
         "replacement_snippet": "# Note: add a lock\nif customer.wallet_balance_mad >= total:"},
        {"category": "logical_bug", "severity": "HIGH", "file_path": "checkout.py", "line_start": 15,
         "title": "Float", "reason": "Gemma: float", "offending_snippet": "tva = round(subtotal * 0.20, 2)",
         "recommended_action": "code_patch", "replacement_snippet": "tva = (subtotal * 20) // 100"}]})
    r = Scanner(samples / "fintech_morocco", router=router).scan_text(text, "checkout.py")
    race = next(f for f in r.findings if f.reason == "Gemma: TOCTOU")
    assert race.replacement_snippet.startswith("with ") and (race.line_start, race.line_end) == (22, 24)
    flt = next(f for f in r.findings if f.reason == "Gemma: float")
    assert flt.replacement_snippet == "tva = (subtotal * 20) // 100"  # valid LLM patch is kept


def test_code_detectors_skip_config_files():
    from barakagate.scanner import heuristic_logic_scan
    yaml_text = '- "Off-by-one loop bounds (range(len(x)+1), <= length)"\n'
    assert heuristic_logic_scan(yaml_text, ".barakagate.yaml", []) == []
    code = "def f(items):\n    for i in range(0, len(items) + 1, 2):\n        pass\n"
    assert any(f.rule_id.startswith("heur.off_by_one") for f in heuristic_logic_scan(code, "a.py", []))


def test_darija_latin_script_in_plain_text_log():
    from barakagate.scanner import heuristic_logic_scan
    log = "client: salam khouya, smiti Khadija Berrada, CIN dyali BK482913\nagent: Merci madame.\n"
    hits = heuristic_logic_scan(log, "support_log.txt", [])
    assert [f.line_start for f in hits if f.rule_id == "heur.darija_pii_note"] == [1]


def test_darija_line_keeps_value_level_regex_findings(tmp_path):
    from barakagate.scanner import Scanner
    (tmp_path / "log.txt").write_text("client: salam khouya, CIN dyali BK482913\n", encoding="utf-8")
    r = Scanner(tmp_path, offline=True).scan_files([str(tmp_path / "log.txt")])
    rules = {f.rule_id for f in r.findings}
    assert "heur.darija_pii_note" in rules and "ma.cin" in rules
