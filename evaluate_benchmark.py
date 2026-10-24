#!/usr/bin/env python3
"""Plutonium 12-case benchmark: Regex baseline (Gitleaks-style) vs Plutonium engines.

    python evaluate_benchmark.py                       # regex + offline (+ cloud_fast if GEMINI_API_KEY, + local_edge if Ollama)
    python evaluate_benchmark.py --engines regex,offline --markdown out.md --json out.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from plutonium.config import load_dotenv  # noqa: E402

SAMPLES = ROOT / "samples"
BENCH_DIR = ROOT / ".plutonium" / "bench"
OUT_DIR = ROOT / ".plutonium"

ENGINE_LABELS = {
    "regex": "Regex Baseline (Gitleaks-style)",
    "offline": "Plutonium Offline Heuristic",
    "cloud_fast": "Gemma 4 26B (cloud_fast)",
    "local_edge": "Gemma 4 E4B (local_edge)",
}

KIND_KEYWORDS = {
    "cin": ["cin", "national id", "carte nationale"],
    "rib": ["rib", "bank account", "iban"],
    "phone": ["phone", "+212", "téléphone"],
    "darija_pii": ["darija", "arabic", "support", "note", "multilingual"],
    "float_currency": ["float", "decimal", "rounding", "centime", "currency", "tva"],
    "toctou": ["race", "toctou", "double", "atomic", "lock", "concurren"],
    "webhook_hmac": ["hmac", "signature", "webhook", "callback"],
    "dict_log_pii": ["__dict__", "log", "dump", "serializ"],
    "negative_qty": ["negative", "quantity", "bound"],
    "promo_bypass": ["discount", "promo", "100%", "stack"],
    "cmi_key": ["cmi", "merchant", "live key", "payment gateway"],
    "internal_host": ["internal", "um6p", "host", "ipv4", "10.", "192.168", "endpoint", "staging"],
    "hpc_token": ["hpc", "token"],
    "cnes": ["cne", "massar", "student"],
    "sentinel_avg": ["sentinel", "-999", "nan", "missing", "average"],
    "missing_seed": ["seed", "reproduc", "random"],
    "ml_leakage": ["leak", "scaler", "fit_transform", "train_test_split", "train/test"],
    "db_uri": ["database", "db", "uri", "postgres", "password", "connection"],
    "aws": ["aws", "akia", "access key"],
    "jwt": ["jwt", "bearer", "token", "secret"],
    "none_deref": ["none", "null", "deref"],
    "sqli": ["sql", "injection"],
    "missing_auth": ["auth", "authorization", "authentication"],
    "off_by_one": ["off-by-one", "off by one", "range", "bound", "empty page"],
}


def _expected() -> Dict[str, List[dict]]:
    data = json.loads((SAMPLES / "expected_findings.json").read_text(encoding="utf-8"))
    out: Dict[str, List[dict]] = {}
    for scen, items in data.items():
        if scen.startswith("_"):
            continue
        for it in items:
            out.setdefault(it["file"], []).append(it)
    return out


DARIJA_LOG = """[support-ticket #4471] 2026-10-21 14:02 canal=whatsapp
client: salam khouya, l'paiement dyali tblocka. smiti Khadija Berrada, CIN dyali BK482913
client: hak RIB dyali bach trdo lia lflous: 007780000123456789012345
client: ila bghiti tsewelni: 0661 23 45 67, ana f Hay Riad, Rabat
agent: Merci madame, je transmets au back-office.
"""

CLEAN_CONTROL = '''"""Pure pricing helpers (negative control: must PASS)."""
from decimal import Decimal, ROUND_HALF_UP
import os

TVA_RATE = Decimal("0.20")
API_BASE = os.getenv("API_BASE", "https://api.example.com")


def tva_centimes(amount_centimes: int) -> int:
    if amount_centimes < 0:
        raise ValueError("amount must be positive")
    tva = (Decimal(amount_centimes) * TVA_RATE).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(tva)


def paginate(items, page_size):
    return [items[i:i + page_size] for i in range(0, len(items), page_size)]
'''


def build_cases() -> List[Dict[str, Any]]:
    """12 labelled cases. Each: id, name, scenario dir (copied to a stable bench dir), target, expected."""
    exp = _expected()
    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    for scen in ("fintech_morocco", "research_lab_um6p", "general_devsecops"):
        dst = BENCH_DIR / scen
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(SAMPLES / scen, dst, ignore=shutil.ignore_patterns(".plutonium", "__pycache__"))
    inline = BENCH_DIR / "inline"
    inline.mkdir(exist_ok=True)
    (inline / "support_log.txt").write_text(DARIJA_LOG, encoding="utf-8")
    (inline / "pricing_clean.py").write_text(CLEAN_CONTROL, encoding="utf-8")

    def scen_case(cid, name, rel):
        scen, fname = rel.split("/", 1)
        return {"id": cid, "name": name, "kind": "text", "root": BENCH_DIR / scen, "target": fname,
                "expected": exp.get(f"samples/{rel}", [])}

    S = "samples/screenshots/"
    cases = [
        scen_case(1, "Fintech checkout (PII fixture + cross-file bugs)", "fintech_morocco/checkout.py"),
        scen_case(2, "Fintech models (CMI live key)", "fintech_morocco/models.py"),
        scen_case(3, "Fintech fees (float MAD + promo bypass)", "fintech_morocco/fees.py"),
        scen_case(4, "Lab loader (student CNEs)", "research_lab_um6p/loader.py"),
        scen_case(5, "Lab train pipeline (ML leakage, seed, sentinel)", "research_lab_um6p/train_pipeline.py"),
        scen_case(6, "Lab config (HPC token, internal host)", "research_lab_um6p/config.py"),
        scen_case(7, "Lab notebook (.ipynb output leak)", "research_lab_um6p/exploration.ipynb"),
        scen_case(8, "DevSecOps API (SQLi, off-by-one, auth, None)", "general_devsecops/api.py"),
        scen_case(9, "DevSecOps settings (JWT, AWS, DB URI)", "general_devsecops/settings.py"),
        {"id": 10, "name": "Darija support log (multilingual PII)", "kind": "text", "root": inline,
         "target": "support_log.txt", "expected": [
             {"file": "support_log.txt", "line": 2, "category": "privacy_pii", "kind": "cin", "regex_detectable": True},
             {"file": "support_log.txt", "line": 2, "category": "privacy_pii", "kind": "darija_pii", "regex_detectable": False},
             {"file": "support_log.txt", "line": 3, "category": "privacy_pii", "kind": "rib", "regex_detectable": True},
             {"file": "support_log.txt", "line": 4, "category": "privacy_pii", "kind": "phone", "regex_detectable": True},
         ]},
        {"id": 11, "name": "DevTools screenshot (vision OCR)", "kind": "image", "root": ROOT,
         "target": str(SAMPLES / "screenshots" / "devtools_leak.png"),
         "expected": exp.get(S + "devtools_leak.png", [])},
        {"id": 12, "name": "Clean pricing module (negative control)", "kind": "text", "root": inline,
         "target": "pricing_clean.py", "expected": [], "negative_control": True},
    ]
    return cases


# --------------------------------------------------------------------------- matching

def _finding_text(f) -> str:
    return " ".join(str(x or "") for x in (f.rule_id, f.title, f.reason, f.offending_snippet)).lower()


def _kind_hit(kind: str, f) -> bool:
    txt = _finding_text(f)
    return any(k in txt for k in KIND_KEYWORDS.get(kind, [kind]))


def _matches(e: dict, f, case: dict) -> bool:
    if Path(f.file_path).name != Path(e["file"]).name:
        return False
    if case["kind"] == "image" or e.get("line") is None or str(e["file"]).endswith(".ipynb"):
        return _kind_hit(e["kind"], f)
    if f.line_start is None:
        return _kind_hit(e["kind"], f)
    lo, hi = f.line_start, f.line_end or f.line_start
    return lo - 2 <= e["line"] <= hi + 2


def score_case(case: dict, findings: list) -> Dict[str, Any]:
    target_name = Path(case["target"]).name
    fs = [f for f in findings if Path(f.file_path).name == target_name]
    expected = case["expected"]
    matched_exp, used, done = [], set(), set()

    def dist(e, f):
        return abs((f.line_start or 0) - (e.get("line") or 0))

    # greedy 1:1 assignment: pass 1 only takes findings whose wording matches the expected kind,
    # pass 2 lets the remaining expectations take any nearby finding.
    for require_kind in (True, False):
        for ei, e in enumerate(expected):
            if ei in done:
                continue
            cands = [i for i, f in enumerate(fs) if i not in used and _matches(e, f, case)
                     and (not require_kind or _kind_hit(e["kind"], f))]
            if not cands:
                continue
            cands.sort(key=lambda i: dist(e, fs[i]))
            used.add(cands[0])
            done.add(ei)
            matched_exp.append((e, fs[cands[0]]))
    tp_findings = sum(1 for f in fs if any(_matches(e, f, case) for e in expected))
    sev_fp = [f for f in fs if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM")]
    return {
        "expected": len(expected),
        "caught": len(matched_exp),
        "leaks_caught": sum(1 for e, _ in matched_exp if e["category"] != "logical_bug"),
        "logic_caught": sum(1 for e, _ in matched_exp if e["category"] == "logical_bug"),
        "cross_file": sum(1 for _, f in matched_exp if f.cross_file_context_used),
        "findings": len(fs),
        "true_findings": tp_findings,
        "negative_fp": len(sev_fp) if case.get("negative_control") else 0,
        "missed": [f'{e["kind"]}@{e.get("line")}' for ei, e in enumerate(expected) if ei not in done],
    }


# --------------------------------------------------------------------------- engines

def _ollama_up() -> bool:
    try:
        from plutonium.llm_router import GemmaRouter
        return GemmaRouter(cache_path=BENCH_DIR / "_probe.json").ollama_available()
    except Exception:  # noqa: BLE001
        return False


def default_engines(offline: bool = False) -> List[str]:
    eng = ["regex", "offline"]
    if offline:
        return eng
    load_dotenv()
    if os.environ.get("GEMINI_API_KEY"):
        eng.append("cloud_fast")
    eng.append("local_edge")  # reported as n/a when Ollama is offline
    return eng


def run_engine_on_case(engine: str, case: dict) -> Dict[str, Any]:
    from plutonium.models import EngineMode
    from plutonium import scanner as sc
    t0 = time.perf_counter()
    engine_used = engine
    if engine == "regex":
        if case["kind"] == "image":
            findings = []  # a regex scanner cannot read pixels
        else:
            path = case["root"] / case["target"]
            findings = sc.regex_baseline(path.read_text(encoding="utf-8"), case["target"])
        engine_used = "regex"
    else:
        offline = engine == "offline"
        router = None
        if not offline:
            from plutonium.llm_router import GemmaRouter
            router = GemmaRouter(cache_path=OUT_DIR / "demo_cache.json", offline_safe=True)
        scanner = sc.Scanner(root=str(case["root"]), router=router, offline=offline)
        mode = EngineMode.LOCAL_EDGE if engine == "local_edge" else EngineMode.CLOUD_FAST
        if case["kind"] == "image":
            res = scanner.scan_image(case["target"], mode=mode)
        else:
            res = scanner.scan_files([str(case["root"] / case["target"])], mode=mode)
        findings, engine_used = res.findings, res.engine_used
    latency = time.perf_counter() - t0
    out = score_case(case, findings)
    out.update({"latency_s": round(latency, 3), "engine_used": engine_used})
    return out


def run_benchmark(engines: Optional[List[str]] = None, offline: bool = False) -> Dict[str, Any]:
    engines = engines or default_engines(offline)
    if offline:
        engines = [e for e in engines if e in ("regex", "offline")]
    cases = build_cases()
    ollama = _ollama_up() if "local_edge" in engines else False
    result: Dict[str, Any] = {"engines": {}, "cases": [
        {"id": c["id"], "name": c["name"], "target": Path(c["target"]).name, "expected": len(c["expected"]),
         "negative_control": bool(c.get("negative_control"))} for c in cases]}
    for eng in engines:
        label = ENGINE_LABELS.get(eng, eng)
        if eng == "local_edge" and not ollama:
            result["engines"][eng] = {"label": label, "status": "n/a (Ollama offline)"}
            continue
        if eng == "cloud_fast" and not os.environ.get("GEMINI_API_KEY"):
            result["engines"][eng] = {"label": label, "status": "n/a (no GEMINI_API_KEY)"}
            continue
        per_case = {}
        for c in cases:
            try:
                per_case[c["id"]] = run_engine_on_case(eng, c)
            except Exception as e:  # noqa: BLE001 - one broken case must not kill the matrix
                per_case[c["id"]] = {"error": f"{type(e).__name__}: {e}", "expected": len(c["expected"]),
                                     "caught": 0, "leaks_caught": 0, "logic_caught": 0, "cross_file": 0,
                                     "findings": 0, "true_findings": 0, "negative_fp": 0, "latency_s": 0.0,
                                     "missed": []}
        tot = lambda k: sum(r.get(k, 0) for r in per_case.values())  # noqa: E731
        expected = sum(len(c["expected"]) for c in cases)
        exp_leaks = sum(1 for c in cases for e in c["expected"] if e["category"] != "logical_bug")
        exp_logic = expected - exp_leaks
        neg = [r for cid, r in per_case.items() if any(c["id"] == cid and c.get("negative_control") for c in cases)]
        result["engines"][eng] = {
            "label": label, "status": "ok",
            "leaks_caught": tot("leaks_caught"), "leaks_expected": exp_leaks,
            "logic_caught": tot("logic_caught"), "logic_expected": exp_logic,
            "cross_file_proofs": tot("cross_file"),
            "recall": round(tot("caught") / expected, 3) if expected else 0.0,
            "precision": round(tot("true_findings") / tot("findings"), 3) if tot("findings") else 0.0,
            "negative_control_fp": sum(r.get("negative_fp", 0) for r in neg),
            "avg_latency_s": round(tot("latency_s") / max(1, len(per_case)), 3),
            "engines_used": sorted({r.get("engine_used", "?") for r in per_case.values() if r.get("engine_used")}),
            "per_case": per_case,
        }
    return result


def to_markdown(result: Dict[str, Any]) -> str:
    engs = result["engines"]
    lines = ["## Plutonium Benchmark: Regex vs Gemma 4", "",
             "| Engine | Leaks/PII caught | Logic bugs caught | Cross-file proofs | Recall | Precision | FP on clean control | Avg latency |",
             "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"]
    for key, e in engs.items():
        if e.get("status") != "ok":
            lines.append(f"| {e['label']} | {e['status']} | - | - | - | - | - | - |")
            continue
        lines.append(
            f"| {e['label']} | {e['leaks_caught']}/{e['leaks_expected']} | {e['logic_caught']}/{e['logic_expected']} | "
            f"{e['cross_file_proofs']} | {e['recall']:.0%} | {e['precision']:.0%} | {e['negative_control_fp']} | "
            f"{e['avg_latency_s']:.2f}s |")
    ok = [k for k, e in engs.items() if e.get("status") == "ok"]
    if ok:
        lines += ["", "### Per-case detection (caught / expected)", "",
                  "| # | Case | " + " | ".join(engs[k]["label"] for k in ok) + " |",
                  "| :-: | :--- | " + " | ".join(":---:" for _ in ok) + " |"]
        for c in result["cases"]:
            cells = []
            for k in ok:
                r = engs[k]["per_case"].get(c["id"]) or engs[k]["per_case"].get(str(c["id"]), {})
                if "error" in r:
                    cells.append("error")
                elif c["negative_control"]:
                    cells.append("PASS" if r.get("negative_fp", 0) == 0 else f"{r['negative_fp']} FP")
                else:
                    cells.append(f"{r.get('caught', 0)}/{c['expected']}")
            lines.append(f"| {c['id']} | {c['name']} | " + " | ".join(cells) + " |")
        used = "; ".join(f"{engs[k]['label']}: {', '.join(engs[k]['engines_used'])}" for k in ok)
        lines += ["", f"_Engines actually used: {used}._",
                  "_Matching: same file and |line diff| <= 2 (notebooks/images: issue-kind keyword match). "
                  "Negative control counts MEDIUM+ findings on a clean file._"]
    return "\n".join(lines) + "\n"


def write_outputs(result: Dict[str, Any], md: str, json_path: Optional[str] = None,
                  md_path: Optional[str] = None) -> None:
    jp = Path(json_path) if json_path else OUT_DIR / "benchmark.json"
    mp = Path(md_path) if md_path else OUT_DIR / "benchmark.md"
    jp.parent.mkdir(parents=True, exist_ok=True)
    mp.parent.mkdir(parents=True, exist_ok=True)
    jp.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    mp.write_text(md, encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engines", help="comma list: regex,offline,cloud_fast,local_edge")
    ap.add_argument("--offline", action="store_true", help="deterministic engines only")
    ap.add_argument("--json", dest="json_path", help="JSON output path (default .plutonium/benchmark.json)")
    ap.add_argument("--markdown", dest="md_path", help="Markdown output path (default .plutonium/benchmark.md)")
    args = ap.parse_args(argv)
    engines = [e.strip() for e in args.engines.split(",")] if args.engines else None
    result = run_benchmark(engines, args.offline)
    md = to_markdown(result)
    write_outputs(result, md, args.json_path, args.md_path)
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
