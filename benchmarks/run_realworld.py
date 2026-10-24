"""Held-out real-world benchmark runner (see benchmarks/README.md for the protocol).

    python3 benchmarks/run_realworld.py --engines regex,offline            # instant, no network
    python3 benchmarks/run_realworld.py --engines cloud_fast               # live Gemma 4 26B
    python3 benchmarks/run_realworld.py --report                           # rebuild report from raw/*.json

Each engine's raw findings are stored in benchmarks/results/raw/<engine>.json; the report merges every
engine present and (re)writes benchmarks/results/realworld.md + the README section.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

FIX = HERE / "realworld"
RAW = HERE / "results" / "raw"
OUT_MD = HERE / "results" / "realworld.md"
README = ROOT / "README.md"
MARK_START, MARK_END = "<!-- REALWORLD_BENCH_START -->", "<!-- REALWORLD_BENCH_END -->"

ENGINE_LABELS = {
    "regex": "Regex baseline (Gitleaks-style)",
    "offline": "BarakaGate offline heuristics (no LLM)",
    "cloud_fast": "BarakaGate + Gemma 4 26B MoE",
    "cloud_deep": "BarakaGate + Gemma 4 31B dense",
    "local_edge": "BarakaGate + Gemma 4 E4B (Ollama)",
    "hybrid_smart": "BarakaGate hybrid (local redact → 31B)",
}
KIND_WORDS = {
    "stripe_key": ["stripe", "sk_live"], "db_uri": ["database", "uri", "mysql", "password", "connection"],
    "float_currency": ["float", "decimal", "currency", "rounding", "centime", "vat", "tva", "precision"],
    "toctou": ["race", "toctou", "concurren", "atomic", "lock", "double"], "lost_update": ["race", "lost update", "concurren", "atomic", "double", "toctou", "transaction"],
    "pii_dump": ["pii", "log", "vars", "dump", "personal", "buyer"], "missing_auth": ["auth", "login_required", "unauthenticated", "authoriz"],
    "webhook_no_signature": ["signature", "hmac", "verif", "webhook", "callback", "notify"], "sqli": ["sql", "inject"],
    "cin": ["cin", "national", "identity", "identit"], "iban": ["iban", "bank"], "phone": ["phone", "tele", "mobile"],
    "rib": ["rib", "bank", "account"], "name_address": ["name", "address", "adresse", "personal", "pii"],
    "split_secret": ["cmi", "key", "secret", "concaten"], "openai_key": ["openai", "sk-proj", "api key", "key"],
    "timing_unsafe_compare": ["timing", "constant", "===", "timingsafeequal", "compare"], "off_by_one": ["off-by-one", "off by one", "bound", "<="],
    "ml_leakage": ["leak", "fit", "split", "train", "test"], "unseeded_rng": ["seed", "reproduc", "random", "permutation"],
    "sentinel_mean": ["sentinel", "na_value", "-1", "missing", "mean", "nan"], "cne": ["cne", "student", "massar"],
    "unquoted_shell_secret": ["wandb", "api key", "secret", "token", "key"], "internal_host": ["internal", "host", "um6p", "hpc"],
    "notebook_output_token": ["hf_", "hugging", "token"],
}


# ----------------------------------------------------------------------------- ground truth
def load_truth() -> Dict[str, Any]:
    L = json.loads((FIX / "labels.json").read_text(encoding="utf-8"))

    def line_of(f: str, anchor: str) -> int:
        lines = (FIX / f).read_text(encoding="utf-8").splitlines()
        hits = [i + 1 for i, l in enumerate(lines) if anchor in l]
        if len(hits) != 1:
            raise SystemExit(f"anchor {anchor!r} in {f} matched lines {hits}")
        return hits[0]

    for p in L["positives"]:
        p["start"] = line_of(p["file"], p["anchor"])
        p["end"] = line_of(p["file"], p["until"]) if p.get("until") else p["start"]
        p["locs"] = [(p["file"], p["start"], p["end"])] + [
            (a["file"], line_of(a["file"], a["anchor"]), line_of(a["file"], a["anchor"])) for a in p.get("alt", [])]
    for t in L["traps"]:
        t["line"] = line_of(t["file"], t["anchor"])
    L["image_truth"] = json.loads((FIX / L["images"]["truth"]).read_text(encoding="utf-8"))
    return L


def files_to_scan(L) -> List[str]:
    fs = {p["file"] for p in L["positives"]} | {a["file"] for p in L["positives"] for a in p.get("alt", [])}
    fs |= {t["file"] for t in L["traps"]} | set(L["negative_files"]) | set(L["extra_scan_files"])
    return sorted(fs)


# ----------------------------------------------------------------------------- running engines
def _finding_dict(f, scanned: str) -> Dict[str, Any]:
    d = f.model_dump(mode="json")
    d["scanned_file"] = scanned
    return d


def run_engine(engine: str, L, retries: int = 2) -> Dict[str, Any]:
    from barakagate.models import EngineMode
    from barakagate.scanner import Scanner, regex_baseline
    from barakagate.llm_router import GemmaRouter

    work = Path(tempfile.mkdtemp(prefix="bg_realworld_"))
    shutil.copytree(FIX, work / "fx", ignore=shutil.ignore_patterns("labels.json", "_truth.json", "make_screenshots.py"))
    fx = work / "fx"
    scanners: Dict[str, Any] = {}
    llm = engine not in ("regex", "offline")

    def scanner_for(project: str):
        if project not in scanners:
            router = GemmaRouter(cache_path=work / f"cache_{project}.json", offline_safe=False) if llm else None
            scanners[project] = Scanner(fx / project, router=router, offline=not llm)
        return scanners[project]

    records = []
    for rel in files_to_scan(L):
        project, inner = rel.split("/", 1)
        t0, attempts, res = time.time(), 0, None
        if engine == "regex":
            text = (fx / rel).read_text(encoding="utf-8")
            fnds = regex_baseline(text, inner, "all")
            res = {"engine_used": "regex", "findings": [_finding_dict(f, rel) for f in fnds]}
        else:
            sc = scanner_for(project)
            while True:
                attempts += 1
                r = sc.scan_files([str(fx / rel)], EngineMode(engine) if llm else EngineMode.CLOUD_FAST, "all")
                if not llm or "gemini" in r.engine_used or "ollama" in r.engine_used or attempts > retries:
                    break
                print(f"    ↻ {rel}: fell back to {r.engine_used}, retrying in 15s", flush=True)
                time.sleep(15)
            res = {"engine_used": r.engine_used, "findings": [_finding_dict(f, rel) for f in r.findings],
                   "context": r.retrieved_context_Chunks}
        res.update(file=rel, latency_s=round(time.time() - t0, 2), attempts=attempts)
        records.append(res)
        print(f"  [{engine}] {rel}: {len(res['findings'])} findings via {res['engine_used']} ({res['latency_s']}s)", flush=True)

    images = []
    for rel in L["images"]["positive_images"] + L["images"]["negative_images"]:
        t0, attempts = time.time(), 0
        if engine == "regex":
            res = {"engine_used": "regex (no vision)", "findings": []}
        else:
            sc = scanner_for("screenshots")
            while True:
                attempts += 1
                r = sc.scan_image(str(fx / rel), EngineMode(engine) if llm else EngineMode.CLOUD_FAST, "all")
                if not llm or "gemini" in r.engine_used or "ollama" in r.engine_used or attempts > retries:
                    break
                print(f"    ↻ {rel}: fell back to {r.engine_used}, retrying in 15s", flush=True)
                time.sleep(15)
            res = {"engine_used": r.engine_used, "findings": [_finding_dict(f, rel) for f in r.findings]}
        res.update(file=rel, latency_s=round(time.time() - t0, 2), attempts=attempts)
        images.append(res)
        print(f"  [{engine}] {rel}: {len(res['findings'])} boxes via {res['engine_used']} ({res['latency_s']}s)", flush=True)
    shutil.rmtree(work, ignore_errors=True)
    return {"engine": engine, "ran_at": time.strftime("%Y-%m-%d %H:%M:%S"), "files": records, "images": images}


# ----------------------------------------------------------------------------- scoring
def _tolerance(file: str) -> int:
    """Line slack when matching: code ±2; one-record-per-line data files must match exactly."""
    ext = Path(file).suffix.lower()
    return 0 if ext in (".csv", ".json", ".jsonl", ".txt", ".log") else 1 if ext == ".ipynb" else 2


def _cls(f) -> str:
    return "bug" if f["category"] == "logical_bug" else "leak"


def _text(f) -> str:
    return " ".join(str(f.get(k) or "") for k in ("title", "reason", "rule_id", "offending_snippet")).lower()


def _iou(a, b) -> float:
    y1, x1, y2, x2 = max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])
    inter = max(0, y2 - y1) * max(0, x2 - x1)
    area = lambda q: max(0, q[2] - q[0]) * max(0, q[3] - q[1])
    return inter / (area(a) + area(b) - inter + 1e-9)


def _file_of(f, project: str) -> str:
    fp = (f.get("file_path") or "").replace("\\", "/").lstrip("./")
    if fp and (FIX / project / fp).exists():
        return f"{project}/{fp}"
    return f["scanned_file"]


def score(raw: Dict[str, Any], L) -> Dict[str, Any]:
    pos = L["positives"]
    lines_cache: Dict[str, List[str]] = {}

    def lines(f):
        if f not in lines_cache:
            lines_cache[f] = (FIX / f).read_text(encoding="utf-8").splitlines()
        return lines_cache[f]

    findings = []
    for rec in raw["files"]:
        project = rec["file"].split("/", 1)[0]
        for f in rec["findings"]:
            f = dict(f); f["_file"] = _file_of(f, project); f["_engine_used"] = rec["engine_used"]
            findings.append(f)
    # de-duplicate the same finding reported while scanning two different files
    seen, uniq = set(), []
    for f in findings:
        key = (f["_file"], f.get("line_start"), f.get("rule_id"), (f.get("offending_snippet") or "")[:60])
        if key not in seen:
            seen.add(key); uniq.append(f)
    findings = uniq

    matched: Dict[str, Dict] = {}
    trap_hits, neg_fps, extras = [], [], []
    remaining = []
    for f in findings:
        ln, file = f.get("line_start") or 0, f["_file"]
        snip = (f.get("offending_snippet") or "").strip()
        if file in L["negative_files"]:
            neg_fps.append(f); continue
        trap = next((t for t in L["traps"] if t["file"] == file and (
            ln == t["line"] or (len(snip) >= 6 and snip in lines(file)[t["line"] - 1]
                                and not any(snip in "\n".join(lines(file)[s - 1:e])
                                            for p in pos for (pf, s, e) in p["locs"] if pf == file)))), None)
        if trap:
            trap_hits.append((trap, f)); continue
        remaining.append(f)

    cands = []
    for fi, f in enumerate(remaining):
        ln, file, txt = f.get("line_start") or 0, f["_file"], _text(f)
        snip = (f.get("offending_snippet") or "").strip()
        for p in pos:
            for (pf, s, e) in p["locs"]:
                if pf != file:
                    continue
                tol = _tolerance(file)
                near = s - tol <= ln <= e + tol
                in_span = len(snip) >= 6 and any(snip.splitlines()[0].strip() in l for l in lines(file)[s - 1:e])
                if not (near or in_span):
                    continue
                kw = any(w in txt for w in KIND_WORDS.get(p["kind"], []))
                if _cls(f) != p["class"] and not kw:
                    continue
                anchor_in = p["anchor"].lower() in txt
                sc = 4 * anchor_in + 2 * kw + (_cls(f) == p["class"]) + (1 if s <= ln <= e else 0) + (0.5 if in_span else 0)
                cands.append((sc, fi, p["id"]))
    used_f, used_p = set(), set()
    for sc, fi, pid in sorted(cands, key=lambda c: -c[0]):
        if fi in used_f or pid in used_p:
            continue
        used_f.add(fi); used_p.add(pid); matched[pid] = remaining[fi]
    extras = [f for i, f in enumerate(remaining) if i not in used_f]

    # images: localization by IoU against pixel-exact truth
    thr = L["images"]["iou_threshold"]
    img_hits, img_extras, img_neg = {}, [], []
    for rec in raw["images"]:
        truth = [(i, t) for i, t in enumerate(L["image_truth"]) if rec["file"].endswith(t["image"])]
        boxes = [f for f in rec["findings"] if f.get("bbox_2d")]
        if rec["file"] in L["images"]["negative_images"]:
            img_neg.extend(boxes); continue
        used = set()
        for i, t in truth:
            best = max(((j, _iou(t["bbox_2d"], b["bbox_2d"])) for j, b in enumerate(boxes) if j not in used),
                       key=lambda x: x[1], default=(None, 0))
            if best[0] is not None and best[1] >= thr:
                used.add(best[0]); img_hits[i] = round(best[1], 2)
        img_extras.extend(b for j, b in enumerate(boxes) if j not in used)

    leak_ids = [p["id"] for p in pos if p["class"] == "leak"]
    bug_ids = [p["id"] for p in pos if p["class"] == "bug"]
    beyond = [p["id"] for p in pos if not p["regex_expected"]]
    xfile = [p["id"] for p in pos if p.get("cross_file")]
    tp = len(matched)
    fp_total = len(trap_hits) + len(neg_fps) + len(extras) + len(img_extras) + len(img_neg)
    img_tp = len(img_hits)
    lat = [r["latency_s"] for r in raw["files"] + raw["images"]]
    llm_answers = [r for r in raw["files"] + raw["images"] if "gemini" in r["engine_used"] or "ollama" in r["engine_used"]]
    return {
        "engine": raw["engine"], "label": ENGINE_LABELS.get(raw["engine"], raw["engine"]), "ran_at": raw.get("ran_at"),
        "matched": {pid: {"line": f.get("line_start"), "title": f.get("title"), "engine_used": f["_engine_used"],
                          "cross_file": f.get("cross_file_context_used")} for pid, f in matched.items()},
        "leaks": (sum(i in matched for i in leak_ids), len(leak_ids)),
        "bugs": (sum(i in matched for i in bug_ids), len(bug_ids)),
        "beyond_regex": (sum(i in matched for i in beyond), len(beyond)),
        "cross_file": (sum(i in matched for i in xfile), len(xfile)),
        "cross_file_cited": sum(bool(matched[i].get("cross_file_context_used")) for i in xfile if i in matched),
        "image_boxes": (img_tp, len(L["image_truth"])), "image_hits": img_hits,
        "recall": (tp + img_tp) / (len(pos) + len(L["image_truth"])),
        "precision": (tp + img_tp) / max(1, tp + img_tp + fp_total),
        "traps_hit": sorted({t["anchor"] for t, _ in trap_hits}), "trap_fp": len(trap_hits), "traps_total": len(L["traps"]),
        "neg_file_fp": len(neg_fps), "neg_image_fp": len(img_neg), "extras": len(extras) + len(img_extras),
        "extra_list": [f"{f['_file']}:{f.get('line_start')} — {f.get('title')}" for f in extras] +
                      [f"{f['scanned_file']} box — {f.get('title')}" for f in img_extras],
        "fp_list": [f"TRAP {t['file']}:{t['line']} ({t['why']}) ← {f.get('title')}" for t, f in trap_hits] +
                   [f"CLEAN {f['_file']}:{f.get('line_start')} ← {f.get('title')}" for f in neg_fps] +
                   [f"CLEAN IMAGE {f['scanned_file']} ← {f.get('title')}" for f in img_neg],
        "avg_latency": round(sum(lat) / max(1, len(lat)), 1),
        "llm_coverage": (len(llm_answers), len(raw["files"]) + len(raw["images"])),
        "engines_used": sorted({r["engine_used"] for r in raw["files"] + raw["images"]}),
    }


# ----------------------------------------------------------------------------- statistics
def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value on discordant pairs (b: only A caught, c: only B caught)."""
    from math import comb
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n)


def caught_set(s, L) -> set:
    return set(s["matched"]) | {f"IMG{i + 1}" for i in s["image_hits"]}


# ----------------------------------------------------------------------------- report
def pct(a, b):
    return f"{a}/{b} ({100 * a / b:.0f}%)" if b else "-"


def to_markdown(scores: List[Dict[str, Any]], L) -> str:
    order = [e for e in ENGINE_LABELS if e in {s["engine"] for s in scores}]
    S = {s["engine"]: s for s in scores}
    n_files = len(files_to_scan(L))
    out = [f"**Held-out set:** 4 mini-projects (Python/Flask, TypeScript/Prisma, ML research, clean controls) · "
           f"{n_files} files + 3 screenshots · **{len(L['positives'])} labelled issues + {len(L['image_truth'])} image regions**, "
           f"**{len(L['traps'])} false-positive traps**, {len(L['negative_files'])} fully-clean files and 1 clean image. "
           f"Ground truth was committed before any engine ran on it (`benchmarks/realworld/labels.json`).", "",
           "| Engine | Leaks/PII | Logic bugs | Beyond-regex edge cases | Cross-file bugs | Screenshot regions (IoU≥0.2) | Recall | Strict precision | Traps fired | FP on clean files/image | Avg s/file |",
           "| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |"]
    for e in order:
        s = S[e]
        out.append(f"| {s['label']} | {pct(*s['leaks'])} | {pct(*s['bugs'])} | {pct(*s['beyond_regex'])} | "
                   f"{pct(*s['cross_file'])} | {pct(*s['image_boxes'])} | **{100 * s['recall']:.0f}%** | {100 * s['precision']:.0f}% | "
                   f"{s['trap_fp']}/{s['traps_total']} | {s['neg_file_fp']} / {s['neg_image_fp']} | {s['avg_latency']} |")
    n_items = len(L["positives"]) + len(L["image_truth"])
    out += ["", "**Statistical confidence** (n = %d labelled items; Wilson 95%% CI on recall; exact McNemar test on paired per-item outcomes vs. the regex baseline):" % n_items, "",
            "| Engine | Caught | Recall [95% CI] | Only this engine caught / only regex caught | McNemar p vs regex |",
            "| :--- | :-: | :-: | :-: | :-: |"]
    base = caught_set(S["regex"], L) if "regex" in S else set()
    for e in order:
        cs = caught_set(S[e], L)
        lo, hi = wilson(len(cs), n_items)
        if e == "regex":
            out.append(f"| {S[e]['label']} | {len(cs)}/{n_items} | {100 * len(cs) / n_items:.0f}% [{100 * lo:.0f}–{100 * hi:.0f}%] | — | — |")
            continue
        b, c = len(cs - base), len(base - cs)
        pv = mcnemar_exact(b, c)
        out.append(f"| {S[e]['label']} | {len(cs)}/{n_items} | {100 * len(cs) / n_items:.0f}% [{100 * lo:.0f}–{100 * hi:.0f}%] | {b} / {c} | "
                   f"{'%.1e' % pv if pv < 0.001 else '%.3f' % pv} |")
    out += ["", "<details><summary><b>Per-issue results (edge-case by edge-case)</b></summary>", "",
            "| ID | Edge case | Type | " + " | ".join(ENGINE_LABELS[e].split(" (")[0].replace("BarakaGate + ", "") for e in order) + " |",
            "| :-: | :--- | :-: | " + " | ".join(":-:" for _ in order) + " |"]
    for p in L["positives"]:
        cells = []
        for e in order:
            m = S[e]["matched"].get(p["id"])
            cells.append("✅" + (" 🔗" if m and m.get("cross_file") and p.get("cross_file") else "") if m else "❌")
        out.append(f"| {p['id']} | {p['edge']} | {p['class']} | " + " | ".join(cells) + " |")
    for i, t in enumerate(L["image_truth"]):
        cells = [f"✅ {S[e]['image_hits'][i]:.2f}" if i in S[e]["image_hits"] else "❌" for e in order]
        out.append(f"| IMG{i + 1} | `{t['image']}` — {t['kind']} region | leak | " + " | ".join(cells) + " |")
    out += ["", "✅ caught · ❌ missed · 🔗 finding cited the cross-file symbol that proves it · image cells show IoU with the true text box.",
            "", "</details>", ""]
    for e in order:
        s = S[e]
        if s["fp_list"] or s["extra_list"]:
            out += [f"<details><summary>{s['label']}: {len(s['fp_list'])} false positives, {s['extras']} unlabeled extra findings</summary>", ""]
            out += [f"- ❗ {x}" for x in s["fp_list"]] + [f"- ❔ {x}" for x in s["extra_list"]]
            out += ["", "</details>", ""]
    notes = []
    for e in order:
        s = S[e]
        if e not in ("regex", "offline"):
            notes.append(f"{s['label']}: {s['llm_coverage'][0]}/{s['llm_coverage'][1]} scans answered by the model "
                         f"(engines seen: {', '.join(s['engines_used'])}); run {s['ran_at']}.")
    if notes:
        out += ["**Run notes.** " + " ".join(notes), ""]
    out += ["**How to read this.** *Strict precision* counts every finding that is not one of the labelled issues as a false "
            "positive, including \"unlabeled extras\" a reviewer might still consider valid (they're listed above for audit). "
            "*Traps* are lines that look dangerous but are correct (env-read secrets, `compare_digest`, parameterized `%s`, "
            "clamped discounts, CIN-shaped SKUs, `.env.example` placeholders, seeded RNGs, masked sentinels).",
            "", "Reproduce: `python3 benchmarks/run_realworld.py --engines regex,offline,cloud_fast`."]
    return "\n".join(out)


def write_report(L) -> str:
    scores = [score(json.loads(p.read_text()), L) for p in sorted(RAW.glob("*.json"))]
    if not scores:
        raise SystemExit("no raw results yet; run with --engines first")
    md = to_markdown(scores, L)
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("# BarakaGate — Held-out Real-World Benchmark\n\n" + md + "\n", encoding="utf-8")
    (OUT_MD.with_suffix(".json")).write_text(json.dumps(scores, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    if README.exists():
        r = README.read_text(encoding="utf-8")
        block = f"{MARK_START}\n{md}\n{MARK_END}"
        if MARK_START in r:
            r = r.split(MARK_START)[0] + block + r.split(MARK_END, 1)[1]
            README.write_text(r, encoding="utf-8")
    return md


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engines", default="", help="comma list: regex,offline,cloud_fast,cloud_deep,local_edge,hybrid_smart")
    ap.add_argument("--report", action="store_true", help="only rebuild the report from raw results")
    a = ap.parse_args(argv)
    from barakagate.config import load_dotenv
    load_dotenv()
    L = load_truth()
    RAW.mkdir(parents=True, exist_ok=True)
    for e in [x.strip() for x in a.engines.split(",") if x.strip()]:
        print(f"== {ENGINE_LABELS.get(e, e)}", flush=True)
        raw = run_engine(e, L)
        (RAW / f"{e}.json").write_text(json.dumps(raw, indent=1, ensure_ascii=False), encoding="utf-8")
    print(write_report(L))
    return 0


if __name__ == "__main__":
    sys.exit(main())
