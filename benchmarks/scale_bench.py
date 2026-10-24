"""Scalability + noise benchmark on real open-source code (no LLM calls, no network).

    python3 benchmarks/scale_bench.py

Corpus: the installed source of widely used Python libraries, copied to a temp dir in 3 cumulative tiers.
Measures indexing cost, incremental re-index, retrieval latency, cross-file definition recall of the context
packer, prompt-size reduction vs. sending the repo, and regex/heuristic alert noise per KLOC.
Writes benchmarks/results/scale.json + scale.md.
"""
from __future__ import annotations

import importlib
import json
import os
import random
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

TIERS = [
    ("S", ["requests", "httpx", "typer", "uvicorn"]),
    ("M", ["fastapi", "starlette", "pydantic", "rich"]),
    ("L", ["google.genai", "PIL", "numpy"]),
]


def pkg_dir(name: str) -> Path:
    return Path(importlib.import_module(name).__file__).parent


def copy_py(src: Path, dst: Path) -> None:
    for f in src.rglob("*.py"):
        out = dst / f.relative_to(src.parent)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, out)


def pctl(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


def main() -> int:
    from plutonium.indexer import CodebaseIndexer
    from plutonium.models import EngineMode
    from plutonium.scanner import heuristic_logic_scan, regex_baseline

    random.seed(0)
    work = Path(tempfile.mkdtemp(prefix="bg_scale_"))
    corpus = work / "corpus"
    rows, pkgs_so_far = [], []
    for tier, pkgs in TIERS:
        for p in pkgs:
            copy_py(pkg_dir(p), corpus)
            pkgs_so_far.append(p)
        files = sorted(corpus.rglob("*.py"))
        texts = {f: f.read_text(encoding="utf-8", errors="ignore") for f in files}
        loc = sum(t.count("\n") + 1 for t in texts.values())
        mb = sum(len(t.encode()) for t in texts.values()) / 1e6
        shutil.rmtree(corpus / ".plutonium", ignore_errors=True)

        ix = CodebaseIndexer(corpus)
        t = time.perf_counter(); st = ix.build(force=True); cold = time.perf_counter() - t
        t = time.perf_counter(); ix2 = CodebaseIndexer(corpus); st2 = ix2.build(); warm = time.perf_counter() - t
        victim = random.choice(files)
        victim.write_text(texts[victim] + "\n\ndef _bg_touch():\n    return 1\n", encoding="utf-8")
        t = time.perf_counter(); ix3 = CodebaseIndexer(corpus); st3 = ix3.build(); incr = time.perf_counter() - t
        victim.write_text(texts[victim], encoding="utf-8")
        index_kb = (corpus / ".plutonium" / "index.json").stat().st_size / 1024

        # retrieval: sample real functions as "changed code" and check the packer brings their callees
        funcs = [c for c in ix.chunks if c.chunk_type in ("function", "class") and len(c.called_symbols) >= 2]
        sample = random.sample(funcs, min(200, len(funcs)))
        lat = {m: [] for m in ("cloud", "local")}
        hit = {m: [0, 0] for m in ("cloud", "local")}
        ctx_chars = {m: [] for m in ("cloud", "local")}
        for c in sample:
            ext_defs = {s for s in c.called_symbols if s in ix.symbol_map and ix.symbol_map[s].file_path != c.file_path}
            for m, mode in (("cloud", EngineMode.CLOUD_FAST), ("local", EngineMode.LOCAL_EDGE)):
                t = time.perf_counter()
                ctx = ix.get_context_for_target(c.code, [c.file_path], mode)
                lat[m].append((time.perf_counter() - t) * 1000)
                got = {x.symbol_name for x in ctx}
                hit[m][0] += len(ext_defs & got); hit[m][1] += len(ext_defs)
                ctx_chars[m].append(sum(len(x.code) for x in ctx))

        # noise: alerts per KLOC on real, presumed-clean library code
        t = time.perf_counter()
        rx = sum(len(regex_baseline(texts[f], str(f.relative_to(corpus)))) for f in files)
        rx_s = time.perf_counter() - t
        hsample = random.sample(files, min(300, len(files)))
        t = time.perf_counter()
        hx, hloc = 0, 0
        for f in hsample:
            rel = str(f.relative_to(corpus))
            ctx = ix.get_context_for_target(texts[f][:4000], [rel], EngineMode.CLOUD_FAST)
            hx += len(heuristic_logic_scan(texts[f], rel, ctx)); hloc += texts[f].count("\n") + 1
        h_s = time.perf_counter() - t

        row = {
            "tier": tier, "packages": list(pkgs_so_far), "files": len(files), "loc": loc, "mb": round(mb, 2),
            "chunks": st.chunks, "symbols": st.symbols, "index_kb": round(index_kb),
            "cold_index_s": round(cold, 2), "files_per_s": round(len(files) / cold), "kloc_per_s": round(loc / 1000 / cold, 1),
            "warm_reindex_s": round(warm, 3), "warm_reused": st2.files_reused,
            "incremental_1file_s": round(incr, 3), "incremental_rechunked": st3.files_indexed,
            "retrieval_ms_p50_cloud": round(statistics.median(lat["cloud"]), 1), "retrieval_ms_p95_cloud": round(pctl(lat["cloud"], .95), 1),
            "retrieval_ms_p50_local": round(statistics.median(lat["local"]), 1), "retrieval_ms_p95_local": round(pctl(lat["local"], .95), 1),
            "xfile_def_recall_cloud": round(hit["cloud"][0] / max(1, hit["cloud"][1]), 3),
            "xfile_def_recall_local": round(hit["local"][0] / max(1, hit["local"][1]), 3),
            "xfile_defs_checked": hit["cloud"][1], "targets_sampled": len(sample),
            "ctx_tokens_cloud_median": round(statistics.median(ctx_chars["cloud"]) / 4),
            "ctx_tokens_local_median": round(statistics.median(ctx_chars["local"]) / 4),
            "repo_tokens": round(mb * 1e6 / 4),
            "regex_mb_per_s": round(mb / rx_s, 1), "regex_alerts": rx, "regex_alerts_per_kloc": round(rx / (loc / 1000), 3),
            "heur_files": len(hsample), "heur_alerts": hx, "heur_alerts_per_kloc": round(hx / (hloc / 1000), 3),
            "heur_ms_per_file": round(h_s / len(hsample) * 1000, 1),
        }
        row["prompt_reduction_cloud"] = round(1 - row["ctx_tokens_cloud_median"] / row["repo_tokens"], 5)
        rows.append(row)
        print(json.dumps(row), flush=True)
    shutil.rmtree(work, ignore_errors=True)

    out = HERE / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "scale.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    md = ["| Tier | Real corpus | Files | Lines | Chunks / symbols | Cold index | Throughput | No-change re-index | 1-file incremental | Retrieval p50 / p95 | Cross-file callee recall (cloud / local budget) | Context vs whole repo | Regex alerts /KLOC | Heuristic alerts /KLOC |",
          "| :-: | :--- | --: | --: | --: | --: | --: | --: | --: | --: | :-: | :-: | :-: | :-: |"]
    for r in rows:
        md.append(f"| {r['tier']} | {', '.join(r['packages'])} | {r['files']:,} | {r['loc']:,} | {r['chunks']:,} / {r['symbols']:,} | "
                  f"{r['cold_index_s']} s | {r['kloc_per_s']} KLOC/s | {r['warm_reindex_s']} s | {r['incremental_1file_s']} s | "
                  f"{r['retrieval_ms_p50_cloud']} / {r['retrieval_ms_p95_cloud']} ms | {100 * r['xfile_def_recall_cloud']:.0f}% / {100 * r['xfile_def_recall_local']:.0f}% | "
                  f"~{r['ctx_tokens_cloud_median']:,} vs ~{r['repo_tokens']:,} tokens (−{100 * r['prompt_reduction_cloud']:.2f}%) | "
                  f"{r['regex_alerts_per_kloc']} | {r['heur_alerts_per_kloc']} |")
    (out / "scale.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main())
