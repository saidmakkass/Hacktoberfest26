# BarakaGate benchmarks

| | Set | Purpose |
|---|---|---|
| 1 | `evaluate_benchmark.py` on `samples/` | In-distribution smoke test; these are the demo fixtures the offline detectors were built alongside. |
| 2 | `benchmarks/realworld/`, scored by `run_realworld.py` | **Held-out** proof of concept. Shows what generalizes beyond the demo. |

## Held-out protocol (set 2)

1. **Fixtures are realistic and natural.** There are no `# BUG` hint comments, and the code shapes deliberately differ from `samples/`: Flask with `%`-formatting, TypeScript/Prisma, cross-module ML pipelines, Slurm scripts, Arabic and French support tickets, and notebook output cells.
2. **Ground truth was frozen first.** `benchmarks/realworld/labels.json` and all fixtures were committed in `8e0758d` *before* any engine was run on them. The BarakaGate detectors and prompts have not been modified based on these results; `git log -- barakagate/` shows this.
3. **Labels point at text, not line numbers.** Each issue is identified by a unique `anchor` substring, which the runner resolves to a line, so labels can't drift silently. `until` extends a label to a range, and `alt` accepts an equivalent location in another file (e.g. the ML leakage can be reported at the call site or inside the helper).
4. **Matching is one-to-one.** A finding can satisfy at most one label. It must sit on the labelled lines (±2 for code, ±1 for notebooks, exact for CSV/JSON records) and agree on class (leak vs. bug) or name the issue kind.
5. **Penalties.**
   - **Traps:** 19 lines that look dangerous but are correct. Any finding on one counts as a false positive.
   - **Clean files:** 6 files plus 1 image where every finding is a false positive.
   - **Strict precision:** also counts *unlabeled extras* (findings that match nothing). They're listed in the report so a human can audit them.
6. **Images are scored by pixel overlap.** Regions are matched by IoU ≥ 0.2 against the exact `textbbox` of the drawn text (`screenshots/_truth.json`). That file is deliberately *not* named like the scanner's offline `*.boxes.json` cache, so only real vision can score.
7. **Live runs are isolated.**
   - Each LLM engine gets a fresh router with its own empty cache and `offline_safe=False`, so no demo-cache answers are reused.
   - A scan that falls back is retried twice with a pause. Any remaining fallback is reported per engine as "scans answered by the model".

## Run

```bash
python3 benchmarks/realworld/make_screenshots.py                       # (re)generate images + truth
python3 benchmarks/run_realworld.py --engines regex,offline            # instant
python3 benchmarks/run_realworld.py --engines cloud_fast,cloud_deep    # live Gemma 4 (GEMINI_API_KEY)
python3 benchmarks/run_realworld.py --engines local_edge               # needs `ollama pull gemma4:e4b`
python3 benchmarks/run_realworld.py --report                           # merge results/raw/*.json → report
```

Outputs: `benchmarks/results/raw/<engine>.json` (every finding), `benchmarks/results/realworld.md` / `.json` (scores), and the README section between the `REALWORLD_BENCH` markers.
