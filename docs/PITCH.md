# BarakaGate: pitch cheat sheet

Every number here is reproducible from the repo (see README §7). Each one has a short answer ready for skeptical PhD questions.

## The 30-second story

1. **Problem.** 23.8M secrets were leaked on public GitHub in 2024, and 70% of those leaked in 2022 were still valid (GitGuardian 2025). In Morocco, leaking a CIN or RIB can cost up to MAD 300,000 under Law 09-08, and the CNDP started enforcing in 2025. Regex scanners only look at single lines. They can't see cross-file bugs, Darija text or screenshots.
2. **Solution.** A pre-flight gate: a pure-Python code index feeds Gemma 4 the exact cross-file definitions it needs, with vision for screenshots and an on-device PII firewall before any cloud call. It runs as a pre-commit hook, CLI, CI gate, Agent Skill and Web Studio.
3. **Proof.** On a held-out benchmark (labels frozen before any run):
   - Gemma 4 26B finds **94%** of issues; regex finds **26%** (p = 1.2×10⁻⁷).
   - **12 of 13** logic bugs, versus 0 for regex.
   - **5 of 6** cross-file bugs, each with the symbol that proves it.
   - **4 of 5** screenshot secrets localized, versus 0.

## Slide numbers

| Use on a slide | Number |
|---|---|
| Held-out recall: Gemma 4 vs. regex | **94% vs 26%** (95% CI 81–98 vs 14–42) |
| Paired significance | **24 vs 0** discordant issues, **p = 1.2×10⁻⁷** (exact McNemar) |
| Logic bugs | **12/13 vs 0/13** |
| Edge cases designed to beat regex | **20/21 vs 0/21** |
| Cross-file bugs | **5/6**, each citing the proving symbol |
| Screenshot secrets localized | **4/5**, median IoU **0.72** |
| Scale | **598k lines indexed in 5.3 s** (112k lines/s), pure Python |
| Retrieval | **29 ms p50 / 97 ms p95** |
| Prompt size | **−99.76%** vs. whole repo, keeping **82%** of cross-file callees |
| Noise on real code | **0.21 alerts / 1,000 lines** |
| Privacy | **0** raw PII values sent to the cloud in hybrid mode (live test) |
| Robustness | 5-step fallback; demo cache gives the **same BLOCK verdict** offline |
| Quality | **19/19** end-to-end spec checks (5 live), **104** tests |

## Likely questions and honest answers

- **"You wrote the test set yourselves."** Yes. To limit the bias, I froze the labels in git *before* any run (commit `0087dc8`) and never changed the detectors afterwards. The fixtures use code shapes different from the demo, there are 19 traps plus fully-clean files, and every false positive is published. The main result is a *paired* comparison on the same items, so fixture bias affects both engines equally.
- **"n = 35 is small."** Agreed; that's why I show Wilson confidence intervals. Even the lower bound for Gemma (81%) is far above the upper bound for regex (42%).
- **"What about precision?"** Strict precision is 69%. Of the non-matching findings, 5 are real issues I hadn't labelled (date of birth on the ID card, a counseling note, float money in other files), and most true false positives come from the regex layer, not Gemma. The next step is a Gemma veto on regex hits.
- **"Why not 31B by default?"** I measured it. During the runs the 31B endpoint answered itself on only 4 of 9 attempts, while 26B answered 30/30. 26B is the default; 31B is opt-in, with automatic fallback.
- **"Isn't sending code to the cloud the very leak you're preventing?"** Use `local_edge` (fully air-gapped, Ollama) or `hybrid_smart` (redact on-device first; we measured 0 raw values sent). The firewall also refuses any prompt that still contains a vault value.
- **"What did you not prove?"** The local `gemma4:e4b` engine wasn't benchmarked (no Ollama on the benchmark machine). The deterministic sanitizer alone strips 71% of raw values. Free-text names and addresses need the local model, and that combination is unmeasured.

## Live demo order (about 4 minutes)

1. Studio Tab 1 → **Load Moroccan Fintech Checkout PR** → show the retrieved `models.py:MoroccanCustomer` context, the Regex-vs-Gemma scoreboard and a cross-file proof card → **Preview Combined Patched File**.
2. Tab 2 → devtools screenshot → **Run Gemma 4 Vision Scan** → toggle a box → **Apply Redaction & Download PNG**.
3. Tab 3 → paste a Darija/French prompt with a CIN and RIB → **Sanitize** → **Ask Cloud Gemma 4** → values are restored locally.
4. Terminal: `git commit` with a CIN → the pre-commit hook blocks it.
5. Close on the held-out table and the p-value.

Run each scenario once before going on stage so the demo cache is warm. If the Wi-Fi drops, the same verdicts are served from the cache, labelled as such.
