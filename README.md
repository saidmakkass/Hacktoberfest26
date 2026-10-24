# BarakaGate

**An open-weight pre-flight gate that stops secrets, multilingual PII and cross-file logic bugs before they leave a developer's laptop. Powered by Gemma 4.**

Hacktoberfest26 Rabat Hack Day | Case 01: Best Open-Source AI Project | Case 02: Best Use of Gemma 4

MIT license | Python 3.10+ | Models: `gemma-4-26b-a4b-it`, `gemma-4-31b-it`, `gemma4:e4b` (Ollama) | Interfaces: pre-commit hook, CLI, Web Studio, Agent Skill, CI

---

## Results at a glance

Every number below comes from a script in this repository. The command to reproduce each one is listed in the section where it appears.

| Metric | BarakaGate + Gemma 4 | Regex baseline | Where |
|---|---|---|---|
| Issues caught on a held-out benchmark | 33 / 35 (94%) | 9 / 35 (26%) | Section 4 |
| Logic and security bugs found | 12 / 13 | 0 / 13 | Section 4 |
| Edge cases designed to evade regex | 20 / 21 | 0 / 21 | Section 4 |
| Cross-file bugs (need another file to prove) | 5 / 6 | 0 / 6 | Section 4 |
| Secrets located in screenshots | 4 / 5 regions (median IoU 0.72) | 0 / 5 | Section 4 |
| Statistical significance (exact McNemar test) | p = 1.2 x 10^-7 | n/a | Section 4 |
| Lines indexed from real open-source code | 597,822 lines in 5.3 s | n/a | Section 5 |
| Prompt size vs. sending the whole repo | 12,441 vs. 5,182,853 tokens (99.76% smaller) | n/a | Section 5 |
| Raw PII sent to the cloud in `hybrid_smart` mode | 0 / 4 values | n/a | Section 6 |
| End-to-end spec checks passing | 19 / 19 | n/a | Section 7 |

## 1. The problem

Developers leak sensitive data in three ways, and most tools only catch the first.

- **Secrets in code.** GitGuardian found 23,770,171 new hardcoded secrets in public GitHub commits in 2024, up 25% year over year. 70% of secrets leaked in 2022 were still valid. 35% of the private repositories they scanned contained plaintext secrets. ([GitGuardian, State of Secrets Sprawl 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/))
- **Personal data in logs, fixtures and tickets.** In Morocco, Law 09-08 lets the CNDP fine organizations up to MAD 300,000, and unlawful processing of sensitive data carries 6 months to 2 years in prison. ([CMS expert guide](https://cms.law/en/int/expert-guides/cms-expert-guide-to-data-protection-and-cyber-security-laws/morocco))
- **Pasting real data into cloud AI assistants.** A stack trace with a real customer record leaves the machine before any code review can see it.

Existing scanners read one line at a time. They cannot see that:

- a checkout file logs a customer object, and the class defined in another file holds a CIN and a RIB;
- a payment webhook marks orders as paid without calling the signature check that already exists in another module;
- a CIN is written inside an Arabic-script support ticket, or an API key is visible in a terminal screenshot.

On our held-out set, the regex baseline found 0 of 13 logic bugs and 0 of 21 edge cases. It also fired on CIN-shaped product SKUs and `.env.example` placeholders.

**Who it is for**

- Moroccan fintech and e-commerce teams (CMI, Payzone, RIB, CIN, Darija support logs)
- University and research labs (CNE/Massar, HPC tokens, notebooks)
- Any team that commits code or sends prompts to cloud AI

## 2. What BarakaGate does

| Capability | What it covers | How |
|---|---|---|
| Secrets and multilingual PII | CIN, 24-digit RIB, MA IBAN, +212 phones, CNE/Massar, CMI/Stripe/OpenAI keys, JWT/AWS, internal hosts, free text in Darija, French and Arabic | Regex baseline plus Gemma 4 contextual reasoning |
| Cross-file logic and security bugs | Float currency, double-spend races, missing or timing-unsafe webhook HMAC, SQL injection, off-by-one, missing auth, ML train/test leakage, missing seeds | Pure-Python code index feeds the exact cross-file definitions to Gemma 4 |
| Screenshots and notebook images | API keys, ID cards, tokens in images | Gemma 4 vision returns bounding boxes, then Pillow blurs or masks them |
| Safe-to-Prompt firewall | Strip PII on-device, ask cloud Gemma 4, restore values locally | Local token vault; the server refuses any prompt that still contains a vault value |
| Human-in-the-loop fixes | Synthetic replacement values, `.env` extraction, bug patches, masking, whitelist | All fixes apply in one pass and the patched file stays valid |
| Gates everywhere | Git pre-commit hook, CLI (exit code 1 on BLOCK), GitHub Actions PR gate, Agent Skill, Web Studio | One scanner and one `.barakagate.yaml` policy behind every gate |

## 3. How it works

Each scan runs through the same five stages.

1. **Collect.** Input is a git diff, files, notebooks, a screenshot or a prompt.
2. **Index.** A pure-Python indexer builds a symbol graph and a BM25 search index over the repository.
3. **Retrieve.** For the changed code, it packs the definitions of the functions it calls (1 hop) plus the top-ranked chunks into a small prompt. Policy packs from `.barakagate.yaml` are added.
4. **Analyze.** Three detectors run side by side: the regex baseline, 14 offline AST detectors, and Gemma 4.
5. **Merge.** Findings are deduplicated and turned into one verdict (PASS, WARN or BLOCK). The redactor then offers fixes.

### Four engine modes

| Mode | Model | Runs on | Why it exists |
|---|---|---|---|
| `cloud_fast` (default) | `gemma-4-26b-a4b-it` | Gemini API | Mixture-of-experts with about 3.8B active parameters. Answered 30 / 30 live scans in our held-out run. |
| `cloud_deep` | `gemma-4-31b-it` | Gemini API | Dense model for the hardest cross-file reasoning. The free-tier endpoint answered only 4 of 9 attempts, so the router fell back to 26B. That measurement is why 26B is the default. |
| `local_edge` | `gemma4:e4b` | Ollama on the laptop | Air-gapped. The only network address in its router chain is `localhost:11434` (asserted in tests). |
| `hybrid_smart` | `e4b` then `31b` | Local, then cloud | Redact on-device, audit the sanitized code in the cloud, restore findings locally. |

### Design decisions, each backed by a number

- **Pure-Python index, no native dependencies.** It indexes 112,500 lines per second, re-indexes by sha256 hash, and has nothing to compile on a laptop or in CI.
- **Symbol graph first, BM25 second.** On real libraries, the packed context contains 82% of the cross-file functions a change calls, using 0.24% of the repository's tokens.
- **Five-step fallback chain.** Requested model, then the other cloud model, then Ollama, then cached response, then the offline engine. Every result is labelled with the engine that actually answered, so a fallback is never presented as Gemma output.

## 4. Accuracy: held-out benchmark

We built a separate benchmark that the detectors and prompts were never written against.

**What is in it**

- 4 mini-projects: Flask e-commerce shop, TypeScript/Prisma wallet, ML research lab, and one project that is clean on purpose
- 27 files and 3 screenshots
- 30 labelled issues and 5 labelled image regions (35 items in total)
- 19 false-positive traps (for example `compare_digest`, env-read secrets, CIN-shaped SKUs, `.env.example` placeholders)
- 6 fully clean files and 1 clean image

**Protocol**

- Ground-truth labels were committed before any engine ran (commit `8e0758d`).
- Each finding can satisfy at most one label and must sit on the labelled line.
- Any finding that matches no label counts against precision (strict scoring).
- Screenshots are scored by pixel overlap (IoU 0.2 or higher) with the exact text box.
- No demo cache is used, and every fallback is reported.

Full details are in `docs/BENCHMARKS.md`.

### Results

| Engine | Leaks / PII | Logic bugs | Edge cases | Cross-file bugs | Screenshots | Recall | Strict precision |
|---|---|---|---|---|---|---|---|
| Regex baseline | 9 / 17 | 0 / 13 | 0 / 21 | 0 / 6 | 0 / 5 | 26% | 64% |
| BarakaGate offline heuristics (no LLM) | 9 / 17 | 3 / 13 | 3 / 21 | 1 / 6 | 0 / 5 | 34% | 67% |
| BarakaGate + Gemma 4 26B | 17 / 17 | 12 / 13 | 20 / 21 | 5 / 6 | 4 / 5 | 94% | 69% |

Edge cases overlap with the other columns, so the rows do not add up to the total.

### Statistical confidence

| Engine | Caught | Recall (95% CI) | Caught only by this engine / only by regex | McNemar p vs. regex |
|---|---|---|---|---|
| Regex baseline | 9 / 35 | 26% (14 to 42) | n/a | n/a |
| Offline heuristics | 12 / 35 | 34% (21 to 51) | 3 / 0 | 0.250 |
| Gemma 4 26B | 33 / 35 | 94% (81 to 98) | 24 / 0 | 1.2 x 10^-7 |

Gemma caught 24 issues the regex missed. The regex caught 0 issues that Gemma missed.

### What Gemma 4 missed

- 1 logic bug: a mean that includes a -1.0 sentinel injected by `fillna()` in another module.
- 1 image region: a second name region on the specimen ID card.

### Reading precision honestly

Strict precision for Gemma 4 is 69%. We audited the 15 non-matching findings by hand:

- **8 unlabeled extras.** 5 are real issues we had not labelled (a health note in a student CSV, a date of birth on an ID card, and float currency in 3 files). 3 are duplicates of caught issues reported at a second location.
- **7 false positives.** 5 come from the regex layer that BarakaGate merges in, not from Gemma's reasoning. 1 comes from a fixture error on our side (`%s` placeholders with `sqlite3` do fail at runtime).

Counting the 5 real extras as correct gives an author-adjudicated precision of 79% (38 / 48). That figure involves our judgment, so the strict 69% remains the headline number. We did not tune anything against the held-out set to improve it.

Reproduce: `python3 benchmarks/run_realworld.py --engines regex,offline,cloud_fast`

## 5. Scale: 598k lines of real open-source code

`python3 benchmarks/scale_bench.py` copies the installed source of 11 widely used libraries into three cumulative tiers. It measures indexing, re-indexing and retrieval, and checks 200 real functions to see whether the packed context includes the definitions they call. No LLM calls are made.

| Tier | Files | Lines | Cold index | Throughput | Retrieval p50 / p95 | Callee recall (cloud / local budget) | Prompt vs. whole repo |
|---|---|---|---|---|---|---|---|
| S | 97 | 28,011 | 0.18 s | 157.6 KLOC/s | 1.3 / 9.4 ms | 87% / 37% | 20,594 vs. 235,818 tokens (-91.27%) |
| M | 384 | 137,936 | 0.87 s | 159.3 KLOC/s | 5.1 / 21.9 ms | 93% / 39% | 20,026 vs. 1,213,144 tokens (-98.35%) |
| L | 1,567 | 597,822 | 5.31 s | 112.5 KLOC/s | 29.2 / 97.2 ms | 82% / 29% | 12,441 vs. 5,182,853 tokens (-99.76%) |

**What this shows**

- Indexing stays above 100,000 lines per second. Going from tier M to L, code grows 4.3x and indexing time grows 6x.
- Retrieval stays interactive: under 100 ms at p95 with 600k lines.
- Prompt size stays at 12,000 to 21,000 tokens while the repository grows 21x.
- Alert noise on presumed-clean production code is low: 0.21 alerts per 1,000 lines for the heuristics, against 0.74 for regex.

**Known weak spots**

- The local-model budget (3 chunks, 2,500 characters) keeps only 29% to 39% of cross-file callees. Deep cross-file audits should use the cloud or `hybrid_smart` mode.
- Re-indexing one changed file is only about 2.8x faster than a cold index at 600k lines (1.87 s vs. 5.31 s), because loading the 28 MB JSON index dominates. A sharded index is on the roadmap.

## 6. Privacy

| Measurement | Result | How it was measured |
|---|---|---|
| Raw values sent to the cloud in `hybrid_smart` (live run, fintech scenario) | 0 / 4 (CIN, RIB, phone, CMI key) | A spy records every prompt the router sends (`scripts/verify_plan.py --live`) |
| Prompt still containing a vault value | Rejected with HTTP 400 | Same script |
| Raw values removed by the deterministic on-device sanitizer, before any LLM | 12 / 17 (71%) | `python3 benchmarks/firewall_bench.py` |

The deterministic layer misses free-text names and addresses, provider keys with no rule, 4-digit-grouped RIBs and split keys. The local `gemma4:e4b` pass in hybrid mode is designed to cover those. Its contribution is not measured here, because Ollama was unavailable on the benchmark machine.

**Privacy rules enforced in code**

- `local_edge` never opens a network connection other than `localhost:11434`.
- `hybrid_smart` and the firewall send only tokenized text. The vault stays in local memory or the browser.
- The server refuses to forward any prompt that still contains a raw vault value.

## 7. Verification

`docs/VERIFICATION.md` is generated by `python3 scripts/verify_plan.py --live`. It runs 19 end-to-end checks, and all 19 pass.

- **Spec.** Every required path exists, the `models.py` contract matches, no deprecated SDK is used.
- **Router and indexer.** Fallback chain per mode, Ollama payload settings, indexer token budgets.
- **Offline behaviour.** Scans return BLOCK, CLI exit codes are correct, all fixes apply in one pass with valid output, image blur touches only the boxes, the pre-commit hook blocks a commit containing a CIN.
- **Live Gemma 4.** Fintech scan with the cross-file proof, 2 other scenarios, vision localizing 4 / 4 secrets in the demo screenshot, hybrid mode sending 0 raw PII, and the demo-cache fallback.

The unit test suite has 104 tests and runs in about 1.5 s.

## 8. Limitations

- **Small labelled set.** 35 items give wide confidence intervals (81% to 98% for Gemma). The paired comparison with regex is still highly significant (24 vs. 0 discordant items).
- **Author-built fixtures.** We wrote both the fixtures and the labels. We reduced the risk by freezing labels before any run, writing code with no hint comments, using code shapes different from the demo samples, including 19 traps and 6 clean files, and publishing every false positive for audit. We did not measure agreement between annotators.
- **Local and 31B engines not benchmarked.** There was no Ollama on the benchmark machine. The 31B run was stopped because the endpoint fell back to 26B on 5 of 9 calls, so we do not report a 31B row made mostly of 26B answers.
- **Latency.** Gemma 4 26B through the API averages 33.6 s per file. That works for pre-commit on a diff or a CI check, but is too slow to scan a whole monorepo file by file. The offline engine (73 ms per file) covers interactive use.
- **Regex layer limits precision.** Most remaining false positives come from regex rules we keep for transparency and recall.

## 9. Roadmap

1. LLM veto of regex hits, to remove the false positives the regex layer causes.
2. A larger labelled corpus (hundreds of issues, multiple annotators, anonymized real commits from partner labs) and SARIF output for GitHub code scanning.
3. A binary or sharded index, so re-indexing cost depends only on the number of changed files.
4. Benchmarks of `gemma4:e4b` and hybrid mode on laptops, and a fine-tuned small model for Darija and Arabic PII.
5. A GitHub App and organization-wide policy packs (banks, universities, hospitals) built on the same `.barakagate.yaml`.

## 10. Quick start

```bash
git clone <this repo> && cd barakagate
pip install -e .                        # requires setuptools>=64, or: pip install -r requirements.txt
echo "GEMINI_API_KEY=your_key" > .env   # optional: everything also works offline
# optional, fully local: ollama pull gemma4:e4b

barakagate serve                        # BarakaGate Studio at http://127.0.0.1:8000
barakagate scan samples/fintech_morocco/checkout.py --root samples/fintech_morocco -p fintech_morocco
barakagate scan samples/research_lab_um6p/train_pipeline.py --root samples/research_lab_um6p --offline
barakagate image samples/screenshots/devtools_leak.png --apply
echo "CIN BE847291 RIB 230780123456789012345678" | barakagate sanitize -
barakagate install-hook                 # pre-commit gate: blocks commits on CRITICAL or HIGH
```

**Reproduce every number in this README**

```bash
python3 -m pytest -q                                          # 104 tests
python3 scripts/verify_plan.py --live                         # 19 end-to-end spec checks
python3 benchmarks/run_realworld.py --engines regex,offline,cloud_fast
python3 benchmarks/scale_bench.py                             # 598k-line scalability run
python3 benchmarks/firewall_bench.py                          # sanitizer leak-through
python3 evaluate_benchmark.py                                 # demo-scenario smoke benchmark
```

## 11. Interfaces and policy

**BarakaGate Studio (4 tabs)**

1. Code Diff, Leak and Logic Bug Inspector: retrieved cross-file context, regex vs. Gemma scoreboard, reasoning trace, one decision per finding, patch preview and apply.
2. Screenshot and Notebook Image Sanitizer: Gemma 4 vision boxes on a canvas; click to toggle, drag to add, blur or mask, download.
3. Safe-to-Prompt Outbound Firewall: sanitize locally, ask cloud Gemma 4, restore values automatically.
4. Policy and Benchmark: edit `.barakagate.yaml` live and run the benchmark matrix.

**Policy as code (`.barakagate.yaml`)**

Three built-in packs can be toggled or combined. Together they hold 15 regex rules and 15 natural-language rules. The natural-language rules go straight into Gemma 4's system prompt, so teams add rules in plain English.

- **General DevSecOps:** AWS, JWT, PEM, database URIs, internal IPs, SQL injection, off-by-one, `None` dereference, missing auth.
- **Moroccan Fintech and E-Commerce (Law 09-08 / CNDP):** CIN, RIB, IBAN, +212 phones, Darija/French/Arabic PII, CMI/Payzone/Stripe keys, float currency, race conditions, webhook HMAC, promo bypass.
- **University and Research Lab:** CNE/Massar, internal HPC hosts and tokens, notebook output leaks, train/test leakage, sentinel values, missing seeds.

**Agent Skill and CI**

- `skills/barakagate/SKILL.md` follows the Agent Skills open standard, so coding agents run BarakaGate before committing or pasting context into cloud LLMs.
- `.github/workflows/barakagate.yml` is a PR gate that fails on BLOCK.
- `barakagate install-hook` installs a local git pre-commit hook.

## 12. Repository layout

About 7,000 lines of code: 14 offline detectors, 19 REST endpoints, 8 CLI commands, 4 engine modes.

```
barakagate/
  models.py          shared Pydantic contract
  config.py          .barakagate.yaml loader (plus .env)
  llm_router.py      Gemini API (26B/31B), Ollama e4b, fallback chain, demo cache
  indexer.py         AST/TS chunker, symbol graph, BM25, notebook image extraction
  scanner.py         regex baseline, 14 AST detectors, Gemma 4 analysis, merge and verdict
  redactor.py        synthetic replacements, .env extractor, patcher, image blur, prompt vault
  cli.py             Typer/Rich CLI and pre-commit hook
  server.py          FastAPI backend (19 endpoints)
  static/index.html  BarakaGate Studio
benchmarks/          held-out set, scalability and firewall benchmarks, results
samples/             demo scenarios: fintech_morocco, research_lab_um6p, general_devsecops, screenshots
scripts/verify_plan.py   19-check spec verification
```

## License

MIT. See [LICENSE](LICENSE). Gemma is provided under the [Gemma Terms of Use](https://ai.google.dev/gemma/terms).