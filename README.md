# BarakaGate

**Stops secrets, personal data and cross-file bugs before they leave a developer's laptop. Powered by Gemma 4.**

Hacktoberfest26 Rabat Hack Day | Case 01: Best Open-Source AI Project | Case 02: Best Use of Gemma 4

MIT license | Python 3.10+ | `gemma-4-26b-a4b-it` · `gemma-4-31b-it` · `gemma4:e4b` (Ollama) | pre-commit hook · CLI · Web Studio · Agent Skill · CI

![BarakaGate Studio](docs/screenshots/studio_inspector.png)

---

## Results at a glance

We compared BarakaGate with a classic pattern-matching scanner (the kind Gitleaks uses) on a test set we never tuned against.

| What we measured | BarakaGate + Gemma 4 | Classic scanner |
|---|---|---|
| Problems caught overall | **33 / 35 (94%)** | 9 / 35 (26%) |
| Logic and security bugs | **12 / 13** | 0 / 13 |
| Tricky cases (split keys, Arabic text, odd formats) | **20 / 21** | 0 / 21 |
| Bugs that need a second file to prove | **5 / 6** | 0 / 6 |
| Secrets found inside screenshots | **4 / 5** | 0 / 5 |
| Real customer data sent to the cloud (hybrid mode) | **0 / 4** | n/a |
| Code indexed (11 real open-source libraries) | **598k lines in 5.3 s** | n/a |
| Prompt size vs. sending the whole repo | **99.76% smaller** | n/a |

Every problem the classic scanner caught, BarakaGate caught too. BarakaGate caught 24 more.

## The problem

- **Secrets keep leaking.** 23.7 million new hardcoded secrets hit public GitHub in 2024, up 25% in a year ([GitGuardian 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/)).
- **In Morocco, a leaked CIN or RIB is a legal risk.** Law 09-08 allows CNDP fines up to MAD 300,000 and prison terms of 6 months to 2 years ([CMS guide](https://cms.law/en/int/expert-guides/cms-expert-guide-to-data-protection-and-cyber-security-laws/morocco)).
- **Developers paste real data into AI chats.** A stack trace with a customer record leaves the machine before any review sees it.

Classic scanners look at one line at a time, so they miss things like:

- logging a `customer` object whose class, defined in another file, holds a CIN and a RIB;
- a payment webhook that marks orders as paid without checking the signature;
- a CIN inside an Arabic-script support ticket, or an API key visible in a screenshot.

**Built for:** Moroccan fintech and e-commerce (CMI, Payzone, RIB, CIN, Darija logs), university and research labs (CNE/Massar, HPC tokens, notebooks), and any team that commits code or uses cloud AI.

## What it does

- 🔴 **Finds secrets and personal data** in code, notebooks and logs: CIN, RIB, IBAN, +212 phones, CNE, API keys, internal URLs, and free text in Darija, French or Arabic.
- 🟣 **Finds logic bugs across files**: float money math, double-spend races, missing webhook checks, SQL injection, off-by-one, missing auth, ML train/test leakage.
- 🖼️ **Blurs secrets in screenshots**: Gemma 4 vision draws boxes around them, you choose what to blur.
- 🧪 **Safe-to-Prompt firewall**: replaces real data with tokens on your laptop, asks cloud Gemma 4, then puts the real values back locally.
- 🩹 **One-click fixes**: fake-but-valid test data, move secret to `.env`, apply bug patch, or keep as is. You decide per finding.
- 🚦 **Works where you work**: git pre-commit hook, CLI, GitHub Actions, Agent Skill for coding agents, and a web Studio.

## How it works

1. **Index** the repository (pure Python, no native dependencies).
2. **Pull the context** for the changed code: the definitions of the functions and classes it uses, even from other files.
3. **Analyze** with Gemma 4, plus fast rule-based checks.
4. **Decide**: PASS, WARN or BLOCK, with a proposed fix for each finding.

### Four engine modes

| Mode | Model | Runs on | Use it for |
|---|---|---|---|
| `cloud_fast` (default) | `gemma-4-26b-a4b-it` | Gemini API | Fast everyday scans |
| `cloud_deep` | `gemma-4-31b-it` | Gemini API | Hardest cross-file reasoning |
| `local_edge` | `gemma4:e4b` | Ollama on your laptop | Fully offline, nothing leaves the machine |
| `hybrid_smart` | `e4b` → `31b` | Laptop, then cloud | Remove personal data locally, then do the deep audit in the cloud |

If the cloud or Ollama is down, BarakaGate falls back automatically (other model → local → cache → offline rules) and always shows which engine answered.

## Screenshots

| Screenshot blur | Safe-to-Prompt firewall |
|---|---|
| ![Vision](docs/screenshots/studio_vision.png) | ![Firewall](docs/screenshots/studio_firewall.png) |

## Quick start

```bash
git clone https://github.com/saidmakkass/Hacktoberfest26 && cd Hacktoberfest26
pip install -e .
echo "GEMINI_API_KEY=your_key" > .env   # optional: everything also works offline
# optional, fully local: ollama pull gemma4:e4b

barakagate serve                        # Studio at http://127.0.0.1:8000
barakagate scan samples/fintech_morocco/checkout.py --root samples/fintech_morocco -p fintech_morocco
barakagate image samples/screenshots/devtools_leak.png --apply
echo "CIN BE847291 RIB 230780123456789012345678" | barakagate sanitize -
barakagate install-hook                 # blocks commits with CRITICAL or HIGH findings
```

## How we tested it

- **Test set:** 4 small realistic projects (Flask shop, TypeScript wallet, ML lab, and one clean project), 27 files and 3 screenshots, 35 labelled problems and 19 traps that look dangerous but are fine.
- **Fair scoring:** labels were committed before any engine ran (commit `8e0758d`), and we never tuned against this set.
- **Result is not luck:** the gap between BarakaGate and the classic scanner is statistically significant (p ≈ 0.0000001).
- **Honest weak spots:** precision is 69% (some extra alerts, mostly from the rule-based layer). Gemma 4 26B takes about 34 s per file through the API. The local and 31B models were not benchmarked yet.

Reproduce every number:

```bash
python3 -m pytest -q                                          # unit tests
python3 scripts/verify_plan.py --live                         # 19 end-to-end checks
python3 benchmarks/run_realworld.py --engines regex,offline,cloud_fast
python3 benchmarks/scale_bench.py                             # 598k-line scale test
python3 benchmarks/firewall_bench.py                          # prompt firewall test
```

Full method and per-case results: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## Policy as code

`.barakagate.yaml` ships with three packs you can mix: **General DevSecOps**, **Moroccan Fintech (Law 09-08)** and **University & Research Lab**. Rules can be written in plain English; they go straight into Gemma 4's instructions.

## Roadmap

1. Let Gemma 4 veto false alarms from the rule-based layer.
2. A bigger test set with real, anonymized commits from partner labs.
3. Benchmark `gemma4:e4b` and hybrid mode on laptops; fine-tune a small model for Darija and Arabic PII.
4. A GitHub App with shared policy packs for banks, universities and hospitals.

## Repository layout

```
barakagate/       scanner, indexer, Gemma 4 router, redactor, CLI, server, Studio UI
benchmarks/       test set and benchmark scripts
samples/          demo scenarios: fintech_morocco, research_lab_um6p, general_devsecops, screenshots
skills/           Agent Skill (SKILL.md)
docs/             benchmarks, verification report, commit review, pitch
```

## License

MIT. See [LICENSE](LICENSE). Gemma is provided under the [Gemma Terms of Use](https://ai.google.dev/gemma/terms).
