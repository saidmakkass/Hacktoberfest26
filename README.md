# Plutonium

**An open-weight pre-flight gate that stops secrets, multilingual PII and cross-file logic bugs before they leave a developer's laptop. Powered by Gemma 4.**

Hacktoberfest26 Rabat Hack Day | Case 01: Best Open-Source AI Project | Case 02: Best Use of Gemma 4

MIT license | Python 3.10+ | Models: `gemma-4-26b-a4b-it`, `gemma-4-31b-it`, `gemma4:e4b` (Ollama) | Interfaces: pre-commit hook, CLI, Web Studio, Agent Skill, CI

---

## Results at a glance

We compared Plutonium with a classic pattern-matching scanner (like Gitleaks) on a separate test set we never tuned against. Every number comes from a script in this repo.

| Metric | Plutonium + Gemma 4 | Classic scanner |
|---|---|---|
| Issues caught | **33 / 35 (94%)** | 9 / 35 (26%) |
| Logic and security bugs | **12 / 13** | 0 / 13 |
| Tricky cases built to fool pattern matching | **20 / 21** | 0 / 21 |
| Bugs that need another file to prove | **5 / 6** | 0 / 6 |
| Secrets found in screenshots | **4 / 5** | 0 / 5 |
| Lines of real open-source code indexed | **597,822 in 5.3 s** | n/a |
| Prompt size vs. sending the whole repo | **99.76% smaller** | n/a |
| Raw personal data sent to the cloud (`hybrid_smart`) | **0 / 4** | n/a |
| End-to-end checks passing | **19 / 19** | n/a |

Plutonium caught everything the classic scanner caught, plus 24 more issues.

## 1. The problem

Developers leak sensitive data in three ways, and most tools only catch the first.

- **Secrets in code.** 23.7 million new hardcoded secrets reached public GitHub in 2024, up 25% in a year ([GitGuardian 2025](https://blog.gitguardian.com/the-state-of-secrets-sprawl-2025/)).
- **Personal data in logs, fixtures and tickets.** In Morocco, Law 09-08 allows CNDP fines up to MAD 300,000 and 6 months to 2 years in prison ([CMS guide](https://cms.law/en/int/expert-guides/cms-expert-guide-to-data-protection-and-cyber-security-laws/morocco)).
- **Real data pasted into cloud AI.** A stack trace with a customer record leaves the machine before any review sees it.

Classic scanners read one line at a time. They miss:

- a checkout file that logs a customer object whose class, in another file, holds a CIN and a RIB;
- a payment webhook that marks orders paid without calling the signature check;
- a CIN inside an Arabic-script support ticket, or an API key in a screenshot.

**Who it is for:** Moroccan fintech and e-commerce teams, university and research labs, and any team that commits code or uses cloud AI.

## 2. What Plutonium does

| Capability | What it covers |
|---|---|
| Secrets and multilingual PII | CIN, 24-digit RIB, MA IBAN, +212 phones, CNE/Massar, CMI/Stripe/OpenAI keys, JWT/AWS, internal hosts, Darija/French/Arabic text |
| Cross-file logic bugs | Float currency, double-spend races, missing webhook HMAC, SQL injection, off-by-one, missing auth, ML train/test leakage, missing seeds |
| Screenshots and notebook images | Gemma 4 vision finds keys and IDs, then blurs or masks them |
| Safe-to-Prompt firewall | Replaces real data with tokens locally, asks cloud Gemma 4, restores the values locally |
| Human-in-the-loop fixes | Fake-but-valid test data, move secret to `.env`, apply bug patch, mask, or keep |
| Gates everywhere | Pre-commit hook, CLI, GitHub Actions, Agent Skill, Web Studio, all using one `.plutonium.yaml` policy |

## 3. How it works

1. **Collect** a git diff, files, notebooks, a screenshot or a prompt.
2. **Index** the repository with a pure-Python symbol graph and search index.
3. **Retrieve** the definitions the changed code uses, even from other files.
4. **Analyze** with Gemma 4, plus fast rule-based checks.
5. **Decide** PASS, WARN or BLOCK, with a fix proposed for each finding.

### Four engine modes

| Mode | Model | Runs on | Why |
|---|---|---|---|
| `cloud_fast` (default) | `gemma-4-26b-a4b-it` | Gemini API | Fast and reliable: answered 30 / 30 live scans |
| `cloud_deep` | `gemma-4-31b-it` | Gemini API | Deepest cross-file reasoning |
| `local_edge` | `gemma4:e4b` | Ollama on the laptop | Fully offline, nothing leaves the machine |
| `hybrid_smart` | `e4b` then `31b` | Local, then cloud | Remove personal data locally, then audit in the cloud |

If a model is down, Plutonium falls back automatically (other cloud model → Ollama → cache → offline rules) and always shows which engine answered.

## 4. Accuracy

**Test set:** 4 mini-projects (Flask shop, TypeScript wallet, ML lab, one clean project), 27 files, 3 screenshots, 35 labelled issues and 19 traps that look dangerous but are safe.

**Fair scoring:** labels were committed before any engine ran (commit `8e0758d`), and nothing was tuned against this set.

| Engine | Leaks / PII | Logic bugs | Tricky cases | Cross-file | Screenshots | Recall |
|---|---|---|---|---|---|---|
| Classic scanner | 9 / 17 | 0 / 13 | 0 / 21 | 0 / 6 | 0 / 5 | 26% |
| Plutonium offline (no LLM) | 9 / 17 | 3 / 13 | 3 / 21 | 1 / 6 | 0 / 5 | 34% |
| Plutonium + Gemma 4 26B | **17 / 17** | **12 / 13** | **20 / 21** | **5 / 6** | **4 / 5** | **94%** |

- The difference with the classic scanner is statistically significant (p ≈ 0.0000001).
- Gemma 4 missed 2 items: one averaging bug and one name region on an ID card.
- Precision is 69%. Most extra alerts come from the rule-based layer, not from Gemma.

Full details: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## 5. Scale

Tested on 11 real open-source libraries, with no LLM calls:

- **597,822 lines indexed in 5.3 s** (over 100,000 lines per second).
- **Search under 100 ms**, even at 600k lines.
- **Prompt stays at about 12,000 tokens** instead of 5.2 million for the whole repo, while keeping 82% of the cross-file functions the code calls.

## 6. Privacy

- In `hybrid_smart` mode, **0 of 4** real values (CIN, RIB, phone, CMI key) reached the cloud in a live test.
- The server **refuses** any prompt that still contains a real value.
- `local_edge` only talks to `localhost:11434`.

## 7. Limitations

- The test set is small (35 items) and we built it ourselves.
- The local `gemma4:e4b` and 31B models are not benchmarked yet.
- Gemma 4 26B takes about 34 s per file through the API: fine for commits and CI, slow for a whole monorepo.

## 8. Roadmap

1. Let Gemma 4 remove false alarms from the rule-based layer.
2. A bigger test set with real, anonymized commits.
3. Benchmark local and hybrid modes on laptops; fine-tune a small model for Darija and Arabic PII.
4. A GitHub App with shared policy packs for banks, universities and hospitals.

## 9. Quick start

```bash
git clone https://github.com/saidmakkass/Hacktoberfest26 && cd Hacktoberfest26
pip install -e .
echo "GEMINI_API_KEY=your_key" > .env   # optional: everything also works offline
# optional, fully local: ollama pull gemma4:e4b

plutonium serve                        # Studio at http://127.0.0.1:8000
plutonium scan samples/fintech_morocco/checkout.py --root samples/fintech_morocco -p fintech_morocco
plutonium image samples/screenshots/devtools_leak.png --apply
echo "CIN BE847291 RIB 230780123456789012345678" | plutonium sanitize -
plutonium install-hook                 # blocks commits with CRITICAL or HIGH findings
```

Reproduce the numbers:

```bash
python3 -m pytest -q
python3 scripts/verify_plan.py --live
python3 benchmarks/run_realworld.py --engines regex,offline,cloud_fast
python3 benchmarks/scale_bench.py
python3 benchmarks/firewall_bench.py
```

## 10. Interfaces and policy

**Plutonium Studio (4 tabs)**

1. Code inspector: findings, cross-file context, and one fix decision per finding.
2. Image sanitizer: Gemma 4 boxes on screenshots, click to blur or keep.
3. Safe-to-Prompt firewall: sanitize locally, ask the cloud, restore locally.
4. Policy and benchmark: edit `.plutonium.yaml` and run the benchmark.

**Policy as code:** `.plutonium.yaml` has three packs you can combine: General DevSecOps, Moroccan Fintech (Law 09-08), and University & Research Lab. Rules can be written in plain English.

**Agent Skill and CI:** `skills/plutonium/SKILL.md` for coding agents, `.github/workflows/plutonium.yml` as a PR gate, and `plutonium install-hook` for a local pre-commit gate.

## 11. Repository layout

```
plutonium/
  models.py          shared data contract
  config.py          .plutonium.yaml loader
  llm_router.py      Gemini API, Ollama, fallback chain
  indexer.py         code chunker, symbol graph, search
  scanner.py         rule checks + Gemma 4 analysis + verdict
  redactor.py        fixes, .env extraction, image blur, prompt vault
  cli.py             CLI and pre-commit hook
  server.py          FastAPI backend
  static/            Plutonium Studio
benchmarks/          test set and benchmark scripts
samples/             demo scenarios
```

## Team

- Khalil Raghib
- Said Makkass
- Ahmed Ait Elaaoud
- Omar Gourragui

## License

MIT. See [LICENSE](LICENSE). Gemma is provided under the [Gemma Terms of Use](https://ai.google.dev/gemma/terms).
