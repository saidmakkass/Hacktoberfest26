# Plutonium — Held-out Real-World Benchmark

**Held-out set:** 4 mini-projects (Python/Flask, TypeScript/Prisma, ML research, clean controls) · 27 files + 3 screenshots · **30 labelled issues + 5 image regions**, **19 false-positive traps**, 6 fully-clean files and 1 clean image. Ground truth was committed before any engine ran on it (`benchmarks/realworld/labels.json`).

| Engine | Leaks/PII | Logic bugs | Beyond-regex edge cases | Cross-file bugs | Screenshot regions (IoU≥0.2) | Recall | Strict precision | Traps fired | FP on clean files/image | Avg s/file |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| Regex baseline (Gitleaks-style) | 9/17 (53%) | 0/13 (0%) | 0/21 (0%) | 0/6 (0%) | 0/5 (0%) | **26%** | 64% | 2/19 | 3 / 0 | 0.0 |
| Plutonium offline heuristics (no LLM) | 9/17 (53%) | 3/13 (23%) | 3/21 (14%) | 1/6 (17%) | 0/5 (0%) | **34%** | 67% | 2/19 | 3 / 0 | 0.0 |
| Plutonium + Gemma 4 26B MoE | 17/17 (100%) | 12/13 (92%) | 20/21 (95%) | 5/6 (83%) | 4/5 (80%) | **94%** | 69% | 3/19 | 4 / 0 | 33.6 |

**Statistical confidence** (n = 35 labelled items; Wilson 95% CI on recall; exact McNemar test on paired per-item outcomes vs. the regex baseline):

| Engine | Caught | Recall [95% CI] | Only this engine caught / only regex caught | McNemar p vs regex |
| :--- | :-: | :-: | :-: | :-: |
| Regex baseline (Gitleaks-style) | 9/35 | 26% [14–42%] | — | — |
| Plutonium offline heuristics (no LLM) | 12/35 | 34% [21–51%] | 3 / 0 | 0.250 |
| Plutonium + Gemma 4 26B MoE | 33/35 | 94% [81–98%] | 24 / 0 | 1.2e-07 |

<details><summary><b>Per-issue results (edge-case by edge-case)</b></summary>

| ID | Edge case | Type | Regex baseline | Plutonium offline heuristics | Gemma 4 26B MoE |
| :-: | :--- | :-: | :-: | :-: | :-: |
| S1 | Stripe live secret key hardcoded in settings | leak | ✅ | ✅ | ✅ |
| S2 | MySQL URI with inline password to an internal host | leak | ✅ | ✅ | ✅ |
| S3 | Float MAD total via `* (1 + VAT_RATE)` with the rate defined in another file and no round() call | bug | ❌ | ❌ | ✅ 🔗 |
| S4 | Refund check-then-act race across an `await` (double refund under concurrency); no `balance` naming | bug | ❌ | ❌ | ✅ |
| S5 | `vars(order.buyer)` logged; PII fields (national_id, iban, phone) only visible in models.py | leak | ❌ | ❌ | ✅ 🔗 |
| S6 | Admin state-mutating route missing @login_required used by every sibling route | bug | ❌ | ✅ | ✅ |
| S7 | Payzone notify endpoint marks orders paid without calling the existing verify_signature(); name has no 'webhook'/'callback' | bug | ❌ | ❌ | ✅ 🔗 |
| S8 | SQL injection via %-formatting (not an f-string) | bug | ❌ | ✅ | ✅ |
| S9 | Real-looking CIN inside a JSON test fixture | leak | ✅ | ✅ | ✅ |
| S10 | Moroccan IBAN printed in 4-digit groups | leak | ✅ | ✅ | ✅ |
| S11 | Phone with irregular spacing (`+212 6 61 23 45 67`) | leak | ❌ | ❌ | ✅ |
| S12 | CIN embedded in an Arabic-script Darija WhatsApp ticket | leak | ✅ | ✅ | ✅ |
| S13 | Dash-formatted phone inside Arabic text | leak | ✅ | ✅ | ✅ |
| S14 | 24-digit RIB printed in 4-digit groups (not the 3-3-16-2 layout regexes expect) | leak | ❌ | ❌ | ✅ |
| S15 | French free-text full name + home address (contextual PII, no fixed format) | leak | ❌ | ❌ | ✅ |
| T1 | CMI live key split across string concatenation to dodge regexes | leak | ❌ | ❌ | ✅ |
| T2 | OpenAI project key; no policy regex exists for this provider | leak | ❌ | ❌ | ✅ |
| T3 | TypeScript/Prisma read-check-write lost update (double spend) across awaits | bug | ❌ | ❌ | ✅ |
| T4 | JS number math for MAD + toFixed rounding | bug | ❌ | ❌ | ✅ |
| T5 | HMAC verified but compared with `===` (timing attack); a correct V2 sits right below | bug | ❌ | ❌ | ✅ |
| T6 | SQL injection through a TS template literal in $queryRawUnsafe | bug | ❌ | ❌ | ✅ |
| T7 | TS loop bound `<= length` (extra empty page) | bug | ❌ | ❌ | ✅ |
| M1 | Imputer+scaler fitted on all rows inside a helper in another module, split happens later in train.py | bug | ❌ | ❌ | ✅ 🔗 |
| M2 | Partial seeding: split is seeded, but the numpy permutation and torch init are not | bug | ❌ | ✅ 🔗 | ✅ 🔗 |
| M3 | Mean includes the -1.0 NA sentinel injected by fillna() in data.py | bug | ❌ | ❌ | ❌ |
| M4 | Student CNE + name + GPA in a CSV | leak | ✅ | ✅ | ✅ |
| M5 | Student CNE next to a counseling (health) note | leak | ✅ | ✅ | ✅ |
| M6 | Unquoted `export KEY=...` in a Slurm script (generic regex needs quotes) | leak | ❌ | ❌ | ✅ |
| M7 | Internal UM6P HPC hostname | leak | ✅ | ✅ | ✅ |
| M8 | Hugging Face token printed in a saved notebook OUTPUT cell (`!env | grep token`) | leak | ❌ | ❌ | ✅ |
| IMG1 | `terminal_env.png` — openai_api_key region | leak | ❌ | ❌ | ✅ 0.69 |
| IMG2 | `terminal_env.png` — stripe_secret_key region | leak | ❌ | ❌ | ✅ 0.76 |
| IMG3 | `cin_card.png` — name region | leak | ❌ | ❌ | ✅ 0.30 |
| IMG4 | `cin_card.png` — name region | leak | ❌ | ❌ | ❌ |
| IMG5 | `cin_card.png` — cin region | leak | ❌ | ❌ | ✅ 0.74 |

✅ caught · ❌ missed · 🔗 finding cited the cross-file symbol that proves it · image cells show IoU with the true text box.

</details>

<details><summary>Regex baseline (Gitleaks-style): 5 false positives, 0 unlabeled extra findings</summary>

- ❗ TRAP souk_shop/data/catalog.json:2 (product SKU shaped like a CIN) ← Moroccan CIN (Carte Nationale d'Identite)
- ❗ TRAP souk_shop/data/catalog.json:3 (product SKU shaped like a CIN) ← Moroccan CIN (Carte Nationale d'Identite)
- ❗ CLEAN clean_controls/.env.example:1 ← CMI / Payzone / Stripe live merchant key
- ❗ CLEAN clean_controls/.env.example:2 ← Database URI with inline password
- ❗ CLEAN clean_controls/build_info.py:5 ← Moroccan CIN (Carte Nationale d'Identite)

</details>

<details><summary>Plutonium offline heuristics (no LLM): 5 false positives, 1 unlabeled extra findings</summary>

- ❗ TRAP souk_shop/data/catalog.json:2 (product SKU shaped like a CIN) ← Moroccan CIN (Carte Nationale d'Identite)
- ❗ TRAP souk_shop/data/catalog.json:3 (product SKU shaped like a CIN) ← Moroccan CIN (Carte Nationale d'Identite)
- ❗ CLEAN clean_controls/.env.example:1 ← CMI / Payzone / Stripe live merchant key
- ❗ CLEAN clean_controls/.env.example:2 ← Database URI with inline password
- ❗ CLEAN clean_controls/build_info.py:5 ← Moroccan CIN (Carte Nationale d'Identite)
- ❔ souk_shop/support/tickets.csv:2 — Darija / Arabic customer-support note with card & bank details

</details>

<details><summary>Plutonium + Gemma 4 26B MoE: 7 false positives, 8 unlabeled extra findings</summary>

- ❗ TRAP souk_shop/config.py:7 (public example DSN) ← Hardcoded Sentry DSN
- ❗ TRAP souk_shop/data/catalog.json:2 (product SKU shaped like a CIN) ← Exposure of Moroccan CIN in SKU
- ❗ TRAP souk_shop/data/catalog.json:3 (product SKU shaped like a CIN) ← Exposure of Moroccan CIN in SKU
- ❗ CLEAN clean_controls/.env.example:1 ← Live Stripe Secret Key Exposed
- ❗ CLEAN clean_controls/.env.example:2 ← Database URI with Inline Password
- ❗ CLEAN clean_controls/build_info.py:5 ← Moroccan CIN (Carte Nationale d'Identite)
- ❗ CLEAN clean_controls/queries.py:9 ← Incorrect SQL placeholder for sqlite3
- ❔ oasis_ml_lab/features.py:6 — ML Train/Test Leakage via Pre-split Transformation
- ❔ oasis_ml_lab/students.csv:3 — Exposure of Sensitive Counseling Data
- ❔ souk_shop/config.py:8 — Floating Point VAT Rate
- ❔ souk_shop/models.py:19 — Use of float for currency amounts
- ❔ souk_shop/payments.py:31 — Unverified Payment Webhook Payload
- ❔ souk_shop/routes.py:8 — PII leakage via object serialization in logs
- ❔ souk_shop/routes.py:22 — Improper use of float for currency amounts
- ❔ screenshots/cin_card.png box — Date and Place of Birth

</details>

**Run notes.** Plutonium + Gemma 4 26B MoE: 30/30 scans answered by the model (engines seen: gemini:gemma-4-26b-a4b-it); run 2026-10-24 14:40:09.

**How to read this.** *Strict precision* counts every finding that is not one of the labelled issues as a false positive, including "unlabeled extras" a reviewer might still consider valid (they're listed above for audit). *Traps* are lines that look dangerous but are correct (env-read secrets, `compare_digest`, parameterized `%s`, clamped discounts, CIN-shaped SKUs, `.env.example` placeholders, seeded RNGs, masked sentinels).

Reproduce: `python3 benchmarks/run_realworld.py --engines regex,offline,cloud_fast`.
