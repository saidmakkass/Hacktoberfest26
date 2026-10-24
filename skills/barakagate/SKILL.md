---
name: barakagate
description: >-
  Pre-flight security, privacy and cross-file logical bug gate powered by Gemma 4. Use it BEFORE
  committing or pushing code, BEFORE pasting prompts, stack traces or logs into a cloud AI, and
  BEFORE sharing screenshots or Jupyter notebooks. Catches hardcoded secrets (JWT, AWS, DB URIs,
  CMI/Stripe live keys), Moroccan PII under Law 09-08 (CIN, 24-digit RIB, MA IBAN, +212 phones,
  Darija/French/Arabic customer text), student CNE/Massar IDs, internal *.um6p.ma hosts, and
  cross-file logic bugs (float MAD currency rounding, wallet race conditions, unsigned payment
  webhooks, ML train/test leakage, SQL injection, off-by-one) - then proposes ready-to-apply fixes.
license: MIT
compatibility: Python 3.10+, git. Optional GEMINI_API_KEY (cloud Gemma 4) and/or Ollama with gemma4:e4b (local).
metadata:
  version: "1.0"
---

# BarakaGate

BarakaGate indexes the repository (AST chunks + symbol graph + BM25), pulls the cross-file
definitions a change depends on, and asks Gemma 4 to find **leaks/PII** and **logical bugs**. A
deterministic regex baseline and an offline heuristic engine always run, so the gate works with no
network at all.

Install once: `pip install -e .` (provides the `barakagate` command; `python -m barakagate.cli` also works).

## When to run it

| Situation | Command |
| :--- | :--- |
| About to commit | `barakagate staged` (or install the hook: `barakagate install-hook`) |
| Reviewing / editing specific files | `barakagate scan path/to/file.py other/dir --json` |
| About to paste a prompt, log or stack trace into a cloud LLM | `barakagate sanitize - < prompt.txt` |
| Sharing a screenshot or notebook image | `barakagate image shot.png --apply --style solid_mask` |
| No network / air-gapped | add `--offline` (regex + heuristics) or `--mode local_edge` (Ollama gemma4:e4b) |

Engines (`--mode`): `cloud_fast` (gemma-4-26b-a4b-it, default), `cloud_deep` (gemma-4-31b-it),
`local_edge` (gemma4:e4b via Ollama, nothing leaves the machine), `hybrid_smart` (local redaction,
then a cloud audit of the sanitized code). Presets (`--preset`): `all`, `fintech_morocco`,
`research_lab`, `general_devsecops`. Policy lives in `.barakagate.yaml`.

## Interpreting results

Prefer `--json`; it prints a `ScanResult`:

- `verdict`: `BLOCK` (any CRITICAL/HIGH finding, exit code 1), `WARN` (MEDIUM), `PASS` (exit 0).
  **Never commit, push or send content on BLOCK.** On WARN, fix or tell the user why it is acceptable.
- `findings[]`: `category` (`security_leak` | `privacy_pii` | `logical_bug`), `severity`,
  `file_path:line_start`, `reason`, `cross_file_context_used` (the indexed symbol that proves the
  issue, e.g. `models.py:MoroccanCustomer`), `offending_snippet`, `replacement_snippet`,
  `recommended_action`, and `caught_by_regex_baseline` (false = only Gemma 4 found it).

## Applying fixes

- `barakagate scan FILES --yes` applies every `recommended_action`; `--fix` asks per finding.
  - `synthetic_twin`: swaps real PII for format-valid fakes (`ZZ123456` CIN, RIB with bank code
    `999` and a valid key, `+2126000000NN`, `SYNTH_*` secrets).
  - `env_extract`: replaces the literal with `os.getenv("NAME", "")` / `process.env.NAME`, adds
    `import os` if needed and appends `NAME=value` to `.env` (never duplicated). Make sure `.env` is
    git-ignored and tell the user to rotate any secret that was already pushed.
  - `code_patch`: applies the proposed bug fix; review the diff and run the tests afterwards.
  - Backups of every patched file go to `.barakagate/backups/`.
- Keep a finding only if it is a genuine false positive; add the value to `allowlist` in
  `.barakagate.yaml` rather than ignoring it silently.
- Re-run the scan after fixing until the verdict is PASS (or WARN with a justification).

## Safe-to-Prompt firewall

`barakagate sanitize FILE --json` returns `{"sanitized": ..., "vault": {...}}`. Send only
`sanitized` to the cloud model; tokens look like `[CIN_TOKEN_1]`, `[RIB_TOKEN_1]`,
`[CNE_TOKEN_1]`, `[PHONE_TOKEN_1]`, `[SECRET_KEY_1]`, `[URL_TOKEN_1]`. Keep the vault local and
restore the answer with `barakagate.redactor.rehydrate(answer, vault)`. Add `--local-llm` to also let
on-device gemma4:e4b tokenize names, addresses and Darija PII.

## Other commands

`barakagate index [--force]` (refresh `.barakagate/index.json`), `barakagate benchmark [--offline]`
(regex vs Gemma 4 matrix), `barakagate serve` (BarakaGate Studio web UI on http://127.0.0.1:8000).
