# Commit review

Plutonium can pause a commit for a terminal or browser review. The browser uses
local assets and a temporary loopback server. Your proposed edits remain in the
session until approval; cancellation leaves the index and working files unchanged.

```sh
pip install -e .
plutonium install-hook
# Stage the intended files, then commit normally:
git commit -m "Your message"
```

The hook shows findings, explanations, and before/after suggestions. Choose
`a` to validate and approve proposals, `c` to cancel the commit, or `w` to open
browser review. You can also start a review with `plutonium review`.

In the browser, choose a file, edit its proposed text or draw image redactions,
then **Validate changes** and **Approve changes**. Permitted findings can be
explicitly dismissed. Enforced findings must be resolved. After approval, the
page says you can close the tab and the server shuts down. Git continues in the
original terminal; later hooks, signing, or commit-message editing can still stop
it. The browser never claims that a commit was created.

## Configuration

`.plutonium.yaml` retains its existing rules and adds a `review` section:

```yaml
review:
  dismissal:
    default: true
    severity:
      CRITICAL: false
      HIGH: false
    category: {}
    rule: {}
  # Optional: engine/preset override default_engine/default_preset.
  offline: false
  allow_fallback: false
  incomplete: block       # block or warn
  open_browser: true
  timeout_seconds: 1800
  max_file_bytes: 1000000
```

Dismissal precedence is rule ID, category, severity, then default. Explicit empty
maps and `false` are preserved. A personal configuration can allow dismissal with
`dismissal: {default: true}`. An organization can use `default: false`, or enforce
specific rule IDs. Both API and CLI honor the effective policy. Offline mode uses
only deterministic checks; unavailable image analysis is reported as incomplete.
Use `offline: true` for a fully offline configuration or `review --offline` for a
local explicit override. Local configuration is user-controlled, not a security
boundary against the machine owner.

Natural-language rules accept strings or stable IDs:

```yaml
nl_rules:
  - id: org.require_auth
    text: Every state-changing API endpoint must require authentication.
```

Legacy strings receive content-derived IDs. Use explicit IDs for rules referenced
by enforcement settings. Model detection is probabilistic; policy enforcement
applies to findings the scanner actually returns, not a guarantee of detection.

## Git safety

Review scans the staged snapshot and cross-file context from that snapshot.
Partial staging is preserved: approved edits are merged into the working file
without staging unrelated changes. Conflicts or changes made externally during
review stop approval. No nested commit is run. Temporary sessions and extracted
image data are deleted on normal exit. Environment extraction is local-only and
refuses a tracked `.env` file.

A refresh retains the live session. Closing the tab is not approval; return to the
printed URL or cancel with Ctrl+C in the terminal. Inactive sessions expire after
the configured timeout. A terminated process loses unapplied session edits.

Noninteractive use never applies fixes or waits for a terminal:

```sh
plutonium review --non-interactive
plutonium check --base BASE_SHA --head PROPOSED_SHA
```

The check command uses `.plutonium.yaml` from the trusted base revision, scans
proposed content without executing it, and emits a JSON report without raw secret
snippets. Configure the **Required policy review** CI job as a required protected
branch check. Required organization checks must run from a trusted workflow or
organization ruleset: a PR-controlled workflow is not itself an enforcement
boundary. The supplied workflow installs scanner code from the base revision.
The initial rollout must land this scanner/check command on the base branch before
that workflow can enforce subsequent PRs. Forks without engine credentials fail
required coverage unless the trusted policy explicitly selects offline checks.

## Standalone Studio and frontend assets

`plutonium serve` retains the standalone inspector, image redaction, prompt
firewall, policies, and benchmarks. Commit review starts its own server and cannot
edit policy or switch repositories.

The review page has no frontend build dependency. Studio styles are checked in;
regenerate its utility stylesheet after changing utility classes with Tailwind 3:

```sh
tailwindcss -c scripts/frontend/tailwind.config.cjs \
  -i scripts/frontend/tailwind.css \
  -o plutonium/static/studio-utilities.css --minify
```

Validation: `python -m pytest -q`; JavaScript syntax checks:
`node --check plutonium/static/review.js` and
`node --check plutonium/static/studio.js`.
