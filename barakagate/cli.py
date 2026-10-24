"""BarakaGate CLI (Typer + Rich).  Entry point: `barakagate` -> `barakagate.cli:app`."""
from __future__ import annotations

import json
import os
import stat
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import typer
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from barakagate.config import PROJECT_ROOT, load_config, load_dotenv
from barakagate.models import ActionType, EngineMode, Finding, FindingCategory, ScanResult

app = typer.Typer(
    name="barakagate",
    help="BarakaGate - multimodal pre-flight security, privacy & cross-file logical bug gate (Gemma 4).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console(highlight=False)

VERDICT_STYLE = {"PASS": "bold green", "WARN": "bold yellow", "BLOCK": "bold red"}
SEV_STYLE = {"CRITICAL": "bold white on red", "HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan"}
ACTION_KEYS = {"s": ActionType.SYNTHETIC_TWIN, "e": ActionType.ENV_EXTRACT, "p": ActionType.CODE_PATCH,
               "m": ActionType.SOLID_MASK, "k": ActionType.WHITELIST}

MODE_HELP = "Engine: cloud_fast | cloud_deep | local_edge | hybrid_smart"
PRESET_HELP = "Policy preset: all | fintech_morocco | research_lab | general_devsecops"


# --------------------------------------------------------------------------- helpers

def _banner() -> None:
    console.print(Panel.fit(
        Text.assemble(("BarakaGate v1.0", "bold bright_green"), "  ",
                      ("Open-Weight Pre-Flight Security, Privacy & Bug Gate", "dim"), "  ",
                      ("powered by Gemma 4", "magenta")),
        border_style="bright_green"))


def _router(root: Path, offline_safe: bool):
    from barakagate.llm_router import GemmaRouter
    cfg = load_config(root)
    return GemmaRouter(ollama_url=cfg.models.get("ollama_url", "http://localhost:11434"),
                       cache_path=root / ".barakagate" / "demo_cache.json", offline_safe=offline_safe)


def _scanner(root: Path, offline: bool, offline_safe: bool):
    from barakagate.scanner import Scanner
    router = None if offline else _router(root, offline_safe)
    return Scanner(root=str(root), router=router, config=load_config(root), offline=offline)


def _mode(mode: str) -> EngineMode:
    try:
        return EngineMode(mode)
    except ValueError:
        raise typer.BadParameter(f"unknown mode '{mode}'. {MODE_HELP}")


def _is_leak(f: Finding) -> bool:
    return f.category != FindingCategory.LOGICAL_BUG


def scoreboard(result: ScanResult) -> str:
    logic = sum(1 for f in result.findings if f.category == FindingCategory.LOGICAL_BUG)
    proofs = sum(1 for f in result.findings if f.cross_file_context_used)
    regex = result.regex_baseline_count or sum(1 for f in result.findings if f.caught_by_regex_baseline)
    total = len(result.findings)
    return (f"Regex baseline: {regex} | BarakaGate (Gemma 4): {total} "
            f"(+{logic} logic bugs, cross-file proofs: {proofs})")


def render_result(result: ScanResult, show_trace: bool = True, max_trace_lines: int = 12) -> None:
    style = VERDICT_STYLE.get(result.verdict, "bold")
    console.print(Panel(
        Group(Text(f"VERDICT: {result.verdict}", style=style),
              Text(result.summary or "", style="white"),
              Text(f"engine: {result.engine_used}   preset: {result.preset_used}   "
                   f"indexed chunks: {result.indexed_chunks_count}", style="dim")),
        border_style=style.split()[-1], title="BarakaGate Verdict", title_align="left"))
    console.print(Text(scoreboard(result), style="bold cyan"))
    if result.retrieved_context_Chunks:
        console.print(Text("Cross-file context: " + ", ".join(result.retrieved_context_Chunks[:10]), style="dim"))
    if result.thinking_trace and show_trace:
        lines = result.thinking_trace.strip().splitlines()
        more = f"\n... ({len(lines) - max_trace_lines} more lines, use --trace)" if len(lines) > max_trace_lines else ""
        console.print(Panel(Text("\n".join(lines[:max_trace_lines]) + more, style="dim italic"),
                            title="<|think|> reasoning trace", title_align="left", border_style="grey37"))
    if not result.findings:
        console.print(Text("No findings. Ship it.", style="green"))
        return
    t = Table(box=box.SIMPLE_HEAVY, show_lines=False, expand=True)
    t.add_column("#", style="dim", width=3)
    t.add_column("Severity", no_wrap=True)
    t.add_column("Category", no_wrap=True)
    t.add_column("Location", style="cyan", overflow="fold")
    t.add_column("Title", overflow="fold")
    t.add_column("Cross-File Proof", style="magenta", overflow="fold")
    t.add_column("Regex?", justify="center", width=6)
    for i, f in enumerate(result.findings, 1):
        sev = f.severity.value
        cat = "🔴 LEAK/PII" if _is_leak(f) else "🟣 LOGIC BUG"
        loc = f"{f.file_path}:{f.line_start}" if f.line_start else f.file_path
        t.add_row(str(i), Text(sev, style=SEV_STYLE.get(sev, "")), cat, Text(loc), Text(f.title),
                  Text(f.cross_file_context_used or "-"), "yes" if f.caught_by_regex_baseline else "[bold]no[/]")
    console.print(t)
    for i, f in enumerate(result.findings, 1):
        if not (f.offending_snippet or f.replacement_snippet):
            continue
        body = Text()
        body.append(f"{f.reason}\n", style="white")
        for ln in (f.offending_snippet or "").splitlines():
            body.append(f"- {ln}\n", style="red")
        for ln in (f.replacement_snippet or "").splitlines():
            body.append(f"+ {ln}\n", style="green")
        console.print(Panel(body, title=f"#{i} fix: {f.recommended_action.value}", title_align="left",
                            border_style="grey50", padding=(0, 1)))


def _resolve(path: str, root: Path) -> Optional[Path]:
    p = Path(path)
    for cand in (p, root / p, Path.cwd() / p):
        if cand.is_file():
            return cand
    return None


def _ask_action(f: Finding) -> ActionType:
    default = {ActionType.SYNTHETIC_TWIN: "s", ActionType.ENV_EXTRACT: "e", ActionType.CODE_PATCH: "p",
               ActionType.SOLID_MASK: "m", ActionType.GAUSSIAN_BLUR: "m", ActionType.WHITELIST: "k"}[f.recommended_action]
    console.print(Text(f"\n{f.severity.value} {f.file_path}:{f.line_start} - {f.title}", style="bold"))
    if f.offending_snippet:
        console.print(Text(f"- {f.offending_snippet}", style="red"))
    if f.replacement_snippet:
        console.print(Text(f"+ {f.replacement_snippet}", style="green"))
    choice = typer.prompt("[s]ynthetic twin / [e]nv extract / [p]atch / [m]ask / [k]eep", default=default)
    return ACTION_KEYS.get(choice.strip().lower()[:1], ActionType.WHITELIST)


def apply_fixes(result: ScanResult, root: Path, interactive: bool) -> List[dict]:
    from barakagate.redactor import apply_to_disk
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for f in result.findings:
        if f.target_type != "image":
            by_file[f.file_path].append(f)
    summaries = []
    for fp, findings in by_file.items():
        path = _resolve(fp, root)
        if path is None:
            console.print(Text(f"skip {fp}: file not found", style="yellow"))
            continue
        decisions = {f.id: (_ask_action(f) if interactive else f.recommended_action) for f in findings}
        summary = apply_to_disk(str(path), findings, decisions, env_path=str(root / ".env"), root=str(root))
        summaries.append(summary)
        console.print(Panel(Text(summary["diff"] or "(no changes)"), title=f"patched {path}",
                            subtitle=f"applied {len(summary['applied'])} / skipped {len(summary['skipped'])}"
                                     + (f" / .env += {', '.join(summary['env_added'])}" if summary["env_added"] else ""),
                            border_style="green"))
    return summaries


def _finish(result: ScanResult, as_json: bool) -> None:
    if as_json:
        typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(code=1 if result.verdict == "BLOCK" else 0)


# --------------------------------------------------------------------------- commands

@app.command()
def scan(
    paths: List[str] = typer.Argument(..., help="Files or directories to scan"),
    mode: str = typer.Option("cloud_fast", "--mode", "-m", help=MODE_HELP),
    preset: str = typer.Option("all", "--preset", "-p", help=PRESET_HELP),
    offline: bool = typer.Option(False, "--offline", help="No LLM: regex + offline heuristic engine only"),
    offline_safe: bool = typer.Option(True, "--offline-safe/--no-offline-safe", help="Fall back to the demo cache"),
    as_json: bool = typer.Option(False, "--json", help="Print the ScanResult as JSON"),
    fix: bool = typer.Option(False, "--fix", help="Interactive human-in-the-loop remediation"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply every recommended action without asking"),
    trace: bool = typer.Option(False, "--trace", help="Show the full reasoning trace"),
    root: Optional[Path] = typer.Option(None, "--root", help="Repository root (index + cache live here)"),
):
    """Scan files/directories for leaks, PII and cross-file logical bugs."""
    load_dotenv()
    root = (root or Path.cwd()).resolve()
    scanner = _scanner(root, offline, offline_safe)
    if not as_json:
        _banner()
        with console.status("Indexing codebase & asking Gemma 4..."):
            result = scanner.scan_files(paths, mode=_mode(mode), preset=preset)
        render_result(result, max_trace_lines=10_000 if trace else 12)
    else:
        result = scanner.scan_files(paths, mode=_mode(mode), preset=preset)
    if (fix or yes) and result.findings:
        apply_fixes(result, root, interactive=fix and not yes)
    _finish(result, as_json)


@app.command()
def staged(
    mode: str = typer.Option("cloud_fast", "--mode", "-m", help=MODE_HELP),
    preset: str = typer.Option("all", "--preset", "-p", help=PRESET_HELP),
    offline: bool = typer.Option(False, "--offline"),
    offline_safe: bool = typer.Option(True, "--offline-safe/--no-offline-safe"),
    as_json: bool = typer.Option(False, "--json"),
    root: Optional[Path] = typer.Option(None, "--root"),
):
    """Scan the git staged diff (pre-commit hook). Exit 1 on BLOCK."""
    load_dotenv()
    root = (root or Path.cwd()).resolve()
    scanner = _scanner(root, offline, offline_safe)
    result = scanner.scan_staged(mode=_mode(mode), preset=preset)
    if not as_json:
        _banner()
        render_result(result)
        if result.verdict == "BLOCK":
            console.print(Text("Commit blocked. Fix with `barakagate scan <files> --fix` or bypass with "
                               "`git commit --no-verify` (not recommended).", style="red"))
    _finish(result, as_json)


@app.command()
def index(
    root: Optional[Path] = typer.Option(None, "--root"),
    force: bool = typer.Option(False, "--force", help="Re-chunk every file"),
):
    """Build / refresh the local codebase index (.barakagate/index.json)."""
    from barakagate.indexer import CodebaseIndexer
    root = (root or Path.cwd()).resolve()
    with console.status("Chunking & indexing..."):
        stats = CodebaseIndexer(root, load_config(root)).build(force=force)
    t = Table(title="Codebase index", box=box.ROUNDED)
    for k, v in stats.model_dump().items():
        t.add_row(k, str(len(v)) if isinstance(v, list) else str(v))
    console.print(t)


def _sidecar_boxes(path: Path) -> List[List[int]]:
    side = path.with_name(path.name + ".boxes.json")
    if side.is_file():
        try:
            return [b["bbox_2d"] for b in json.loads(side.read_text()) if b.get("bbox_2d")]
        except (ValueError, KeyError, TypeError):
            return []
    return []


@app.command()
def image(
    path: Path = typer.Argument(..., exists=True, dir_okay=False),
    apply: bool = typer.Option(False, "--apply", help="Write a redacted PNG"),
    style: str = typer.Option("gaussian_blur", "--style", help="gaussian_blur | solid_mask"),
    out: Optional[Path] = typer.Option(None, "--out"),
    mode: str = typer.Option("cloud_fast", "--mode", "-m", help=MODE_HELP),
    offline: bool = typer.Option(False, "--offline"),
    offline_safe: bool = typer.Option(True, "--offline-safe/--no-offline-safe"),
    as_json: bool = typer.Option(False, "--json"),
    root: Optional[Path] = typer.Option(None, "--root"),
):
    """Gemma 4 vision scan of a screenshot; optionally blur/mask the leaks."""
    from barakagate.redactor import redact_image
    load_dotenv()
    root = (root or Path.cwd()).resolve()
    result = _scanner(root, offline, offline_safe).scan_image(str(path), mode=_mode(mode))
    boxes = [f.bbox_2d for f in result.findings if f.bbox_2d]
    if not boxes:
        boxes = _sidecar_boxes(path)
    if not as_json:
        _banner()
        render_result(result)
    out_path = None
    if apply:
        if style not in ("gaussian_blur", "solid_mask"):
            raise typer.BadParameter("style must be gaussian_blur or solid_mask")
        out_path = redact_image(str(path), boxes, style=style, out_path=str(out) if out else None)
        if not as_json:
            console.print(Text(f"Redacted {len(boxes)} region(s) -> {out_path}", style="bold green"))
    if as_json:
        data = json.loads(result.model_dump_json())
        data["redacted_path"] = out_path
        typer.echo(json.dumps(data, indent=2, ensure_ascii=False))
    raise typer.Exit(code=1 if (result.verdict == "BLOCK" and not apply) else 0)


@app.command()
def sanitize(
    file: str = typer.Argument("-", help="File to sanitize, or - for stdin"),
    as_json: bool = typer.Option(False, "--json"),
    local_llm: bool = typer.Option(False, "--local-llm", help="Also run on-device gemma4:e4b NER (Ollama)"),
):
    """Safe-to-Prompt firewall: tokenize PII/secrets before pasting into a cloud AI."""
    from barakagate.redactor import sanitize_prompt, sanitize_prompt_llm
    text = sys.stdin.read() if file == "-" else Path(file).read_text(encoding="utf-8")
    sanitized, vault = sanitize_prompt_llm(text) if local_llm else sanitize_prompt(text)
    if as_json:
        typer.echo(json.dumps({"sanitized": sanitized, "vault": vault}, indent=2, ensure_ascii=False))
        return
    console.print(Panel(Text(sanitized), title="Sanitized prompt (safe to send)", border_style="green"))
    t = Table(title="Local token vault (never leaves this machine)", box=box.ROUNDED)
    t.add_column("Token", style="cyan")
    t.add_column("Original value", style="red")
    for tok, val in vault.items():
        t.add_row(Text(tok), Text(val))
    console.print(t)


HOOK_SCRIPT = """#!/bin/sh
# BarakaGate pre-commit hook (installed by `barakagate install-hook`)
if command -v barakagate >/dev/null 2>&1; then
  barakagate staged
else
  if command -v python3 >/dev/null 2>&1; then
    python3 -m barakagate.cli staged
  else
    python -m barakagate.cli staged
  fi
fi
"""


@app.command("install-hook")
def install_hook(root: Optional[Path] = typer.Option(None, "--root")):
    """Install the git pre-commit hook (backs up an existing hook)."""
    root = (root or Path.cwd()).resolve()
    git_dir = root / ".git"
    if not git_dir.is_dir():
        console.print(Text(f"{root} is not a git repository", style="red"))
        raise typer.Exit(code=2)
    hooks = git_dir / "hooks"
    hooks.mkdir(exist_ok=True)
    hook = hooks / "pre-commit"
    if hook.exists() and "BarakaGate" not in hook.read_text(errors="ignore"):
        hook.rename(hooks / "pre-commit.bak")
        console.print(Text("Existing hook backed up to pre-commit.bak", style="yellow"))
    hook.write_text(HOOK_SCRIPT)
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    console.print(Text(f"Installed BarakaGate pre-commit hook -> {hook}", style="bold green"))


def _load_benchmark_module():
    import importlib.util
    for cand in (Path.cwd() / "evaluate_benchmark.py", PROJECT_ROOT / "evaluate_benchmark.py"):
        if cand.is_file():
            spec = importlib.util.spec_from_file_location("evaluate_benchmark", cand)
            mod = importlib.util.module_from_spec(spec)
            sys.modules["evaluate_benchmark"] = mod
            spec.loader.exec_module(mod)
            return mod
    raise typer.BadParameter("evaluate_benchmark.py not found")


@app.command()
def benchmark(
    offline: bool = typer.Option(False, "--offline", help="Only deterministic engines (regex + offline heuristic)"),
    engines: Optional[str] = typer.Option(None, "--engines", help="Comma list: regex,offline,cloud_fast,local_edge"),
):
    """Run the 12-case Regex vs Gemma 4 benchmark matrix."""
    load_dotenv()
    mod = _load_benchmark_module()
    eng = [e.strip() for e in engines.split(",")] if engines else None
    with console.status("Running benchmark..."):
        result = mod.run_benchmark(eng, offline)
    md = mod.to_markdown(result)
    mod.write_outputs(result, md)
    from rich.markdown import Markdown
    console.print(Markdown(md))
    console.print(Text("Saved .barakagate/benchmark.md and .barakagate/benchmark.json", style="dim"))


@app.command()
def serve(host: str = typer.Option("127.0.0.1", "--host"), port: int = typer.Option(8000, "--port")):
    """Launch BarakaGate Studio (FastAPI web UI)."""
    import uvicorn
    _banner()
    console.print(Text(f"Studio -> http://{host}:{port}", style="bold green"))
    uvicorn.run("barakagate.server:app", host=host, port=port)


if __name__ == "__main__":
    app()
