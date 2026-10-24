"""BarakaGate Studio backend (FastAPI).

Run:  uvicorn barakagate.server:app --port 8000   (or `barakagate serve`)

Design rules:
* Repo root = env ``BARAKAGATE_ROOT`` or the current working directory.
* Scanner / redactor / indexer are imported lazily inside endpoints so the server
  boots even while teammates' modules are still being written.
* Engine failures never surface as HTTP 500: scans degrade to the deterministic
  ``offline_heuristic`` engine and the problem is reported in ``warnings``.
* Long LLM calls run in plain ``def`` endpoints (FastAPI threadpool).
"""
from __future__ import annotations

import base64
import difflib
import inspect
import io
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from barakagate.config import CONFIG_FILENAME, PROJECT_ROOT, find_config, load_config, validate_yaml
from barakagate.models import ActionType, EngineMode, Finding, ScanResult

VERSION = "1.0.0"
STATIC_DIR = Path(__file__).resolve().parent / "static"
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "fintech_morocco": {
        "label": "Load Moroccan Fintech Checkout PR",
        "title": "Moroccan Fintech Checkout PR",
        "preset": "fintech_morocco",
        "targets": ["checkout.py"],
    },
    "research_lab_um6p": {
        "label": "Load Research Lab Notebook & Pipeline",
        "title": "UM6P Research Lab Notebook & Pipeline",
        "preset": "research_lab",
        "targets": ["train_pipeline.py", "loader.py"],
    },
    "general_devsecops": {
        "label": "Load General DevSecOps API",
        "title": "General DevSecOps API",
        "preset": "general_devsecops",
        "targets": ["api.py", "settings.py"],
    },
}

IMAGE_LABELS = {
    "devtools": "DevTools CMI Bearer Token + Moroccan CIN",
    "notebook": "Jupyter Notebook Research Table with Student CNEs",
    "jupyter": "Jupyter Notebook Research Table with Student CNEs",
    "cne": "Jupyter Notebook Research Table with Student CNEs",
    "dashboard": "Fintech Admin Dashboard",
}

PRESETS = [
    {"value": "all", "label": "All Policy Packs"},
    {"value": "fintech_morocco", "label": "🇲🇦 Moroccan Fintech & E-Commerce"},
    {"value": "research_lab", "label": "🎓 University & Research Lab"},
    {"value": "general_devsecops", "label": "🌐 General DevSecOps"},
]

ENGINE_LABELS = {
    "cloud_fast": "Gemma 4 26B MoE (gemma-4-26b-a4b-it)",
    "cloud_deep": "Gemma 4 31B Dense (gemma-4-31b-it)",
    "local_edge": "Local gemma4:e4b (Ollama)",
    "hybrid_smart": "Hybrid: local gemma4:e4b → cloud gemma-4-31b-it",
}


# --------------------------------------------------------------------------- state
def repo_root() -> Path:
    return Path(os.environ.get("BARAKAGATE_ROOT") or os.getcwd()).resolve()


def samples_dir() -> Path:
    cand = repo_root() / "samples"
    if all((cand / s).is_dir() for s in SCENARIOS):
        return cand
    return PROJECT_ROOT / "samples"


def policy_path() -> Path:
    return repo_root() / CONFIG_FILENAME


def work_dir() -> Path:
    d = repo_root() / ".barakagate"
    d.mkdir(parents=True, exist_ok=True)
    return d


class _State:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.routers: Dict[str, Any] = {}
        self.scanners: Dict[tuple, Any] = {}
        self.scan_locks: Dict[tuple, threading.Lock] = {}
        self.scans: Dict[str, Dict[str, Any]] = {}
        self.status_cache: Dict[str, Any] = {}

    def reset(self) -> None:
        with self.lock:
            self.scanners.clear()
            self.scan_locks.clear()
            self.status_cache.clear()


STATE = _State()
MAX_SCANS = 64


def get_router():
    from barakagate.llm_router import GemmaRouter

    root = repo_root()
    key = str(root)
    with STATE.lock:
        r = STATE.routers.get(key)
        if r is None:
            cfg = load_config(root)
            r = GemmaRouter(
                ollama_url=cfg.models.get("ollama_url", "http://localhost:11434"),
                cache_path=root / ".barakagate" / "demo_cache.json",
                offline_safe=True,
            )
            STATE.routers[key] = r
        return r


def get_scanner(root: Optional[Path] = None, offline: bool = False):
    """One Scanner per (root, offline) — lazily imported and built."""
    from barakagate.scanner import Scanner  # lazy: Builder A

    root = Path(root or repo_root()).resolve()
    key = (str(root), bool(offline))
    with STATE.lock:
        sc = STATE.scanners.get(key)
        if sc is None:
            cfg = load_config(root)
            sc = Scanner(root=str(root), router=get_router(), config=cfg, offline=bool(offline))
            STATE.scanners[key] = sc
            STATE.scan_locks[key] = threading.Lock()
        return sc, STATE.scan_locks[key]


def _remember_scan(entry: Dict[str, Any]) -> str:
    scan_id = uuid.uuid4().hex[:12]
    with STATE.lock:
        STATE.scans[scan_id] = entry
        while len(STATE.scans) > MAX_SCANS:
            STATE.scans.pop(next(iter(STATE.scans)))
    return scan_id


def _get_scan(scan_id: str) -> Dict[str, Any]:
    entry = STATE.scans.get(scan_id)
    if not entry:
        raise HTTPException(404, f"Unknown scan_id '{scan_id}' (server restarted? re-run the scan)")
    return entry


def _dump(model: Any) -> Any:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return model


def _within(path: Path, *bases: Path) -> bool:
    for b in bases:
        try:
            path.relative_to(b.resolve())
            return True
        except ValueError:
            continue
    return False


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _index_stats(scanner) -> Dict[str, int]:
    try:
        idx = scanner.indexer
        if hasattr(idx, "ensure_built"):
            idx.ensure_built()
        elif not getattr(idx, "chunks", None):
            idx.build()
        chunks = list(getattr(idx, "chunks", []) or [])
        symbols = len(getattr(idx, "symbol_map", {}) or {})
        files = len({c.file_path for c in chunks})
        return {"chunks": len(chunks), "symbols": symbols, "files": files}
    except Exception:  # noqa: BLE001
        return {"chunks": 0, "symbols": 0, "files": 0}


def _chunk_dict(c: Any) -> Dict[str, Any]:
    d = _dump(c) if not isinstance(c, dict) else c
    return {
        "file_path": d.get("file_path", ""),
        "symbol_name": d.get("symbol_name", ""),
        "chunk_type": d.get("chunk_type", ""),
        "start_line": d.get("start_line", 0),
        "end_line": d.get("end_line", 0),
        "code": d.get("code", ""),
    }


def _empty_result(preset: str, summary: str) -> ScanResult:
    return ScanResult(verdict="PASS", engine_used="unavailable", preset_used=preset, summary=summary)


def _verdict(findings: List[Finding]) -> str:
    try:
        from barakagate.scanner import compute_verdict

        return compute_verdict(findings)
    except Exception:  # noqa: BLE001
        sev = {f.severity.value for f in findings if f.recommended_action != ActionType.WHITELIST}
        if sev & {"CRITICAL", "HIGH"}:
            return "BLOCK"
        return "WARN" if "MEDIUM" in sev else "PASS"


def _run_scan(fn_name: str, args: tuple, kwargs: dict, root: Path, offline: bool, warnings: List[str]):
    """Run a Scanner method; degrade to the offline heuristic engine on any failure."""
    try:
        sc, lock = get_scanner(root, offline)
    except ImportError as e:
        warnings.append(f"Scanner module unavailable: {e}")
        return None, None
    try:
        with lock:
            res = getattr(sc, fn_name)(*args, **kwargs)
            ctx = list(getattr(sc, "last_context", []) or [])
        errs = getattr(getattr(sc, "router", None), "last_errors", None) or []
        if not offline and res.engine_used.startswith(("offline", "cache")) and errs:
            warnings.append("Cloud/local engines failed, fell back: " + " | ".join(errs[:3]))
        return res, (sc, ctx)
    except Exception as e:  # noqa: BLE001
        warnings.append(f"{fn_name} failed on engine ({type(e).__name__}: {str(e)[:200]}); using offline heuristic.")
        if offline:
            return None, None
        try:
            sc, lock = get_scanner(root, True)
            with lock:
                res = getattr(sc, fn_name)(*args, **kwargs)
                ctx = list(getattr(sc, "last_context", []) or [])
            return res, (sc, ctx)
        except Exception as e2:  # noqa: BLE001
            warnings.append(f"offline heuristic failed too: {type(e2).__name__}: {str(e2)[:200]}")
            return None, None


# --------------------------------------------------------------------------- app
app = FastAPI(title="BarakaGate Studio", version=VERSION)
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):  # never leak a bare 500 page
    return JSONResponse(status_code=500, content={"detail": f"{type(exc).__name__}: {exc}"})


@app.get("/", response_class=HTMLResponse)
def index_page():
    page = STATIC_DIR / "index.html"
    if not page.is_file():
        return HTMLResponse("<h1>BarakaGate Studio</h1><p>static/index.html missing</p>")
    return FileResponse(str(page), media_type="text/html")


@app.get("/api/status")
def status():
    root = repo_root()
    cached = STATE.status_cache.get(str(root))
    if cached and time.time() - cached["_ts"] < 10:
        return {k: v for k, v in cached.items() if k != "_ts"}
    warnings: List[str] = []
    engines = {"cloud": False, "ollama": False}
    try:
        r = get_router()
        engines = {"cloud": bool(r.cloud_available()), "ollama": bool(r.ollama_available())}
    except Exception as e:  # noqa: BLE001
        warnings.append(f"router: {e}")
    index = {"chunks": 0, "symbols": 0, "files": 0}
    try:
        sc, _ = get_scanner(root, True)
        index = _index_stats(sc)
    except Exception as e:  # noqa: BLE001
        warnings.append(f"indexer not ready: {type(e).__name__}: {e}")
    cfg = load_config(root)
    out = {
        "version": VERSION,
        "root": str(root),
        "engines": engines,
        "index": index,
        "models": cfg.models,
        "engine_labels": ENGINE_LABELS,
        "default_engine": cfg.default_engine,
        "default_preset": cfg.default_preset,
        "presets": PRESETS,
        "preset_titles": {k: (v or {}).get("title", k) for k, v in (cfg.raw.get("presets") or {}).items()},
        "warnings": warnings,
    }
    if not warnings:
        STATE.status_cache[str(root)] = {**out, "_ts": time.time()}
    return out


class IndexBody(BaseModel):
    force: bool = False
    scenario: Optional[str] = None


@app.post("/api/index")
def reindex(body: IndexBody = IndexBody()):
    root = repo_root()
    if body.scenario:
        if body.scenario not in SCENARIOS:
            raise HTTPException(404, f"unknown scenario {body.scenario}")
        root = samples_dir() / body.scenario
    try:
        sc, lock = get_scanner(root, True)
        with lock:
            stats = sc.indexer.build(force=body.force)
        STATE.status_cache.clear()
        out = _dump(stats)
        out.update(_index_stats(sc))
        out["root"] = str(root)
        return out
    except Exception as e:  # noqa: BLE001
        return {"files_indexed": 0, "files_reused": 0, "chunks": 0, "symbols": 0, "files": 0,
                "notebook_images": [], "warnings": [f"{type(e).__name__}: {e}"]}


# --------------------------------------------------------------------------- samples
@app.get("/api/samples")
def list_samples():
    out = []
    for name, meta in SCENARIOS.items():
        d = samples_dir() / name
        out.append({
            "name": name, "label": meta["label"], "title": meta["title"], "preset": meta["preset"],
            "target_file": meta["targets"][0], "targets": meta["targets"],
            "files": sorted(p.name for p in d.iterdir() if p.is_file()) if d.is_dir() else [],
        })
    return out


def _scenario_files(name: str) -> Dict[str, str]:
    d = samples_dir() / name
    files: Dict[str, str] = {}
    for p in sorted(d.rglob("*")):
        if not p.is_file() or ".barakagate" in p.parts or "__pycache__" in p.parts:
            continue
        rel = p.relative_to(d).as_posix()
        if p.suffix == ".ipynb":
            files[rel] = _notebook_as_text(p)
        else:
            files[rel] = _read(p)
    return files


def _notebook_as_text(p: Path) -> str:
    """Readable rendering of a notebook for the code viewer (images elided)."""
    try:
        nb = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _read(p)
    out: List[str] = []
    for i, cell in enumerate(nb.get("cells", [])):
        src = cell.get("source", "")
        src = "".join(src) if isinstance(src, list) else str(src)
        out.append(f"# %% [{cell.get('cell_type', 'code')}] cell_{i}")
        out.append(src)
        for o in cell.get("outputs", []) or []:
            data = o.get("data") or {}
            if "text/plain" in data:
                txt = data["text/plain"]
                txt = "".join(txt) if isinstance(txt, list) else str(txt)
                out.append("# Out: " + txt.replace("\n", "\n# Out: "))
            if "image/png" in data:
                out.append("# Out: <image/png output — see Image Sanitizer tab>")
            if o.get("text"):
                t = o["text"]
                out.append("# Out: " + ("".join(t) if isinstance(t, list) else str(t)))
        out.append("")
    return "\n".join(out)


@app.get("/api/samples/{name}")
def get_sample(name: str):
    if name not in SCENARIOS:
        raise HTTPException(404, f"unknown scenario '{name}'")
    meta = SCENARIOS[name]
    return {"name": name, "title": meta["title"], "preset": meta["preset"],
            "target_file": meta["targets"][0], "targets": meta["targets"],
            "files": _scenario_files(name)}


# --------------------------------------------------------------------------- scanning
class ScanBody(BaseModel):
    scenario: Optional[str] = None
    files: Optional[List[str]] = None
    text: Optional[str] = None
    file_path: Optional[str] = None
    mode: EngineMode = EngineMode.CLOUD_FAST
    preset: str = "all"
    offline: bool = False


def _resolve_file(fp: str, base: Path, file_map: Dict[str, Path]) -> Optional[str]:
    """Map a finding's file_path onto one of the scanned files (relative key)."""
    if not fp:
        return next(iter(file_map), None)
    norm = fp.replace("\\", "/")
    if norm in file_map:
        return norm
    try:
        rel = Path(norm).resolve().relative_to(base).as_posix() if Path(norm).is_absolute() else None
        if rel in file_map:
            return rel
    except ValueError:
        pass
    for key in file_map:
        if norm.endswith("/" + key) or key.endswith("/" + norm) or Path(key).name == Path(norm).name:
            return key
    return None


def _finish_scan(res: Optional[ScanResult], ctx_info, *, base: Path, file_map: Dict[str, Path],
                 texts: Dict[str, str], preset: str, warnings: List[str], scenario: Optional[str],
                 kind: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if res is None:
        res = _empty_result(preset, "Scanner unavailable — " + "; ".join(warnings[-1:]))
    sc, ctx = ctx_info if ctx_info else (None, [])
    # Attach each finding to a scanned file key so preview/apply can find it.
    by_file: Dict[str, List[Finding]] = {}
    for f in res.findings:
        key = _resolve_file(f.file_path, base, file_map) if file_map else f.file_path
        if key:
            by_file.setdefault(key, []).append(f)
    entry = {
        "kind": kind, "scenario": scenario, "base": str(base), "file_map": {k: str(v) for k, v in file_map.items()},
        "texts": texts, "findings": {f.id: f for f in res.findings}, "by_file": by_file, "result": res,
    }
    scan_id = _remember_scan(entry)
    out = _dump(res)
    regex_count = sum(1 for f in res.findings if f.caught_by_regex_baseline)
    out.update({
        "scan_id": scan_id,
        "kind": kind,
        "scenario": scenario,
        "warnings": warnings,
        "target_files": list(texts.keys()),
        "files": texts,
        "context": [_chunk_dict(c) for c in ctx],
        "finding_files": {fid: k for k, fl in by_file.items() for fid in [x.id for x in fl]},
        "scoreboard": {
            "regex_caught": regex_count,
            "gemma_caught": len(res.findings),
            "logical_bugs": sum(1 for f in res.findings if f.category.value == "logical_bug"),
            "leaks": sum(1 for f in res.findings if f.category.value == "security_leak"),
            "pii": sum(1 for f in res.findings if f.category.value == "privacy_pii"),
            "cross_file": sum(1 for f in res.findings if f.cross_file_context_used),
        },
    })
    if sc is not None:
        out["index"] = _index_stats(sc)
    if extra:
        out.update(extra)
    return out


@app.post("/api/scan")
def scan(body: ScanBody):
    warnings: List[str] = []
    t0 = time.time()
    if body.scenario:
        if body.scenario not in SCENARIOS:
            raise HTTPException(404, f"unknown scenario '{body.scenario}'")
        base = samples_dir() / body.scenario
        targets = body.files or SCENARIOS[body.scenario]["targets"]
        file_map = {t: (base / t).resolve() for t in targets if (base / t).is_file()}
        if not file_map:
            raise HTTPException(404, "scenario target files missing")
        texts = {k: _read(p) for k, p in file_map.items()}
        res, ctx = _run_scan("scan_files", ([str(p) for p in file_map.values()],),
                             {"mode": body.mode, "preset": body.preset}, base, body.offline, warnings)
        out = _finish_scan(res, ctx, base=base, file_map=file_map, texts=texts, preset=body.preset,
                           warnings=warnings, scenario=body.scenario, kind="scenario")
    elif body.text is not None:
        fp = body.file_path or "snippet.py"
        base = repo_root()
        res, ctx = _run_scan("scan_text", (body.text,), {"file_path": fp, "mode": body.mode, "preset": body.preset},
                             base, body.offline, warnings)
        out = _finish_scan(res, ctx, base=base, file_map={fp: base / fp}, texts={fp: body.text},
                           preset=body.preset, warnings=warnings, scenario=None, kind="text")
    elif body.files:
        base = repo_root()
        file_map: Dict[str, Path] = {}
        for f in body.files:
            p = (base / f).resolve()
            if not _within(p, base) or not p.is_file():
                raise HTTPException(400, f"file outside repo or missing: {f}")
            file_map[p.relative_to(base).as_posix()] = p
        texts = {k: _read(p) for k, p in file_map.items()}
        res, ctx = _run_scan("scan_files", ([str(p) for p in file_map.values()],),
                             {"mode": body.mode, "preset": body.preset}, base, body.offline, warnings)
        out = _finish_scan(res, ctx, base=base, file_map=file_map, texts=texts, preset=body.preset,
                           warnings=warnings, scenario=None, kind="files")
    else:
        raise HTTPException(400, "Provide one of: scenario, files, text")
    out["elapsed_s"] = round(time.time() - t0, 2)
    return out


class StagedBody(BaseModel):
    mode: EngineMode = EngineMode.CLOUD_FAST
    preset: str = "all"
    offline: bool = False


@app.post("/api/scan/staged")
def scan_staged(body: StagedBody = StagedBody()):
    warnings: List[str] = []
    t0 = time.time()
    base = repo_root()
    diff = ""
    try:
        diff = subprocess.run(["git", "diff", "--cached"], cwd=str(base), capture_output=True,
                              text=True, timeout=20).stdout
    except Exception as e:  # noqa: BLE001
        warnings.append(f"git diff --cached failed: {e}")
    res, ctx = _run_scan("scan_staged", (), {"mode": body.mode, "preset": body.preset}, base, body.offline, warnings)
    file_map: Dict[str, Path] = {}
    if res is not None:
        for f in res.findings:
            p = Path(f.file_path)
            p = p if p.is_absolute() else base / p
            if p.is_file() and _within(p.resolve(), base):
                file_map[p.resolve().relative_to(base).as_posix()] = p.resolve()
    texts = {"staged.diff": diff or "# No staged changes (git diff --cached is empty)\n"}
    texts.update({k: _read(p) for k, p in file_map.items()})
    out = _finish_scan(res, ctx, base=base, file_map=file_map, texts=texts, preset=body.preset,
                       warnings=warnings, scenario=None, kind="staged")
    out["elapsed_s"] = round(time.time() - t0, 2)
    return out


# --------------------------------------------------------------------------- preview / apply
class DecisionsBody(BaseModel):
    scan_id: str
    decisions: Dict[str, str] = Field(default_factory=dict)
    in_place: bool = False


def _decisions_for(entry, decisions: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for fid, f in entry["findings"].items():
        out[fid] = decisions.get(fid) or f.recommended_action.value
    return out


def _fallback_apply(text: str, findings: List[Finding], decisions: Dict[str, str]) -> str:
    for f in sorted(findings, key=lambda x: -(x.line_start or 0)):
        act = decisions.get(f.id, "")
        if act == "whitelist" or not f.offending_snippet:
            continue
        if act == "solid_mask":
            text = text.replace(f.offending_snippet, "█" * min(len(f.offending_snippet), 24), 1)
        elif f.replacement_snippet:
            text = text.replace(f.offending_snippet, f.replacement_snippet, 1)
    return text


def _unified(a: str, b: str, name: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), f"a/{name}", f"b/{name}"))


@app.post("/api/preview")
def preview(body: DecisionsBody):
    entry = _get_scan(body.scan_id)
    decisions = _decisions_for(entry, body.decisions)
    warnings: List[str] = []
    out: Dict[str, Any] = {}
    try:
        from barakagate import redactor
    except ImportError as e:
        redactor = None
        warnings.append(f"redactor unavailable, using simple patcher: {e}")
    for key, findings in entry["by_file"].items():
        original = entry["texts"].get(key)
        if original is None:
            continue
        sel = {f.id: decisions[f.id] for f in findings}
        try:
            if redactor is None:
                raise RuntimeError("no redactor")
            patched = redactor.apply_text_fixes(original, findings, sel)
            try:
                diff = redactor.preview_patch(original, findings, sel, filename=key)
            except TypeError:
                diff = redactor.preview_patch(original, findings, sel)
        except Exception as e:  # noqa: BLE001
            if redactor is not None:
                warnings.append(f"{key}: redactor failed ({type(e).__name__}: {e}); simple patcher used")
            patched = _fallback_apply(original, findings, sel)
            diff = _unified(original, patched, key)
        out[key] = {"original": original, "patched": patched, "diff": diff or _unified(original, patched, key)}
    return {"files": out, "warnings": warnings, "decisions": decisions}


@app.post("/api/apply")
def apply(body: DecisionsBody):
    entry = _get_scan(body.scan_id)
    decisions = _decisions_for(entry, body.decisions)
    warnings: List[str] = []
    try:
        from barakagate import redactor
    except ImportError as e:
        raise HTTPException(503, f"redactor module unavailable: {e}")
    root = repo_root()
    written: List[Dict[str, Any]] = []
    for key, findings in entry["by_file"].items():
        if key not in entry["texts"] or key == "staged.diff":
            continue
        sel = {f.id: decisions[f.id] for f in findings}
        if all(a == "whitelist" for a in sel.values()):
            continue
        src = Path(entry["file_map"].get(key, ""))
        original = entry["texts"][key]
        # Sample fixtures are never overwritten unless explicitly asked; ad-hoc text always goes
        # to .barakagate/patched; real repo files (files/staged scans) are patched in place.
        if entry["kind"] == "text":
            safe_copy = True
        elif entry["kind"] == "scenario":
            safe_copy = not body.in_place
        else:
            safe_copy = False
        if safe_copy:
            sub = entry["scenario"] or ("snippets" if entry["kind"] == "text" else "repo")
            dest = (work_dir() / "patched" / sub / key).resolve()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(original, encoding="utf-8")
            env_path = dest.parent / ".env"
        else:
            dest = src
            if not _within(dest.resolve(), root, samples_dir()):
                warnings.append(f"refusing to write outside repo: {dest}")
                continue
            env_path = root / ".env"
        try:
            info = redactor.apply_to_disk(str(dest), findings, sel, env_path=str(env_path), root=str(root))
        except Exception as e:  # noqa: BLE001
            warnings.append(f"{key}: apply_to_disk failed ({type(e).__name__}: {e})")
            continue
        patched = _read(dest)
        written.append({
            "file": key, "path": str(dest), "rel_path": _rel(dest), "in_place": not safe_copy,
            "env_path": str(env_path) if env_path.exists() else None,
            "diff": _unified(original, patched, key), "info": _jsonable(info),
        })
    return {"written": written, "warnings": warnings}


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(repo_root()).as_posix()
    except ValueError:
        return str(p)


def _jsonable(x: Any) -> Any:
    try:
        json.dumps(x, default=str)
        return json.loads(json.dumps(x, default=str))
    except Exception:  # noqa: BLE001
        return str(x)


# --------------------------------------------------------------------------- images
def _image_roots() -> List[Path]:
    return [repo_root(), PROJECT_ROOT.resolve()]


def _safe_image_path(path: str) -> Path:
    if not path or "\x00" in path:
        raise HTTPException(400, "missing path")
    raw = Path(path)
    if ".." in raw.parts:
        raise HTTPException(400, "path traversal rejected")
    p = (raw if raw.is_absolute() else repo_root() / raw).resolve()
    if not _within(p, *_image_roots()):
        raise HTTPException(400, "path outside repository rejected")
    if p.suffix.lower() not in IMAGE_EXTS:
        raise HTTPException(400, "not an image")
    if not p.is_file():
        raise HTTPException(404, "image not found")
    return p


def _img_url(p: Path) -> str:
    from urllib.parse import quote

    return "/api/images/file?path=" + quote(_rel(p))


def _label_for(p: Path) -> str:
    n = p.stem.lower()
    for k, v in IMAGE_LABELS.items():
        if k in n:
            return v
    return p.name


def _extract_notebook_images() -> List[Path]:
    out: List[Path] = []
    dest = work_dir() / "tmp_nb_images"
    for nb in sorted(samples_dir().rglob("*.ipynb")):
        if ".barakagate" in nb.parts or ".ipynb_checkpoints" in nb.parts:
            continue
        try:
            data = json.loads(nb.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for ci, cell in enumerate(data.get("cells", [])):
            for oi, o in enumerate(cell.get("outputs", []) or []):
                b64 = (o.get("data") or {}).get("image/png")
                if not b64:
                    continue
                b64 = "".join(b64) if isinstance(b64, list) else b64
                target = dest / f"{nb.stem}_cell{ci}_out{oi}.png"
                if not target.exists():
                    try:
                        dest.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(base64.b64decode(b64))
                    except Exception:  # noqa: BLE001
                        continue
                out.append(target)
    return out


def _nb_label(p: Path) -> str:
    m = re.match(r"(.+?)_cell(\d+)", p.stem)
    return f"Notebook plot: {m.group(1)}.ipynb cell {m.group(2)}" if m else f"Notebook output: {p.stem}"


def _image_size(p: Path):
    try:
        from PIL import Image

        with Image.open(p) as im:
            return im.size
    except Exception:  # noqa: BLE001
        return (0, 0)


@app.get("/api/images")
def list_images():
    seen = set()
    items: List[Dict[str, Any]] = []

    def add(p: Path, source: str, label: Optional[str] = None):
        import hashlib

        p = p.resolve()
        if not p.is_file() or p.suffix.lower() not in IMAGE_EXTS or ".redacted" in p.name:
            return
        try:
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            return
        if digest in seen:  # same notebook plot extracted by several indexers
            return
        seen.add(digest)
        w, h = _image_size(p)
        items.append({"path": _rel(p), "name": p.name, "label": label or _label_for(p), "source": source,
                      "url": _img_url(p), "width": w, "height": h})

    shots = samples_dir() / "screenshots"
    if shots.is_dir():
        for p in sorted(shots.iterdir()):
            add(p, "sample")
    for p in _extract_notebook_images():
        add(p, "notebook", _nb_label(p))
    for d in [work_dir() / "tmp_nb_images", *samples_dir().glob("*/.barakagate/tmp_nb_images")]:
        if d.is_dir():
            for p in sorted(d.glob("*.png")):
                add(p, "notebook", _nb_label(p))
    up = work_dir() / "uploads"
    if up.is_dir():
        for p in sorted(up.iterdir(), key=lambda x: -x.stat().st_mtime)[:12]:
            add(p, "upload", f"Uploaded: {p.name}")
    return items


@app.get("/api/images/file")
def image_file(path: str):
    p = _safe_image_path(path)
    return FileResponse(str(p))


@app.post("/api/image/scan")
async def image_scan(request: Request):
    """Multipart upload (field `file`) or JSON {path, mode, preset, offline}."""
    ctype = request.headers.get("content-type", "")
    params: Dict[str, Any] = {}
    if "multipart/form-data" in ctype:
        form = await request.form()
        up = form.get("file")
        if up is None or not hasattr(up, "read"):
            raise HTTPException(400, "multipart upload needs a 'file' field")
        data = await up.read()
        suffix = Path(getattr(up, "filename", "") or "upload.png").suffix.lower() or ".png"
        if suffix not in IMAGE_EXTS:
            raise HTTPException(400, "unsupported image type")
        dest = work_dir() / "uploads" / f"{uuid.uuid4().hex[:8]}_{re.sub(r'[^A-Za-z0-9._-]', '_', Path(up.filename or 'upload').stem)[:40]}{suffix}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        img_path = dest
        params = {k: form.get(k) for k in ("mode", "preset", "offline") if form.get(k) is not None}
    else:
        try:
            params = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "send multipart 'file' or JSON {path}")
        img_path = _safe_image_path(str(params.get("path", "")))
    mode = params.get("mode") or "cloud_fast"
    preset = params.get("preset") or "all"
    offline = str(params.get("offline", "false")).lower() in ("1", "true", "yes", "on")
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_image_scan_sync, img_path, mode, preset, offline)


def _image_scan_sync(img_path: Path, mode: str, preset: str, offline: bool):
    warnings: List[str] = []
    t0 = time.time()
    try:
        mode_e = EngineMode(mode)
    except ValueError:
        mode_e = EngineMode.CLOUD_FAST
    res, _ = _run_scan("scan_image", (str(img_path),), {"mode": mode_e, "preset": preset}, repo_root(), offline, warnings)
    if res is None:
        res = _empty_result(preset, "Vision scanner unavailable")
    w, h = _image_size(img_path)
    entry = {"kind": "image", "scenario": None, "base": str(repo_root()), "file_map": {}, "texts": {},
             "findings": {f.id: f for f in res.findings}, "by_file": {}, "result": res, "image": str(img_path)}
    out = _dump(res)
    out.update({
        "scan_id": _remember_scan(entry), "warnings": warnings, "elapsed_s": round(time.time() - t0, 2),
        "image": {"path": _rel(img_path), "url": _img_url(img_path), "width": w, "height": h, "name": img_path.name},
    })
    return out


class RedactBody(BaseModel):
    path: str
    boxes: List[List[float]] = Field(default_factory=list)
    style: str = "gaussian_blur"
    as_json: bool = False


@app.post("/api/image/redact")
def image_redact(body: RedactBody):
    src = _safe_image_path(body.path)
    style = "solid_mask" if body.style in ("solid_mask", "solid", "solid_cyber") else "gaussian_blur"
    boxes = []
    for b in body.boxes:
        if len(b) != 4:
            raise HTTPException(400, "each box must be [ymin, xmin, ymax, xmax] on a 0-1000 scale")
        boxes.append([int(max(0, min(1000, round(v)))) for v in b])
    out_dir = work_dir() / "redacted"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{src.stem}.redacted.png"
    try:
        from barakagate import redactor

        res_path = redactor.redact_image(str(src), boxes, style=style, out_path=str(out_path))
        res_path = Path(res_path or out_path)
    except ImportError:
        res_path = _fallback_redact(src, boxes, style, out_path)
    if body.as_json:
        return {"url": _img_url(res_path), "path": _rel(res_path), "boxes": len(boxes), "style": style}
    return Response(content=res_path.read_bytes(), media_type="image/png",
                    headers={"X-Redacted-Path": _rel(res_path),
                             "Content-Disposition": f'inline; filename="{res_path.name}"'})


def _fallback_redact(src: Path, boxes, style: str, out_path: Path) -> Path:
    from PIL import Image, ImageDraw, ImageFilter

    im = Image.open(src).convert("RGB")
    W, H = im.size
    for ymin, xmin, ymax, xmax in boxes:
        x1, y1, x2, y2 = int(xmin / 1000 * W), int(ymin / 1000 * H), int(xmax / 1000 * W), int(ymax / 1000 * H)
        if x2 <= x1 or y2 <= y1:
            continue
        if style == "solid_mask":
            ImageDraw.Draw(im).rectangle([x1, y1, x2, y2], fill=(8, 12, 20))
        else:
            region = im.crop((x1, y1, x2, y2)).filter(ImageFilter.GaussianBlur(14))
            im.paste(region, (x1, y1))
    im.save(out_path, "PNG")
    return out_path


# --------------------------------------------------------------------------- prompt firewall
class SanitizeBody(BaseModel):
    text: str
    use_local_llm: bool = False


@app.post("/api/sanitize")
def sanitize(body: SanitizeBody):
    from barakagate import redactor  # lazy: Builder B

    warnings: List[str] = []
    engine = "local deterministic tokenizer"
    sanitized, vault = None, None
    if body.use_local_llm and hasattr(redactor, "sanitize_prompt_llm"):
        try:
            if get_router().ollama_available():
                sanitized, vault = redactor.sanitize_prompt_llm(body.text, router=get_router()) \
                    if "router" in inspect.signature(redactor.sanitize_prompt_llm).parameters \
                    else redactor.sanitize_prompt_llm(body.text)
                engine = "ollama:gemma4:e4b (on-device)"
            else:
                warnings.append("Ollama gemma4:e4b not reachable — used the local deterministic tokenizer.")
        except Exception as e:  # noqa: BLE001
            warnings.append(f"local LLM sanitizer failed ({type(e).__name__}); used deterministic tokenizer")
            sanitized = vault = None
    if sanitized is None:
        sanitized, vault = redactor.sanitize_prompt(body.text, load_config(repo_root()))
    leaked = sum(len(v.encode()) for v in (vault or {}).values() if v and v in sanitized)
    return {"sanitized": sanitized, "vault": vault or {}, "engine": engine, "warnings": warnings,
            "entities": len(vault or {}), "residual_pii_bytes": leaked}


class FirewallBody(BaseModel):
    sanitized_prompt: str
    vault: Dict[str, str] = Field(default_factory=dict)
    mode: EngineMode = EngineMode.CLOUD_DEEP
    offline: bool = False


FIREWALL_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}, "fixed_code": {"type": "string"}},
    "required": ["answer", "fixed_code"],
}
FIREWALL_SYSTEM = (
    "You are a senior software engineer helping debug code. The user's prompt was sanitized on-device: "
    "sensitive values were replaced with placeholder tokens such as [CIN_TOKEN_1], [RIB_TOKEN_1], "
    "[SECRET_KEY_1], [URL_TOKEN_1]. Keep every placeholder token EXACTLY as written whenever you refer to it; "
    "never invent real values. Answer concisely: explain the root cause, then give corrected code in fixed_code."
)


def _offline_firewall_answer(prompt: str, vault: Dict[str, str]):
    tokens = list(vault.keys())
    tok_line = ", ".join(tokens) if tokens else "(no sensitive entities)"
    answer = (
        "Cloud Gemma 4 is unavailable (offline-safe mode), so this is BarakaGate's deterministic local answer.\n\n"
        f"Your sanitized prompt referenced {len(tokens)} protected value(s): {tok_line}. None of them left this machine.\n\n"
        "Likely root cause: monetary amounts (MAD/TVA) are computed with IEEE-754 float arithmetic "
        "(e.g. `amount * 0.20` then `round(x, 2)`), which drifts by 1 centime during reconciliation. "
        "Use `decimal.Decimal` with ROUND_HALF_UP, or integer centimes, end to end."
    )
    people = [t for t in tokens if any(k in t for k in ("CIN", "RIB", "CNE", "PHONE", "IBAN", "NAME"))]
    if people:
        answer += ("\n\nThe mismatch you saw for " + ", ".join(people[:3]) +
                   " is the rounding drift, not bad data — and keep these identifiers out of assertion messages and logs.")
    fixed = (
        "from decimal import Decimal, ROUND_HALF_UP\n\n"
        "TVA_RATE = Decimal(\"0.20\")\n\n"
        "def compute_tva(amount_mad: Decimal) -> Decimal:\n"
        "    return (amount_mad * TVA_RATE).quantize(Decimal(\"0.01\"), rounding=ROUND_HALF_UP)\n"
    )
    return {"answer": answer, "fixed_code": fixed}


@app.post("/api/firewall/ask")
def firewall_ask(body: FirewallBody):
    prompt = body.sanitized_prompt or ""
    # Defense in depth: refuse to ship anything that still contains a raw vault value.
    raw_hits = [tok for tok, val in (body.vault or {}).items() if val and len(val) >= 3 and val in prompt]
    if raw_hits:
        raise HTTPException(400, f"Refusing to send: prompt still contains raw values for {', '.join(raw_hits)}")
    mode = body.mode if body.mode != EngineMode.LOCAL_EDGE else EngineMode.CLOUD_DEEP
    warnings: List[str] = []
    engine = "offline_template"
    t0 = time.time()
    data = None
    router = None
    try:
        router = get_router()
    except Exception as e:  # noqa: BLE001
        warnings.append(f"router unavailable: {e}")
    if router is not None and not body.offline and (router.cloud_available() or router.ollama_available()):
        try:
            data, engine = router.analyze(mode, prompt, FIREWALL_SYSTEM, FIREWALL_SCHEMA, cache_tag="firewall")
            if getattr(router, "last_errors", None):
                warnings.append("Fell back to " + engine + " after: " + " | ".join(router.last_errors[:2]))
        except Exception as e:  # noqa: BLE001
            warnings.append(f"cloud call failed ({type(e).__name__}: {str(e)[:200]}); offline template used")
            data = None
    elif not body.offline:
        warnings.append("No GEMINI_API_KEY / Ollama — deterministic offline answer used.")
    if not isinstance(data, dict) or not (data.get("answer") or data.get("fixed_code")):
        data = _offline_firewall_answer(prompt, body.vault)
        engine = "offline_template"
    raw = str(data.get("answer", ""))
    code = str(data.get("fixed_code", ""))
    try:
        from barakagate.redactor import rehydrate
    except ImportError:
        def rehydrate(text, vault):  # type: ignore[no-redef]
            for k, v in vault.items():
                text = text.replace(k, v)
            return text
    return {
        "sent_prompt": prompt,
        "sent_bytes": len(prompt.encode()),
        "pii_bytes_sent": 0,
        "raw_answer": raw,
        "raw_fixed_code": code,
        "rehydrated_answer": rehydrate(raw, body.vault),
        "rehydrated_fixed_code": rehydrate(code, body.vault),
        "engine": engine,
        "warnings": warnings,
        "elapsed_s": round(time.time() - t0, 2),
    }


# --------------------------------------------------------------------------- policy
@app.get("/api/policy")
def get_policy():
    p = policy_path()
    src = p if p.is_file() else find_config(repo_root())
    return {"yaml": _read(src) if src else "", "path": str(p)}


class PolicyBody(BaseModel):
    yaml: str


@app.put("/api/policy")
def put_policy(body: PolicyBody):
    try:
        data = validate_yaml(body.yaml)
    except ValueError as e:
        raise HTTPException(400, str(e))
    p = policy_path()
    p.write_text(body.yaml, encoding="utf-8")
    STATE.reset()
    presets = data.get("presets") or {}
    return {"ok": True, "path": str(p), "presets": list(presets.keys()),
            "regex_rules": sum(len((v or {}).get("regex_rules") or []) for v in presets.values()),
            "nl_rules": sum(len((v or {}).get("nl_rules") or []) for v in presets.values())}


# --------------------------------------------------------------------------- benchmark
class BenchBody(BaseModel):
    offline: bool = True


def _import_benchmark():
    import importlib
    import sys

    for root in (str(repo_root()), str(PROJECT_ROOT)):
        if root not in sys.path:
            sys.path.insert(0, root)
    for name in ("evaluate_benchmark", "barakagate.evaluate_benchmark"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    raise ImportError("evaluate_benchmark.py not found")


@app.post("/api/benchmark")
def run_benchmark(body: BenchBody = BenchBody()):
    try:
        mod = _import_benchmark()
    except ImportError as e:
        return {"markdown": "", "result": None, "warnings": [str(e)]}
    fn = getattr(mod, "run_benchmark")
    kwargs: Dict[str, Any] = {}
    params = inspect.signature(fn).parameters
    if "offline" in params:
        kwargs["offline"] = body.offline
    if "root" in params:
        kwargs["root"] = str(repo_root())
    t0 = time.time()
    try:
        res = fn(**kwargs)
    except Exception as e:  # noqa: BLE001
        return {"markdown": "", "result": None, "warnings": [f"benchmark failed: {type(e).__name__}: {e}"]}
    md, result = _split_bench(res, mod)
    payload = {"markdown": md, "result": _jsonable(result), "elapsed_s": round(time.time() - t0, 2),
               "ts": time.time(), "warnings": []}
    try:
        (work_dir() / "benchmark.json").write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
    except OSError:
        pass
    return payload


def _split_bench(res: Any, mod: Any):
    md = ""
    result = res
    if isinstance(res, tuple) and len(res) == 2:
        a, b = res
        md, result = (a, b) if isinstance(a, str) else (b, a)
    elif isinstance(res, str):
        md, result = res, None
    elif isinstance(res, dict):
        md = res.get("markdown") or res.get("md") or ""
    if hasattr(result, "model_dump"):
        result = result.model_dump(mode="json")
    if not md:
        for name in ("to_markdown", "render_markdown", "markdown_table", "format_markdown"):
            f = getattr(mod, name, None)
            if callable(f):
                try:
                    md = f(res if not isinstance(res, tuple) else result)
                    break
                except Exception:  # noqa: BLE001
                    continue
    return md or "", result


@app.get("/api/benchmark/last")
def benchmark_last():
    for p in (work_dir() / "benchmark.json", PROJECT_ROOT / ".barakagate" / "benchmark.json"):
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "markdown" not in data:
                    md = ""
                    try:
                        md, _ = _split_bench(data, _import_benchmark())
                    except Exception:  # noqa: BLE001
                        pass
                    data = {"markdown": md, "result": data}
                return data
            except (OSError, json.JSONDecodeError):
                continue
    return {"markdown": "", "result": None}
