"""Verify BarakaGate against the build plan + CLAUDE.md spec, end to end.

    python3 scripts/verify_plan.py            # offline checks only (no network)
    python3 scripts/verify_plan.py --live     # + live Gemma 4 checks (needs GEMINI_API_KEY)

Writes docs/VERIFICATION.md with a PASS/FAIL row per check.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS: list[tuple[str, str, bool, str]] = []  # (section, check, ok, detail)


def check(section: str, name: str):
    def deco(fn):
        def run():
            t = time.time()
            try:
                detail = fn() or ""
                ok = True
            except Exception as e:  # noqa: BLE001
                ok, detail = False, f"{type(e).__name__}: {e}"
                if os.environ.get("VERIFY_DEBUG"):
                    traceback.print_exc()
            detail = f"{detail} ({time.time() - t:.1f}s)".strip()
            RESULTS.append((section, name, ok, detail))
            print(f"[{'PASS' if ok else 'FAIL'}] {section} :: {name} — {detail}", flush=True)
        run.__name__ = fn.__name__
        return run
    return deco


def sh(cmd: list[str], cwd: Path = ROOT, env: dict | None = None, timeout: int = 600) -> subprocess.CompletedProcess:
    e = {**os.environ, "PYTHONPATH": str(ROOT), **(env or {})}
    return subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)


def copy_samples(tmp: Path) -> Path:
    dst = tmp / "samples"
    shutil.copytree(ROOT / "samples", dst, ignore=shutil.ignore_patterns(".barakagate"))
    shutil.copy(ROOT / ".barakagate.yaml", tmp / ".barakagate.yaml")
    return dst


# --------------------------------------------------------------------------- structure & contract
@check("Spec §2", "Directory structure matches spec")
def c_structure():
    req = ["LICENSE", "README.md", "pyproject.toml", "requirements.txt", ".barakagate.yaml",
           ".github/workflows/barakagate.yml", "skills/barakagate/SKILL.md", "barakagate/__init__.py",
           "barakagate/models.py", "barakagate/config.py", "barakagate/llm_router.py", "barakagate/indexer.py",
           "barakagate/scanner.py", "barakagate/redactor.py", "barakagate/cli.py", "barakagate/server.py",
           "barakagate/static/index.html", "samples/fintech_morocco", "samples/research_lab_um6p",
           "samples/general_devsecops", "samples/screenshots/devtools_leak.png", "evaluate_benchmark.py",
           "samples/generate_sample_screenshots.py"]
    missing = [p for p in req if not (ROOT / p).exists()]
    assert not missing, f"missing: {missing}"
    lic = (ROOT / "LICENSE").read_text()
    assert lic.startswith("MIT License"), "LICENSE is not MIT"
    return f"{len(req)} required paths present, MIT license"


@check("Spec §3", "models.py contains the spec contract verbatim")
def c_models():
    spec = (ROOT / "CLAUDE.md").read_text()
    block = spec.split("## 3. Shared Data Contract", 1)[1].split("```python", 1)[1].split("```", 1)[0].strip()
    assert block in (ROOT / "barakagate/models.py").read_text(), "spec block not found verbatim in models.py"
    return f"{len(block.splitlines())} spec lines matched exactly"


@check("Pitfall 1", "Only the new google-genai SDK is used")
def c_sdk():
    bad = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.py")
           if ".barakagate" not in p.parts and p.name != "verify_plan.py"
           and re.search(r"^\s*(import|from)\s+google\.generativeai", p.read_text(errors="ignore"), re.M)]
    assert not bad, f"deprecated SDK in {bad}"
    assert "from google import genai" in (ROOT / "barakagate/llm_router.py").read_text()
    return "no google.generativeai imports; router uses `from google import genai`"


@check("Plan", "Full pytest suite green (offline, mocked LLMs)")
def c_pytest():
    r = sh([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], timeout=900)
    tail = (r.stdout.strip().splitlines() or ["?"])[-1]
    assert r.returncode == 0, tail
    return tail


# --------------------------------------------------------------------------- router
@check("Spec §5 / Pitfall 3", "Router fallback chains per engine mode")
def c_chain():
    from barakagate.llm_router import GemmaRouter
    from barakagate.models import EngineMode as M
    r = GemmaRouter.__new__(GemmaRouter)
    ch = {m.value: GemmaRouter.engine_chain(r, m) for m in M}
    assert ch["cloud_fast"][:3] == [("gemini", "gemma-4-26b-a4b-it"), ("gemini", "gemma-4-31b-it"), ("ollama", "gemma4:e4b")]
    assert ch["cloud_deep"][0] == ("gemini", "gemma-4-31b-it")
    assert ch["local_edge"] == [("ollama", "gemma4:e4b")], "local_edge must never leave the machine"
    assert ch["hybrid_smart"][0] == ("gemini", "gemma-4-31b-it")
    return "26b→31b→e4b→demo cache; local_edge is Ollama-only"


@check("Pitfall 2 / 6", "Ollama payload: num_ctx 8192, flat 'json' format for images")
def c_ollama():
    from barakagate import llm_router
    sent = []

    class R:
        def raise_for_status(self): pass
        def json(self): return {"message": {"content": '{"findings": []}'}}

    class C:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def post(self, url, json): sent.append(json); return R()

    orig = llm_router.httpx.Client
    llm_router.httpx.Client = C
    try:
        with tempfile.TemporaryDirectory() as td:
            img = Path(td) / "x.png"; img.write_bytes(b"\x89PNG")
            r = llm_router.GemmaRouter(cache_path=Path(td) / "c.json")
            r.call_local_ollama("p", "s", [], {"type": "object"})
            r.call_local_ollama("p", "s", [str(img)], {"type": "object"})
    finally:
        llm_router.httpx.Client = orig
    assert sent[0]["options"]["num_ctx"] == 8192 and sent[0]["format"] == {"type": "object"}
    assert sent[1]["format"] == "json" and sent[1]["messages"][1]["images"]
    return "structured schema for text, format='json' + schema-in-prompt for vision"


# --------------------------------------------------------------------------- indexer
@check("Spec §4", "Indexer: cross-file symbol resolution + engine token budgets")
def c_indexer():
    from barakagate.indexer import CodebaseIndexer
    from barakagate.models import EngineMode as M
    with tempfile.TemporaryDirectory() as td:
        s = copy_samples(Path(td)) / "fintech_morocco"
        ix = CodebaseIndexer(s); st = ix.build()
        text = (s / "checkout.py").read_text()
        cloud = ix.get_context_for_target(text, ["checkout.py"], M.CLOUD_FAST)
        local = ix.get_context_for_target(text, ["checkout.py"], M.LOCAL_EDGE)
        labels = [f"{Path(c.file_path).name}:{c.symbol_name}" for c in cloud]
        assert "models.py:MoroccanCustomer" in labels and "models.py:CMI_WEBHOOK_SECRET" in labels, labels
        assert all(Path(c.file_path).name != "checkout.py" for c in cloud), "target file leaked into context"
        assert len(cloud) <= 15 and len(local) <= 3 and sum(len(c.code) for c in local) <= 2500
        st2 = ix.build()
        assert st2.files_reused >= 1, "incremental sha256 reuse not working"
    return f"{st.chunks} chunks/{st.symbols} symbols; cloud ctx={len(cloud)} (≤15), local ctx={len(local)} (≤3, ≤2500 chars); sha256 reuse ok"


# --------------------------------------------------------------------------- scanner / CLI offline
@check("Plan verification", "Offline scans: every scenario → BLOCK with leaks + logic bugs + cross-file proofs")
def c_offline_scans():
    from barakagate.models import FindingCategory as C
    from barakagate.scanner import Scanner
    out = []
    with tempfile.TemporaryDirectory() as td:
        s = copy_samples(Path(td))
        for scen, files in [("fintech_morocco", ["checkout.py"]), ("research_lab_um6p", ["train_pipeline.py", "loader.py"]),
                            ("general_devsecops", ["api.py", "settings.py"])]:
            r = Scanner(s / scen, offline=True).scan_files([str(s / scen / f) for f in files])
            leaks = sum(f.category != C.LOGICAL_BUG for f in r.findings)
            bugs = sum(f.category == C.LOGICAL_BUG for f in r.findings)
            xf = sum(bool(f.cross_file_context_used) for f in r.findings)
            assert r.verdict == "BLOCK" and leaks >= 2 and bugs >= 2 and xf >= 1, (scen, r.verdict, leaks, bugs, xf)
            out.append(f"{scen}: {leaks} leaks/{bugs} bugs/{xf} x-file")
    return "; ".join(out)


@check("Plan verification", "CLI `scan --offline` with no API key still blocks (exit 1, JSON output)")
def c_cli_offline():
    with tempfile.TemporaryDirectory() as td:
        s = copy_samples(Path(td))
        r = sh([sys.executable, "-m", "barakagate", "scan", "fintech_morocco/checkout.py", "--root", "fintech_morocco",
                "--offline", "--json"], cwd=s, env={"GEMINI_API_KEY": ""})
        assert r.returncode == 1, f"exit {r.returncode}: {r.stderr[-300:]}"
        data = json.loads(r.stdout[r.stdout.index("{"):])
        assert data["verdict"] == "BLOCK" and data["findings"]
    return f"verdict BLOCK, {len(data['findings'])} findings, engine={data['engine_used']}"


@check("Pitfall 5", "Applying all fixes: patched file parses and re-scan is clean of heuristics")
def c_apply_all():
    import ast
    from barakagate.redactor import apply_text_fixes
    from barakagate.scanner import Scanner
    with tempfile.TemporaryDirectory() as td:
        s = copy_samples(Path(td)) / "fintech_morocco"
        sc = Scanner(s, offline=True)
        r = sc.scan_files([str(s / "checkout.py")])
        src = (s / "checkout.py").read_text()
        patched = apply_text_fixes(src, r.findings, {f.id: f.recommended_action.value for f in r.findings})
        ast.parse(patched)
        (s / "checkout.py").write_text(patched)
        r2 = Scanner(s, offline=True).scan_files([str(s / "checkout.py")])
        left = [f.rule_id for f in r2.findings if f.rule_id.startswith("heur.")]
        assert not left, f"heuristics still fire after patching: {left}"
    return f"{len(r.findings)} fixes applied in one pass; valid Python; 0 heuristic findings on re-scan (verdict now {r2.verdict})"


@check("Pitfall 4", "bbox [ymin,xmin,ymax,xmax]/1000 → pixels with padding; blur changes only the box")
def c_bbox():
    from PIL import Image, ImageChops
    from barakagate.redactor import bbox_to_pixels, redact_image
    x1, y1, x2, y2 = bbox_to_pixels([100, 200, 300, 400], 1000, 500)
    assert x1 < 200 and x2 > 400 and y1 < 50 and y2 > 150, (x1, y1, x2, y2)
    with tempfile.TemporaryDirectory() as td:
        src = ROOT / "samples/screenshots/devtools_leak.png"
        boxes = [b["bbox_2d"] for b in json.loads(Path(str(src) + ".boxes.json").read_text())]
        out = redact_image(str(src), boxes, "gaussian_blur", str(Path(td) / "o.png"))
        a, b = Image.open(src).convert("RGB"), Image.open(out).convert("RGB")
        diff = ImageChops.difference(a, b).getbbox()
        assert diff is not None, "image unchanged"
        w, h = a.size
        corner = ImageChops.difference(a.crop((0, h - 40, 200, h)), b.crop((0, h - 40, 200, h))).getbbox()
        assert corner is None, "pixels outside boxes changed"
    return f"{len(boxes)} boxes blurred; pixels outside boxes untouched"


@check("Plan verification", "Pre-commit hook blocks a staged CIN/RIB, allows a clean commit")
def c_hook():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        g = lambda *a: subprocess.run(["git", *a], cwd=repo, capture_output=True, text=True,
                                      env={**os.environ, "PYTHONPATH": str(ROOT), "GEMINI_API_KEY": ""})
        g("init", "-q"); g("config", "user.email", "t@t"); g("config", "user.name", "t")
        shutil.copy(ROOT / ".barakagate.yaml", repo)
        r = sh([sys.executable, "-m", "barakagate", "install-hook", "--root", "."], cwd=repo)
        assert r.returncode == 0 and os.access(repo / ".git/hooks/pre-commit", os.X_OK)
        (repo / "ok.py").write_text('print("hello")\n'); g("add", "."); ok = g("commit", "-qm", "clean")
        (repo / "leak.py").write_text('CLIENT = {"cin": "BE847291", "rib": "230780123456789012345678"}\n')
        g("add", "leak.py"); bad = g("commit", "-qm", "leak")
        log = g("log", "--oneline").stdout.strip().splitlines()
        assert ok.returncode == 0 and bad.returncode != 0 and len(log) == 1, (ok.returncode, bad.returncode, log)
    return "clean commit accepted, PII commit rejected"


@check("Spec §7", "Studio: all spec labels + every REST endpoint answers (offline)")
def c_server():
    from fastapi.testclient import TestClient
    os.environ["BARAKAGATE_ROOT"] = str(ROOT)
    import barakagate.server as srv
    c = TestClient(srv.app)
    html = c.get("/").text
    labels = ["engineMode", "domainPreset", "Cloud Fast: gemma-4-26b-a4b-it (Gemini API MoE)",
              "Cloud Deep: gemma-4-31b-it (Gemini API 256K)", "Local Air-Gapped: gemma4:e4b (Laptop Ollama)",
              "Hybrid Smart Router (Local gemma4:e4b Redact → Cloud gemma-4-31b-it Bug Audit)",
              "Load Moroccan Fintech Checkout PR", "Load Research Lab Notebook &amp; Pipeline",
              "Load General DevSecOps API", "Scan Live Git Staged Diff", "Re-Index Codebase",
              "Swap Synthetic Twin", "Extract to .env", "Hard Mask", "Keep / Whitelist", "Apply Bug Fix Patch",
              "Keep Original (Ignore)", "Preview Combined Patched File", "Apply Selected Fixes to Disk",
              "Run Gemma 4 Vision Scan", "Sanitize with Local gemma4:e4b", "Save Policy", "Run Full Benchmark Suite"]
    missing = [l for l in labels if l not in html]
    assert not missing, f"UI labels missing: {missing}"
    assert c.get("/api/status").status_code == 200
    assert c.get("/api/samples/fintech_morocco").status_code == 200
    scan = c.post("/api/scan", json={"scenario": "fintech_morocco", "offline": True}).json()
    assert scan["verdict"] == "BLOCK", scan.get("verdict")
    dec = {f["id"]: f["recommended_action"] for f in scan["findings"]}
    assert c.post("/api/preview", json={"scan_id": scan["scan_id"], "decisions": dec}).status_code == 200
    ap = c.post("/api/apply", json={"scan_id": scan["scan_id"], "decisions": dec})
    assert ap.status_code == 200 and ".barakagate" in json.dumps(ap.json()), "apply must not overwrite fixtures"
    imgs = c.get("/api/images").json()
    assert c.post("/api/image/scan", json={"path": "samples/screenshots/devtools_leak.png", "offline": True}).status_code == 200
    red = c.post("/api/image/redact", json={"path": "samples/screenshots/devtools_leak.png",
                                            "boxes": [[100, 100, 200, 300]], "style": "solid_mask"})
    assert red.status_code == 200 and red.headers["content-type"].startswith("image/png")
    san = c.post("/api/sanitize", json={"text": "CIN BE847291 RIB 230780123456789012345678"}).json()
    assert "BE847291" not in san["sanitized"]
    bad = c.post("/api/firewall/ask", json={"sanitized_prompt": "BE847291", "vault": san["vault"], "offline": True})
    assert bad.status_code == 400, "firewall must refuse raw PII"
    assert c.get("/api/policy").status_code == 200
    assert c.put("/api/policy", json={"yaml": "not: [valid"}).status_code == 400
    assert c.get("/api/images/file", params={"path": "../../etc/passwd"}).status_code in (400, 403, 404)
    return f"{len(labels)} spec labels present; scan/preview/apply/image/redact/sanitize/firewall/policy OK; {len(imgs) if isinstance(imgs, list) else len(imgs.get('images', []))} images listed"


@check("Case 01", "Agent Skill manifest + CI workflow are well-formed")
def c_skill_ci():
    import yaml
    sk = (ROOT / "skills/barakagate/SKILL.md").read_text()
    fm = yaml.safe_load(sk.split("---", 2)[1])
    assert fm.get("name") == "barakagate" and len(fm.get("description", "")) > 40
    wf = yaml.safe_load((ROOT / ".github/workflows/barakagate.yml").read_text())
    assert "jobs" in wf and "barakagate" in json.dumps(wf)
    return f"SKILL.md name={fm['name']}; workflow jobs={list(wf['jobs'])}"


# --------------------------------------------------------------------------- live
LIVE: list = []


def live(fn):
    LIVE.append(fn)
    return fn


@live
@check("Live / Plan verification", "cloud_fast fintech scan → real Gemma 4 BLOCK with ≥2 leaks, ≥2 bugs, MoroccanCustomer proof")
def l_fintech():
    from barakagate.models import EngineMode, FindingCategory as C
    from barakagate.scanner import Scanner
    s = ROOT / "samples/fintech_morocco"
    r = None
    for _ in range(3):
        r = Scanner(s).scan_files([str(s / "checkout.py")], EngineMode.CLOUD_FAST, "fintech_morocco")
        if r.engine_used.startswith("gemini"):
            break
        time.sleep(10)
    assert r.engine_used.startswith("gemini"), f"no live answer: {r.engine_used}"
    leaks = sum(f.category != C.LOGICAL_BUG for f in r.findings)
    bugs = sum(f.category == C.LOGICAL_BUG for f in r.findings)
    proofs = {f.cross_file_context_used for f in r.findings if f.cross_file_context_used}
    assert r.verdict == "BLOCK" and leaks >= 2 and bugs >= 2, (r.verdict, leaks, bugs)
    assert any("MoroccanCustomer" in p for p in proofs), proofs
    return f"{r.engine_used}: {leaks} leaks, {bugs} bugs, proofs={sorted(proofs)}"


@live
@check("Live / Phase C", "Research + DevSecOps scenarios scanned live (populates demo_cache.json)")
def l_other():
    from barakagate.models import EngineMode
    from barakagate.scanner import Scanner
    out = []
    for scen, files, preset in [("research_lab_um6p", ["train_pipeline.py", "loader.py"], "research_lab"),
                                ("general_devsecops", ["api.py", "settings.py"], "general_devsecops")]:
        s = ROOT / "samples" / scen
        r = Scanner(s).scan_files([str(s / f) for f in files], EngineMode.CLOUD_FAST, preset)
        out.append(f"{scen}: {r.engine_used} {r.verdict} {len(r.findings)} findings")
        assert r.verdict == "BLOCK"
    return "; ".join(out)


@live
@check("Live / Spec §7 Tab 2", "Real Gemma 4 vision on devtools_leak.png (sidecar hidden) → boxes on the secrets")
def l_vision():
    from barakagate.models import EngineMode
    from barakagate.scanner import Scanner
    with tempfile.TemporaryDirectory() as td:
        img = Path(td) / "devtools_leak.png"
        shutil.copy(ROOT / "samples/screenshots/devtools_leak.png", img)  # no .boxes.json next to it
        truth = json.loads((ROOT / "samples/screenshots/devtools_leak.png.boxes.json").read_text())
        r = None
        for _ in range(3):
            r = Scanner(td).scan_image(str(img), EngineMode.CLOUD_FAST)
            if r.engine_used.startswith("gemini"):
                break
            time.sleep(10)
        assert r.engine_used.startswith("gemini"), r.engine_used
        boxes = [f.bbox_2d for f in r.findings if f.bbox_2d]

        def iou(a, b):
            y1, x1, y2, x2 = max(a[0], b[0]), max(a[1], b[1]), min(a[2], b[2]), min(a[3], b[3])
            inter = max(0, y2 - y1) * max(0, x2 - x1)
            area = lambda q: (q[2] - q[0]) * (q[3] - q[1])
            return inter / (area(a) + area(b) - inter + 1e-9)
        hit = sum(any(iou(t["bbox_2d"], b) > 0.2 for b in boxes) for t in truth)
        assert hit >= 3, f"only {hit}/{len(truth)} secrets localized; boxes={boxes}"
    return f"{r.engine_used}: {hit}/{len(truth)} ground-truth secrets localized (IoU>0.2)"


@live
@check("Live / Spec §1.4", "hybrid_smart: no raw CIN/RIB/phone/CMI key reaches the cloud prompt")
def l_hybrid():
    from barakagate.llm_router import GemmaRouter
    from barakagate.models import EngineMode
    from barakagate.scanner import Scanner
    sent = []
    router = GemmaRouter()
    orig = router.analyze

    def spy(mode, prompt, *a, **k):
        sent.append(prompt)
        return orig(mode, prompt, *a, **k)
    router.analyze = spy
    s = ROOT / "samples/fintech_morocco"
    r = Scanner(s, router=router).scan_files([str(s / "checkout.py")], EngineMode.HYBRID_SMART, "fintech_morocco")
    raw = ["BE847291", "230780123456789012345678", "+212661234567", "cmi_live_sk_9988776655443322"]
    assert sent, "cloud was never called"
    leaked = [v for v in raw if any(v in p for p in sent)]
    assert not leaked, f"raw PII sent to cloud: {leaked}"
    rehydrated = any("BE847291" in (f.offending_snippet or "") for f in r.findings)
    return f"{r.engine_used}; {len(sent[0])} sanitized chars sent, 0 raw values; findings rehydrated locally={rehydrated}"


@live
@check("Live / Pitfall 3", "Demo-cache fallback: same scan with cloud+Ollama down is served from cache")
def l_cache():
    from barakagate.llm_router import GemmaRouter
    from barakagate.models import EngineMode
    from barakagate.scanner import Scanner
    s = ROOT / "samples/fintech_morocco"
    key = os.environ.pop("GEMINI_API_KEY", None)
    try:
        dead = GemmaRouter(ollama_url="http://127.0.0.1:9")
        dead.gemini_client = None
        r = Scanner(s, router=dead).scan_files([str(s / "checkout.py")], EngineMode.CLOUD_FAST, "fintech_morocco")
    finally:
        if key:
            os.environ["GEMINI_API_KEY"] = key
    assert r.engine_used.startswith("cache:"), r.engine_used
    return f"engine_used={r.engine_used}, verdict {r.verdict}, {len(r.findings)} findings"


def write_report(live_mode: bool) -> Path:
    passed = sum(ok for *_, ok, _ in [(a, b, c, d) for a, b, c, d in RESULTS])
    lines = ["# BarakaGate — Plan & Spec Verification", "",
             f"Generated by `python3 scripts/verify_plan.py{' --live' if live_mode else ''}` on "
             f"{time.strftime('%Y-%m-%d %H:%M')} — **{passed}/{len(RESULTS)} checks passed**.", "",
             "| # | Area | Check | Result | Evidence |", "| :-: | :--- | :--- | :-: | :--- |"]
    for i, (sec, name, ok, det) in enumerate(RESULTS, 1):
        lines.append(f"| {i} | {sec} | {name} | {'✅ PASS' if ok else '❌ FAIL'} | {det.replace('|', '/')} |")
    out = ROOT / "docs" / "VERIFICATION.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="also run live Gemma 4 checks")
    args = ap.parse_args()
    from barakagate.config import load_dotenv
    load_dotenv()
    for fn in [c_structure, c_models, c_sdk, c_pytest, c_chain, c_ollama, c_indexer, c_offline_scans,
               c_cli_offline, c_apply_all, c_bbox, c_hook, c_server, c_skill_ci]:
        fn()
    if args.live:
        for fn in LIVE:
            fn()
    out = write_report(args.live)
    failed = [r for r in RESULTS if not r[2]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed → {out.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
