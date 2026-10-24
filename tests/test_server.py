"""Offline tests for the BarakaGate Studio FastAPI backend."""
import importlib.util
import shutil
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HAS_SCANNER = importlib.util.find_spec("barakagate.scanner") is not None
HAS_REDACTOR = importlib.util.find_spec("barakagate.redactor") is not None
needs_scanner = pytest.mark.skipif(not HAS_SCANNER, reason="barakagate.scanner not built yet")
needs_redactor = pytest.mark.skipif(not HAS_REDACTOR, reason="barakagate.redactor not built yet")


@pytest.fixture
def client(monkeypatch, tmp_path):
    from barakagate import server

    monkeypatch.setenv("BARAKAGATE_ROOT", str(tmp_path))
    server.STATE.reset()
    server.STATE.routers.clear()
    server.STATE.scans.clear()
    yield TestClient(server.app)
    server.STATE.reset()
    server.STATE.routers.clear()


def test_index_html_served(client):
    r = client.get("/")
    assert r.status_code == 200
    html = r.text
    assert 'id="engineMode"' in html and 'id="domainPreset"' in html
    for tab in ("tab-code", "tab-image", "tab-firewall", "tab-policy"):
        assert f'data-tab="{tab}"' in html and f'id="{tab}"' in html
    for label in ("[Load Moroccan Fintech Checkout PR]", "[Load Research Lab Notebook &amp; Pipeline]",
                  "[Load General DevSecOps API]", "[Scan Live Git Staged Diff]"):
        assert label in html


def test_status(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    s = r.json()
    assert s["version"]
    assert s["engines"] == {"cloud": False, "ollama": False}
    assert set(s["index"]) >= {"chunks", "symbols", "files"}
    assert s["models"]["cloud_fast"] == "gemma-4-26b-a4b-it"
    assert any(p["value"] == "fintech_morocco" for p in s["presets"])


def test_samples(client):
    r = client.get("/api/samples")
    assert {x["name"] for x in r.json()} == {"fintech_morocco", "research_lab_um6p", "general_devsecops"}
    s = client.get("/api/samples/fintech_morocco").json()
    assert s["target_file"] == "checkout.py"
    assert "checkout.py" in s["files"] and "MoroccanCustomer" in s["files"]["models.py"]
    assert client.get("/api/samples/../../etc").status_code == 404
    assert client.get("/api/samples/nope").status_code == 404


@needs_redactor
def test_sanitize_roundtrip(client):
    raw = "client CIN BE847291 RIB 230780123456789012345678 url https://hpc-staging.internal.um6p.ma/api/v1"
    r = client.post("/api/sanitize", json={"text": raw})
    assert r.status_code == 200
    body = r.json()
    for secret in ("BE847291", "230780123456789012345678"):
        assert secret not in body["sanitized"]
    assert body["vault"]
    from barakagate.redactor import rehydrate

    assert rehydrate(body["sanitized"], body["vault"]) == raw


@needs_redactor
def test_firewall_refuses_raw_values_and_answers_offline(client):
    vault = {"[CIN_TOKEN_1]": "BE847291"}
    bad = client.post("/api/firewall/ask", json={"sanitized_prompt": "fix BE847291 please", "vault": vault})
    assert bad.status_code == 400
    ok = client.post("/api/firewall/ask", json={"sanitized_prompt": "why is [CIN_TOKEN_1] off by 1 centime?",
                                                "vault": vault})
    assert ok.status_code == 200
    d = ok.json()
    assert d["engine"] == "offline_template"
    assert "[CIN_TOKEN_1]" in d["raw_answer"] and "BE847291" not in d["raw_answer"]
    assert "BE847291" in d["rehydrated_answer"]
    assert d["pii_bytes_sent"] == 0


def test_policy_get_and_invalid_put(client, tmp_path):
    g = client.get("/api/policy")
    assert g.status_code == 200 and "presets" in g.json()["yaml"]
    real = (ROOT / ".barakagate.yaml").read_text(encoding="utf-8")
    for bad in ("presets: [unclosed", "just_a_string", "presets:\n  x:\n    regex_rules:\n      - id: a\n        pattern: '(['\n"):
        r = client.put("/api/policy", json={"yaml": bad})
        assert r.status_code == 400, bad
    assert not (tmp_path / ".barakagate.yaml").exists()
    assert (ROOT / ".barakagate.yaml").read_text(encoding="utf-8") == real
    good = client.put("/api/policy", json={"yaml": real})
    assert good.status_code == 200 and (tmp_path / ".barakagate.yaml").read_text(encoding="utf-8") == real


def test_image_path_traversal_rejected(client, tmp_path):
    for bad in ("../../../etc/passwd", "/etc/passwd", "samples/../../../../etc/hostname", "../x.png"):
        r = client.get("/api/images/file", params={"path": bad})
        assert r.status_code in (400, 404), bad
        assert r.status_code == 400 or "root" not in r.text
    (tmp_path / "pic.png").write_bytes(b"not really")
    assert client.get("/api/images/file", params={"path": "pic.png"}).status_code == 200
    (tmp_path / "secret.txt").write_text("x")
    assert client.get("/api/images/file", params={"path": "secret.txt"}).status_code == 400


def test_images_list(client):
    r = client.get("/api/images")
    assert r.status_code == 200
    names = [i["name"] for i in r.json()]
    if (ROOT / "samples" / "screenshots" / "devtools_leak.png").exists():
        assert "devtools_leak.png" in names
    for it in r.json():
        assert client.get(it["url"]).status_code == 200


@needs_redactor
def test_image_redact_returns_png(client):
    shot = ROOT / "samples" / "screenshots" / "devtools_leak.png"
    if not shot.exists():
        pytest.skip("sample screenshot missing")
    r = client.post("/api/image/redact", json={"path": str(shot), "boxes": [[100, 100, 300, 500]], "style": "solid_mask"})
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert r.content[:8] == b"\x89PNG\r\n\x1a\n"


@needs_scanner
def test_scan_scenario_offline_blocks_with_context(client):
    r = client.post("/api/scan", json={"scenario": "fintech_morocco", "mode": "cloud_fast", "preset": "all", "offline": True})
    assert r.status_code == 200
    d = r.json()
    assert d["verdict"] == "BLOCK"
    assert d["findings"] and d["scan_id"]
    assert "checkout.py" in d["files"]
    assert d["context"], "cross-file context chunks expected"
    assert all({"file_path", "symbol_name", "start_line", "end_line", "code"} <= set(c) for c in d["context"])
    assert any("models.py" in c["file_path"] for c in d["context"])
    assert d["scoreboard"]["regex_caught"] <= d["scoreboard"]["gemma_caught"]


@needs_scanner
def test_scan_text_offline(client):
    r = client.post("/api/scan", json={"text": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', "file_path": "x.py", "offline": True})
    assert r.status_code == 200
    assert r.json()["findings"]


@needs_scanner
@needs_redactor
def test_preview_and_apply_writes_safe_copy(client, tmp_path):
    d = client.post("/api/scan", json={"scenario": "fintech_morocco", "offline": True}).json()
    original = (ROOT / "samples" / "fintech_morocco" / "checkout.py").read_text(encoding="utf-8")
    pv = client.post("/api/preview", json={"scan_id": d["scan_id"], "decisions": {}})
    assert pv.status_code == 200
    files = pv.json()["files"]
    assert "checkout.py" in files
    assert files["checkout.py"]["original"] == original
    assert files["checkout.py"]["patched"] != original and files["checkout.py"]["diff"]
    ap = client.post("/api/apply", json={"scan_id": d["scan_id"], "decisions": {}})
    assert ap.status_code == 200
    written = ap.json()["written"]
    assert written
    out = Path(written[0]["path"])
    assert out.is_relative_to(tmp_path / ".barakagate" / "patched" / "fintech_morocco")
    assert out.read_text(encoding="utf-8") != original
    # the sample fixture itself is untouched
    assert (ROOT / "samples" / "fintech_morocco" / "checkout.py").read_text(encoding="utf-8") == original


def test_unknown_scan_id(client):
    assert client.post("/api/preview", json={"scan_id": "nope", "decisions": {}}).status_code == 404


def test_benchmark_last(client):
    r = client.get("/api/benchmark/last")
    assert r.status_code == 200 and "markdown" in r.json()
