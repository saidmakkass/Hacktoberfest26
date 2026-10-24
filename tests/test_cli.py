import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from barakagate.cli import app

ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


def test_sanitize_stdin_json():
    prompt = "salam, CIN BE847291 w RIB 230780123456789012345678, host https://gpu01.internal.um6p.ma/x\n"
    res = runner.invoke(app, ["sanitize", "-", "--json"], input=prompt)
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert "BE847291" not in data["sanitized"] and "[CIN_TOKEN_1]" in data["sanitized"]
    assert data["vault"]["[RIB_TOKEN_1]"] == "230780123456789012345678"


def test_sanitize_stdin_rich_table():
    res = runner.invoke(app, ["sanitize", "-"], input="call +212661234567\n")
    assert res.exit_code == 0
    assert "[PHONE_TOKEN_1]" in res.stdout and "+212661234567" in res.stdout  # vault shown locally


@pytest.fixture
def fintech(tmp_path):
    dst = tmp_path / "fintech_morocco"
    shutil.copytree(ROOT / "samples" / "fintech_morocco", dst)
    return dst


def test_scan_offline_json_blocks(fintech, monkeypatch):
    monkeypatch.chdir(fintech)
    res = runner.invoke(app, ["scan", str(fintech / "checkout.py"), "--offline", "--json", "--root", str(fintech)])
    assert res.exit_code == 1, res.output
    data = json.loads(res.stdout)
    assert data["verdict"] == "BLOCK"
    assert any("BE847291" in (f.get("offending_snippet") or "") or f["rule_id"] == "ma.cin" for f in data["findings"])


def test_scan_rich_output_and_yes_fix(fintech, monkeypatch):
    monkeypatch.chdir(fintech)
    res = runner.invoke(app, ["scan", "checkout.py", "--offline", "--root", str(fintech)])
    assert res.exit_code == 1
    assert "BarakaGate v1.0" in res.stdout and "BLOCK" in res.stdout and "Regex baseline:" in res.stdout
    res = runner.invoke(app, ["scan", "checkout.py", "--offline", "--yes", "--root", str(fintech)])
    patched = (fintech / "checkout.py").read_text()
    assert "BE847291" not in patched
    compile(patched, "checkout.py", "exec")
    assert list((fintech / ".barakagate" / "backups").glob("checkout.py.*.bak"))


def test_install_hook(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    hooks = tmp_path / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho old\n")
    res = runner.invoke(app, ["install-hook", "--root", str(tmp_path)])
    assert res.exit_code == 0, res.output
    hook = hooks / "pre-commit"
    assert "barakagate staged" in hook.read_text()
    assert os.access(hook, os.X_OK)
    assert (hooks / "pre-commit.bak").read_text() == "#!/bin/sh\necho old\n"


def test_install_hook_not_a_repo(tmp_path):
    assert runner.invoke(app, ["install-hook", "--root", str(tmp_path)]).exit_code == 2


@pytest.mark.parametrize("style", ["gaussian_blur", "solid_mask"])
def test_image_apply_writes_output(tmp_path, style):
    shots = ROOT / "samples" / "screenshots"
    if not (shots / "devtools_leak.png").exists():
        subprocess.run(["python3", str(ROOT / "samples" / "generate_sample_screenshots.py")], check=True)
    src = tmp_path / "devtools_leak.png"
    shutil.copy(shots / "devtools_leak.png", src)
    shutil.copy(shots / "devtools_leak.png.boxes.json", tmp_path / "devtools_leak.png.boxes.json")
    out = tmp_path / "out.png"
    res = runner.invoke(app, ["image", str(src), "--apply", "--offline", "--style", style,
                              "--out", str(out), "--root", str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert out.is_file() and out.read_bytes() != src.read_bytes()
