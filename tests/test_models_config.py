import pytest
from pydantic import ValidationError

from plutonium.config import load_config, validate_yaml, load_dotenv
from plutonium.models import ActionType, Finding, FindingCategory, ScanResult, Severity


def test_finding_confidence_bounds():
    kw = dict(id="f1", category=FindingCategory.PRIVACY_PII, target_type="text", file_path="a.py",
              rule_id="ma.cin", severity=Severity.HIGH, title="t", reason="r",
              recommended_action=ActionType.SYNTHETIC_TWIN)
    assert Finding(confidence=0.5, **kw).confidence == 0.5
    with pytest.raises(ValidationError):
        Finding(confidence=1.5, **kw)


def test_scanresult_roundtrip():
    r = ScanResult(verdict="PASS", engine_used="x", preset_used="all", summary="ok")
    assert ScanResult.model_validate_json(r.model_dump_json()) == r


def test_config_presets_and_rules(project_root):
    cfg = load_config(project_root)
    assert set(cfg.preset_names("all")) == {"general_devsecops", "fintech_morocco", "research_lab"}
    ids = {r.id for r in cfg.regex_rules("fintech_morocco")}
    assert {"ma.cin", "ma.rib", "ma.phone", "ma.cmi_key"} <= ids
    rib = next(r for r in cfg.regex_rules("fintech_morocco") if r.id == "ma.rib")
    assert rib.compiled.search('"rib": "230780123456789012345678"')
    cin = next(r for r in cfg.regex_rules("fintech_morocco") if r.id == "ma.cin")
    assert cin.compiled.search("cin BE847291 ok")
    cne = next(r for r in cfg.regex_rules("research_lab") if r.id == "lab.cne")
    assert cne.compiled.search("R139482710")
    assert cfg.nl_rules("research_lab")
    assert cfg.is_allowlisted("[SYNTH_CIN_1]")


def test_validate_yaml_rejects_bad_regex():
    with pytest.raises(ValueError):
        validate_yaml("presets:\n  x:\n    regex_rules:\n      - id: bad\n        pattern: '(['\n")
    with pytest.raises(ValueError):
        validate_yaml("just: text")


def test_load_dotenv(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# c\nexport FOO_BG=bar\nQ='x y'\n")
    monkeypatch.delenv("FOO_BG", raising=False)
    loaded = load_dotenv(env)
    assert loaded == {"FOO_BG": "bar", "Q": "x y"}
