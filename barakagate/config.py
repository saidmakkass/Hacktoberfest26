"""Policy-as-Code loader for `.barakagate.yaml` plus a tiny `.env` loader."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from barakagate.models import DomainPreset

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
CONFIG_FILENAME = ".barakagate.yaml"

DEFAULT_MODELS = {
    "cloud_fast": "gemma-4-26b-a4b-it",
    "cloud_deep": "gemma-4-31b-it",
    "local_edge": "gemma4:e4b",
    "ollama_url": "http://localhost:11434",
}


@dataclass
class RegexRule:
    id: str
    category: str
    severity: str
    title: str
    pattern: str
    action: str
    preset: str
    compiled: re.Pattern = field(repr=False, default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.compiled is None:
            self.compiled = re.compile(self.pattern)


@dataclass
class BarakaConfig:
    raw: Dict[str, Any]
    path: Optional[Path] = None

    @property
    def models(self) -> Dict[str, str]:
        return {**DEFAULT_MODELS, **(self.raw.get("models") or {})}

    @property
    def allowlist(self) -> List[str]:
        return list(self.raw.get("allowlist") or [])

    @property
    def ignore_paths(self) -> List[str]:
        return list(self.raw.get("ignore_paths") or [])

    @property
    def block_on(self) -> List[str]:
        return list(self.raw.get("block_on") or ["CRITICAL", "HIGH"])

    @property
    def warn_on(self) -> List[str]:
        return list(self.raw.get("warn_on") or ["MEDIUM"])

    @property
    def default_engine(self) -> str:
        return self.raw.get("default_engine", "cloud_fast")

    @property
    def default_preset(self) -> str:
        return self.raw.get("default_preset", "all")

    def preset_names(self, preset: str | DomainPreset = DomainPreset.ALL) -> List[str]:
        preset = preset.value if isinstance(preset, DomainPreset) else str(preset)
        presets = self.raw.get("presets") or {}
        if preset in ("all", "", None):
            return list(presets.keys())
        if preset == "research_lab_um6p":
            preset = "research_lab"
        return [preset] if preset in presets else []

    def regex_rules(self, preset: str | DomainPreset = DomainPreset.ALL) -> List[RegexRule]:
        rules: List[RegexRule] = []
        for name in self.preset_names(preset):
            for r in (self.raw["presets"][name].get("regex_rules") or []):
                try:
                    rules.append(RegexRule(
                        id=r["id"], category=r["category"], severity=r.get("severity", "MEDIUM"),
                        title=r.get("title", r["id"]), pattern=r["pattern"],
                        action=r.get("action", "env_extract"), preset=name,
                    ))
                except (KeyError, re.error):
                    continue  # a broken user rule must never crash the gate
        return rules

    def nl_rules(self, preset: str | DomainPreset = DomainPreset.ALL) -> List[str]:
        out: List[str] = []
        for name in self.preset_names(preset):
            out.extend(self.raw["presets"][name].get("nl_rules") or [])
        return out

    def is_allowlisted(self, value: str) -> bool:
        for item in self.allowlist:
            if item and (item in value):
                return True
        return False

    def is_ignored_path(self, path: str) -> bool:
        p = path.replace("\\", "/")
        return any(ig in p for ig in self.ignore_paths)


def find_config(root: Path | str | None = None) -> Optional[Path]:
    start = Path(root or os.getcwd()).resolve()
    for d in [start, *start.parents]:
        cand = d / CONFIG_FILENAME
        if cand.is_file():
            return cand
    fallback = PROJECT_ROOT / CONFIG_FILENAME
    return fallback if fallback.is_file() else None


def load_config(root: Path | str | None = None, path: Path | str | None = None) -> BarakaConfig:
    cfg_path = Path(path) if path else find_config(root)
    raw: Dict[str, Any] = {}
    if cfg_path and cfg_path.is_file():
        try:
            raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            raw = {}
    raw.setdefault("presets", {})
    return BarakaConfig(raw=raw, path=cfg_path)


def validate_yaml(text: str) -> Dict[str, Any]:
    """Parse YAML policy text; raises ValueError with a readable message when invalid."""
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}") from e
    if not isinstance(data, dict) or "presets" not in data:
        raise ValueError("Policy must be a mapping with a 'presets' section")
    for pname, preset in (data.get("presets") or {}).items():
        for r in (preset or {}).get("regex_rules") or []:
            try:
                re.compile(r["pattern"])
            except (KeyError, re.error) as e:
                raise ValueError(f"Bad regex rule in preset '{pname}': {r.get('id')}: {e}") from e
    return data


def load_dotenv(path: Path | str | None = None, override: bool = False) -> Dict[str, str]:
    """Minimal .env loader (KEY=VALUE lines). Searches cwd, then project root."""
    candidates = [Path(path)] if path else [Path(os.getcwd()) / ".env", PROJECT_ROOT / ".env"]
    loaded: Dict[str, str] = {}
    for cand in candidates:
        if not cand.is_file():
            continue
        for line in cand.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:]
            key, val = line.split("=", 1)
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if override or key not in os.environ:
                os.environ[key] = val
            loaded[key] = val
        break
    return loaded
