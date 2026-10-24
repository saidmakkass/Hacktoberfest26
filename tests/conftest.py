import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch, tmp_path):
    """Tests never hit the real Gemini API or Ollama unless BARAKAGATE_LIVE=1."""
    if os.environ.get("BARAKAGATE_LIVE") != "1":
        monkeypatch.setenv("GEMINI_API_KEY", "")
        monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:9")
    yield


@pytest.fixture
def project_root() -> Path:
    return ROOT
