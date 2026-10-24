import json

import httpx
import pytest

from plutonium import llm_router
from plutonium.llm_router import AllEnginesFailed, GemmaRouter, clean_json_text, repair_json
from plutonium.models import EngineMode

SCHEMA = {"type": "object", "properties": {"findings": {"type": "array"}}}


def test_clean_json_text_strips_fences_and_thoughts():
    raw = "<|channel>thought\nhmm<channel|>```json\n{\"a\": 1}\n```"
    assert json.loads(clean_json_text(raw)) == {"a": 1}


@pytest.mark.parametrize("raw,expected", [
    ('{"a": [1, 2,],}', {"a": [1, 2]}),
    ('Sure! {"a": 1}', {"a": 1}),
    ('{"findings": [{"x": 1}, {"x": 2', {"findings": [{"x": 1}, {"x": 2}]}),
])
def test_repair_json(raw, expected):
    assert repair_json(raw) == expected


def _router(tmp_path, **kw):
    return GemmaRouter(cache_path=tmp_path / "cache.json", **kw)


def test_chain_order():
    r = GemmaRouter.__new__(GemmaRouter)
    assert GemmaRouter.engine_chain(r, EngineMode.CLOUD_FAST)[0] == ("gemini", "gemma-4-26b-a4b-it")
    assert GemmaRouter.engine_chain(r, EngineMode.CLOUD_DEEP)[0] == ("gemini", "gemma-4-31b-it")
    assert GemmaRouter.engine_chain(r, EngineMode.LOCAL_EDGE) == [("ollama", "gemma4:e4b")]


def test_fallback_gemini_to_ollama_and_cache(tmp_path, monkeypatch):
    r = _router(tmp_path)
    r.gemini_client = object()  # pretend a key exists
    calls = []

    def fail_gemini(*a, **k):
        calls.append(k.get("model_id"))
        raise RuntimeError("429 RESOURCE_EXHAUSTED")

    monkeypatch.setattr(r, "call_gemini_api", fail_gemini)
    monkeypatch.setattr(r, "call_local_ollama", lambda *a, **k: {"findings": [1]})
    data, label = r.analyze(EngineMode.CLOUD_FAST, "p", "s", SCHEMA)
    assert data == {"findings": [1]} and label == "ollama:gemma4:e4b"
    assert calls == ["gemma-4-26b-a4b-it", "gemma-4-31b-it"]

    # Everything down -> served from demo cache
    monkeypatch.setattr(r, "call_local_ollama", lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("down")))
    data, label = r.analyze(EngineMode.CLOUD_FAST, "p", "s", SCHEMA)
    assert data == {"findings": [1]} and label.startswith("cache:")


def test_all_fail_raises(tmp_path):
    r = _router(tmp_path)  # no key, ollama URL points at a closed port
    with pytest.raises(AllEnginesFailed):
        r.analyze(EngineMode.LOCAL_EDGE, "p", "s", SCHEMA)


def test_ollama_payload(tmp_path, monkeypatch):
    sent = {}

    class FakeResp:
        def raise_for_status(self): pass
        def json(self): return {"message": {"content": "```json\n{\"findings\": []}\n```"}}

    class FakeClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def post(self, url, json):
            sent["url"], sent["json"] = url, json
            return FakeResp()

    monkeypatch.setattr(llm_router.httpx, "Client", FakeClient)
    r = _router(tmp_path)
    img = tmp_path / "x.png"
    img.write_bytes(b"\x89PNG")
    assert r.call_local_ollama("p", "s", [], SCHEMA) == {"findings": []}
    assert sent["json"]["format"] == SCHEMA and sent["json"]["options"]["num_ctx"] == 8192
    r.call_local_ollama("p", "s", [str(img)], SCHEMA)
    assert sent["json"]["format"] == "json" and sent["json"]["messages"][1]["images"]


def test_hybrid_rehydrates(tmp_path, monkeypatch):
    r = _router(tmp_path)
    seen = {}

    def fake_analyze(mode, prompt, *a, **k):
        seen["prompt"] = prompt
        return {"findings": [{"offending_snippet": "cin=[CIN_TOKEN_1]"}]}, "gemini:gemma-4-31b-it"

    monkeypatch.setattr(r, "analyze", fake_analyze)
    sanitize = lambda t: (t.replace("AB123456", "[CIN_TOKEN_1]"), {"[CIN_TOKEN_1]": "AB123456"})
    rehydrate = lambda t, v: t.replace("[CIN_TOKEN_1]", v["[CIN_TOKEN_1]"])
    data, label, vault = r.hybrid_redact_then_audit("cin=AB123456", "s", SCHEMA, sanitize, rehydrate)
    assert "AB123456" not in seen["prompt"]
    assert data["findings"][0]["offending_snippet"] == "cin=AB123456"
    assert label.startswith("hybrid:")
