"""Unified Gemma 4 router: Gemini API (26b MoE / 31b dense) + local Ollama gemma4:e4b.

Fallback chain (pitfall #3): requested model -> other cloud model -> local Ollama ->
`.barakagate/demo_cache.json` -> raise `AllEnginesFailed` (the scanner then uses its
deterministic offline heuristic engine so the demo never shows an empty screen).
"""
from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from barakagate.config import load_dotenv
from barakagate.models import EngineMode

try:  # Strictly the new SDK (pitfall #1) — never `google.generativeai`.
    from google import genai
    from google.genai import types
except ImportError:  # pragma: no cover - exercised only without the SDK installed
    genai = None
    types = None

CLOUD_FAST_MODEL = "gemma-4-26b-a4b-it"
CLOUD_DEEP_MODEL = "gemma-4-31b-it"
LOCAL_MODEL = "gemma4:e4b"
CACHE_PATH = Path(".barakagate") / "demo_cache.json"


class AllEnginesFailed(RuntimeError):
    def __init__(self, errors: List[str]):
        super().__init__("All Gemma 4 engines failed: " + " | ".join(errors))
        self.errors = errors


def clean_json_text(raw_text: str) -> str:
    """Strips markdown fences or stray thinking tags if emitted by local Ollama or Gemini API."""
    text = re.sub(r"<\|channel>thought.*?<channel\|>", "", raw_text or "", flags=re.DOTALL).strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()
    return text


def repair_json(text: str) -> Any:
    """Best-effort JSON parse: strict, then trimmed to outer braces, trailing commas, truncation."""
    text = clean_json_text(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = min([i for i in (text.find("{"), text.find("[")) if i != -1], default=-1)
    if start == -1:
        raise ValueError("No JSON object found in model output")
    body = text[start:]
    body = re.sub(r",\s*([}\]])", r"\1", body)
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        pass
    # Truncated output: close open strings/brackets, dropping the last partial element.
    for cut in range(len(body), 0, -1):
        if body[cut - 1] not in "}],\"0123456789el":
            continue
        candidate = body[:cut].rstrip(",")
        stack, in_str, esc = [], False, False
        for ch in candidate:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
            elif ch == '"':
                in_str = not in_str
            elif not in_str and ch in "{[":
                stack.append("}" if ch == "{" else "]")
            elif not in_str and ch in "}]" and stack:
                stack.pop()
        if in_str:
            continue
        try:
            return json.loads(re.sub(r",\s*([}\]])", r"\1", candidate + "".join(reversed(stack))))
        except json.JSONDecodeError:
            continue
    raise ValueError("Unrepairable JSON from model")


def _cache_key(prompt: str, image_paths: List[str], tag: str = "") -> str:
    h = hashlib.sha256()
    h.update(tag.encode())
    h.update(prompt.encode("utf-8", "ignore"))
    for p in image_paths:
        try:
            h.update(Path(p).read_bytes())
        except OSError:
            h.update(p.encode())
    return h.hexdigest()


class DemoCache:
    """Persisted responses so the stage demo survives Wi-Fi drops / 429s."""

    def __init__(self, path: Path | str = CACHE_PATH):
        self.path = Path(path)
        self._data: Dict[str, Any] = {}
        if self.path.is_file():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self._data.get(key)

    def put(self, key: str, value: Dict[str, Any]) -> None:
        self._data[key] = value
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass


def _flatten_schema_for_prompt(schema: dict) -> str:
    return json.dumps(schema, ensure_ascii=False)


class GemmaRouter:
    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        cache_path: Path | str = CACHE_PATH,
        offline_safe: bool = True,
        thinking_level: Optional[str] = None,
        timeout_s: float = 120.0,
    ):
        load_dotenv()
        self.ollama_url = os.environ.get("OLLAMA_URL", ollama_url)
        api_key = os.environ.get("GEMINI_API_KEY")
        self.gemini_client = None
        if api_key and genai is not None:
            self.gemini_client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(timeout=int(timeout_s * 1000)),
            )
        self.cache = DemoCache(cache_path)
        self.offline_safe = offline_safe
        self.thinking_level = thinking_level or os.environ.get("BARAKAGATE_THINKING", "low")
        self.timeout_s = timeout_s
        self.last_errors: List[str] = []

    # ------------------------------------------------------------------ status
    def cloud_available(self) -> bool:
        return self.gemini_client is not None

    def ollama_available(self) -> bool:
        try:
            with httpx.Client(timeout=1.5) as client:
                return client.get(f"{self.ollama_url}/api/tags").status_code == 200
        except httpx.HTTPError:
            return False

    # ------------------------------------------------------------------ cloud
    def call_gemini_api(
        self,
        prompt: str,
        system_instruction: str,
        image_paths: list[str],
        response_schema: dict,
        model_id: str = CLOUD_FAST_MODEL,
        thinking_level: str = "high",
    ) -> dict:
        if not self.gemini_client:
            raise RuntimeError("GEMINI_API_KEY is not set in environment.")
        contents: list = []
        # Mandatory Gemma 4 Modality Order: Images BEFORE Text
        for img_path in image_paths:
            mime = mimetypes.guess_type(img_path)[0] or "image/png"
            contents.append(types.Part.from_bytes(data=Path(img_path).read_bytes(), mime_type=mime))
        contents.append(prompt)

        cfg: Dict[str, Any] = dict(
            system_instruction=system_instruction,
            temperature=0.1,
            response_mime_type="application/json",
            response_schema=response_schema,
        )
        if thinking_level and thinking_level != "none":
            cfg["thinking_config"] = types.ThinkingConfig(thinking_level=thinking_level)
        try:
            response = self.gemini_client.models.generate_content(
                model=model_id, contents=contents, config=types.GenerateContentConfig(**cfg)
            )
        except Exception as e:  # Gemma quirk: retry once with a minimal config + schema in prompt
            if not _is_config_rejection(e):
                raise
            folded = (
                f"{system_instruction}\n\nRespond ONLY with JSON matching this schema:\n"
                f"{_flatten_schema_for_prompt(response_schema)}\n\n{prompt}"
            )
            response = self.gemini_client.models.generate_content(
                model=model_id,
                contents=contents[:-1] + [folded],
                config=types.GenerateContentConfig(temperature=0.1, response_mime_type="application/json"),
            )
        return repair_json(response.text or "")

    # ------------------------------------------------------------------ local
    def call_local_ollama(
        self,
        prompt: str,
        system_instruction: str,
        image_paths: list[str],
        response_schema: dict,
        model_id: str = LOCAL_MODEL,
    ) -> dict:
        images_b64 = []
        for img_path in image_paths:
            with open(img_path, "rb") as f:
                images_b64.append(base64.b64encode(f.read()).decode("utf-8"))

        # Pitfall #6: vision + nested format schema can return empty arrays on some Ollama
        # versions -> use "json" mode and put the schema in the prompt instead.
        if images_b64:
            prompt = f"{prompt}\n\nReturn ONLY JSON matching this schema:\n{_flatten_schema_for_prompt(response_schema)}"
        user_msg: Dict[str, Any] = {"role": "user", "content": prompt}
        if images_b64:
            user_msg["images"] = images_b64

        payload = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system_instruction},
                user_msg,
            ],
            "format": "json" if images_b64 else response_schema,
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 8192},  # pitfall #2
        }
        with httpx.Client(timeout=90.0) as client:
            resp = client.post(f"{self.ollama_url}/api/chat", json=payload)
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
            return repair_json(content)

    # ------------------------------------------------------------------ routing
    def engine_chain(self, mode: EngineMode) -> List[Tuple[str, str]]:
        """Ordered (backend, model) attempts for a mode."""
        mode = EngineMode(mode)
        if mode == EngineMode.CLOUD_FAST:
            return [("gemini", CLOUD_FAST_MODEL), ("gemini", CLOUD_DEEP_MODEL), ("ollama", LOCAL_MODEL)]
        if mode == EngineMode.CLOUD_DEEP:
            return [("gemini", CLOUD_DEEP_MODEL), ("gemini", CLOUD_FAST_MODEL), ("ollama", LOCAL_MODEL)]
        if mode == EngineMode.LOCAL_EDGE:
            return [("ollama", LOCAL_MODEL)]  # air-gapped: never leave the machine
        return [("gemini", CLOUD_DEEP_MODEL), ("gemini", CLOUD_FAST_MODEL), ("ollama", LOCAL_MODEL)]

    def analyze(
        self,
        mode: EngineMode | str,
        prompt: str,
        system_instruction: str,
        response_schema: dict,
        image_paths: Optional[List[str]] = None,
        cache_tag: str = "",
        use_cache: bool = True,
    ) -> Tuple[Dict[str, Any], str]:
        """Run the fallback chain. Returns (parsed_json, engine_label)."""
        mode = EngineMode(mode)
        image_paths = list(image_paths or [])
        key = _cache_key(prompt + system_instruction, image_paths, f"{cache_tag}")
        errors: List[str] = []
        for backend, model in self.engine_chain(mode):
            if backend == "gemini" and not self.gemini_client:
                errors.append(f"{model}: no GEMINI_API_KEY")
                continue
            for attempt in range(2 if backend == "gemini" else 1):
                try:
                    if backend == "gemini":
                        data = self.call_gemini_api(
                            prompt, system_instruction, image_paths, response_schema,
                            model_id=model, thinking_level=self.thinking_level,
                        )
                        label = f"gemini:{model}"
                    else:
                        data = self.call_local_ollama(prompt, system_instruction, image_paths, response_schema, model_id=model)
                        label = f"ollama:{model}"
                    if not isinstance(data, dict):
                        data = {"findings": data if isinstance(data, list) else []}
                    if use_cache:
                        self.cache.put(key, {"engine": label, "data": data, "ts": time.time()})
                    self.last_errors = errors
                    return data, label
                except Exception as e:  # noqa: BLE001 - every failure must degrade, not crash
                    errors.append(f"{model}: {type(e).__name__}: {str(e)[:160]}")
                    if backend == "gemini" and _is_retryable(e) and attempt == 0:
                        time.sleep(1.5)
                        continue
                    break
        self.last_errors = errors
        if self.offline_safe and use_cache:
            hit = self.cache.get(key)
            if hit:
                return hit["data"], f"cache:{hit.get('engine', 'unknown')}"
        raise AllEnginesFailed(errors)

    def hybrid_redact_then_audit(
        self,
        prompt: str,
        system_instruction: str,
        response_schema: dict,
        sanitize_fn,
        rehydrate_fn,
        cache_tag: str = "",
    ) -> Tuple[Dict[str, Any], str, Dict[str, str]]:
        """Hybrid smart pipeline: on-device redaction, then a cloud 31b audit of sanitized code.

        `sanitize_fn(text) -> (sanitized, vault)` runs locally (Ollama gemma4:e4b when present,
        deterministic synthetic-token engine otherwise). Findings are rehydrated locally.
        """
        sanitized, vault = sanitize_fn(prompt)
        data, label = self.analyze(EngineMode.HYBRID_SMART, sanitized, system_instruction, response_schema, cache_tag=cache_tag)
        data = json.loads(rehydrate_fn(json.dumps(data, ensure_ascii=False), vault))
        return data, f"hybrid:local-redact->{label}", vault


def _is_config_rejection(e: Exception) -> bool:
    msg = str(e).lower()
    return any(s in msg for s in ("400", "invalid_argument", "not supported", "unsupported", "unknown field"))


def _is_retryable(e: Exception) -> bool:
    msg = str(e).lower()
    return any(s in msg for s in ("500", "503", "internal", "unavailable", "deadline", "timeout", "timed out"))
