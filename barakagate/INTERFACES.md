# BarakaGate internal interface contract

All modules import shared types from `barakagate/models.py` (do NOT modify the spec
models; additive helpers only). Python 3.10, no C-extension deps beyond Pillow.

Already built (Phase 0):
- `barakagate.config`: `load_config(root=None) -> BarakaConfig` with `.regex_rules(preset) -> list[RegexRule]`
  (`id, category, severity, title, pattern, action, preset, compiled`), `.nl_rules(preset) -> list[str]`,
  `.models`, `.allowlist`, `.is_allowlisted(value)`, `.is_ignored_path(path)`, `.block_on`, `.warn_on`,
  `.preset_names(preset)`; `validate_yaml(text) -> dict` (raises ValueError); `load_dotenv()`;
  `PROJECT_ROOT`, `CONFIG_FILENAME`.
- `barakagate.llm_router`: `GemmaRouter(ollama_url=..., cache_path=..., offline_safe=True, thinking_level=None)`
  - `.analyze(mode, prompt, system_instruction, response_schema, image_paths=None, cache_tag="") -> (dict, engine_label)`
    runs the fallback chain; raises `AllEnginesFailed` when nothing (incl. demo cache) answers.
  - `.hybrid_redact_then_audit(prompt, system, schema, sanitize_fn, rehydrate_fn) -> (dict, label, vault)`
  - `.cloud_available()`, `.ollama_available()`, `.call_gemini_api(...)`, `.call_local_ollama(...)`
  - `repair_json(text)`, `clean_json_text(text)`
  - Live latency: 26b ≈ 6–15 s, 31b ≈ 30–60 s; vision works with inline bytes; bbox is `[ymin,xmin,ymax,xmax]` 0–1000.
- `barakagate.models`: spec models + `IndexStats`, `LLMFinding`, `LLMScanResponse` (loose schemas for LLM output).

## indexer.py (Agent A)
```python
class CodebaseIndexer:
    def __init__(self, root: str | Path, config: BarakaConfig | None = None): ...
    chunks: list[CodeChunk]; symbol_map: dict[str, CodeChunk]
    def build(self, force: bool = False) -> IndexStats      # incremental via sha256, persists .barakagate/index.json under root
    def chunk_file(self, path: Path) -> list[CodeChunk]      # .py AST, .ts/.tsx/.js regex+braces, .ipynb cells, config 80/10 windows
    def get_context_for_target(self, text: str, target_files: list[str] | None = None,
                               mode: EngineMode = EngineMode.CLOUD_FAST) -> list[CodeChunk]
    # 1-hop symbol resolution first (excluding chunks from target_files), then BM25, then budget:
    # cloud_fast/cloud_deep -> 15 chunks; local_edge/hybrid_smart -> 3 chunks & <= 2500 chars.
    notebook_images: list[str]   # PNGs extracted from .ipynb outputs into <root>/.barakagate/tmp_nb_images/
def tokenize(text) -> list[str];  class BM25: (docs: list[list[str]]) .score(query_tokens) -> list[float]
```

## scanner.py (Agent A)
```python
def regex_baseline(text: str, file_path: str, preset="all", config=None) -> list[Finding]   # caught_by_regex_baseline=True
def heuristic_logic_scan(text: str, file_path: str, context_chunks: list[CodeChunk]) -> list[Finding]
def normalize_findings(raw: dict, default_file: str, target_type="text") -> list[Finding]   # LLM JSON -> Finding, tolerant
def compute_verdict(findings, config=None) -> str   # BLOCK if any CRITICAL/HIGH (non-whitelisted), WARN if MEDIUM, else PASS
SCAN_RESPONSE_SCHEMA: dict;  IMAGE_RESPONSE_SCHEMA: dict
class Scanner:
    def __init__(self, root=".", router: GemmaRouter | None = None, config=None, offline: bool = False): ...
    indexer: CodebaseIndexer
    def scan_files(self, paths: list[str], mode=EngineMode.CLOUD_FAST, preset="all") -> ScanResult
    def scan_text(self, text: str, file_path: str = "snippet.py", mode=..., preset="all") -> ScanResult
    def scan_diff(self, diff_text: str, mode=..., preset="all") -> ScanResult
    def scan_staged(self, mode=..., preset="all") -> ScanResult     # git diff --cached
    def scan_image(self, image_path: str, mode=..., preset="all") -> ScanResult   # findings with target_type="image", bbox_2d
```
- `offline=True` or `AllEnginesFailed` -> regex + heuristic only, `engine_used="offline_heuristic"`.
- Findings from LLM merged with regex ones (dedupe by file+line+overlapping snippet; mark `caught_by_regex_baseline`).
- `ScanResult.retrieved_context_Chunks` = list of `"file_path:symbol_name"`; also expose `scanner.last_context: list[CodeChunk]`.
- Image scans: OCR via LLM; offline fallback = cached result or empty with summary explaining.

## redactor.py (Agent B)
```python
def synthetic_twin(kind: str, value: str = "", index: int = 1) -> str   # kinds: cin, rib, cne, phone, iban, email, secret, jwt, generic
def rib_key(bank_branch_account_22_digits: str) -> str                  # valid 2-digit RIB key (97 - (n*100 % 97))
def apply_text_fixes(text: str, findings: list[Finding], decisions: dict[str, ActionType | str]) -> str
    # decisions map finding.id -> action; snippet substring replace first, else reverse line order (pitfall #5)
def preview_patch(text, findings, decisions) -> str   # unified diff
def extract_to_env(finding, language="python") -> tuple[str, str, str]   # (replacement_code, ENV_NAME, value)
def apply_to_disk(path: str, findings, decisions, env_path: str | None = None) -> dict   # writes file + appends .env
def bbox_to_pixels(bbox_2d, width, height, pad=0.15) -> tuple[int,int,int,int]   # (x1,y1,x2,y2)
def redact_image(path, boxes: list[list[int]], style="gaussian_blur"|"solid_mask", out_path=None) -> str
def sanitize_prompt(text: str, config=None) -> tuple[str, dict[str, str]]   # tokens like [CIN_TOKEN_1], [RIB_TOKEN_1], [SECRET_KEY_1], [URL_TOKEN_1]
def rehydrate(text: str, vault: dict[str, str]) -> str
```

## cli.py (Agent B) — Typer app `app`
`scan PATHS... [--mode] [--preset] [--offline-safe/--offline] [--json] [--fix]`, `staged`, `index`, `image PATH [--apply] [--style]`,
`sanitize [FILE|-]`, `install-hook`, `benchmark`, `serve [--port 8000]`. Exit code 1 on BLOCK.

## server.py (Agent C) — FastAPI `app`, serves `barakagate/static/index.html`.
