# BARAKAGATE — MASTER SYSTEM SPECIFICATION & AGENT IMPLEMENTATION GUIDE

> **AGENT INSTRUCTION HEADER (READ FIRST)**  
> This document is the single source of truth for building **BarakaGate**, an open-source **Multimodal Pre-Flight Security, Privacy & Cross-File Logical Bug Gate** built for **Hacktoberfest26 Rabat Hack Day (Case 01: Best Open-Source AI Project & Case 02: Best Use of Gemma 4)**.  
> Follow the exact directory structure, Pydantic data contracts (`barakagate/models.py`), API implementations, chunking/indexing logic, and UI layouts specified below. Do not invent incompatible schemas or use deprecated SDKs.

## 1. System Overview & Dual-Challenge Winning Architecture

**BarakaGate** is a pre-commit CLI, Agent Skill harness, and interactive Web Studio that scans staged Git diffs, source repositories, Jupyter notebooks, prompts, and screenshots to catch and fix two critical classes of pre-production failures that traditional regex tools ([Gitleaks](https://github.com/gitleaks/gitleaks), [Microsoft Presidio](https://github.com/data-privacy-stack/presidio)) and single-file linters miss:
1. **Multimodal & Multilingual Privacy/Secret Leaks**: Contextual secrets, internal URLs, visual leaks inside screenshots, and multilingual PII across **General DevSecOps**, **Moroccan Fintech/E-Commerce** ([Law 09-08 / CNDP](https://www.dpo-consulting.com/blog/morocco-data-protection-law-09-08), 24-digit [Moroccan RIBs](https://rib.ma/en), CINs, CMI keys, Darija/French/Arabic logs), and **University/Research Labs** (student CNE/Massar IDs, `.ipynb` output leaks, internal `*.um6p.ma` endpoints).
2. **Cross-File Logical & Security Bugs**: By chunking and indexing the repository into a local symbol dependency graph + BM25 index, BarakaGate pulls cross-file definitions (imported models, helper functions, callers) alongside any code change so Gemma 4 catches logical bugs (e.g., MAD/EUR float rounding, race conditions, missing webhook verification, ML train/test data leakage, off-by-one bugs) and generates ready-to-apply code patches.

### Hybrid Gemma 4 Model Routing (Cloud Gemini API + Local Ollama `gemma4:e4b`)

BarakaGate implements a unified `ModelRouter` supporting **four selectable execution modes**:
1. **`cloud_fast` (Default — Case 02 Primary)**: Uses `gemma-4-26b-a4b-it` via the [Google Gemini API](https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api) (26B Mixture-of-Experts with only 3.8B active parameters for sub-second latency, 256K context window, multimodal vision, and `<|think|>` reasoning) ([Gemma 4 Model Card](https://ai.google.dev/gemma/docs/core/model_card_4)).
2. **`cloud_deep` (Case 02 Heavy Reasoning)**: Uses `gemma-4-31b-it` via the Gemini API (31B dense model, 80.0% LiveCodeBench v6, 256K context) for complex cross-file logical bug verification.
3. **`local_edge` (100% Offline Air-Gapped Mode)**: Uses `gemma4:e4b` running locally on the laptop via [Ollama's Structured Outputs API](https://docs.ollama.com/capabilities/structured-outputs) (`http://localhost:11434/api/chat`, 128K context, multimodal vision) ([Ollama Gemma 4](https://ollama.com/library/gemma4)). Zero bytes leave the machine.
4. **`hybrid_smart` (The Signature Pipeline)**: Runs local `gemma4:e4b` first to detect and replace sensitive PII/secrets with synthetic placeholders (`[SYNTH_CIN_1]`, `[SYNTH_KEY_1]`) on-device, then sends the **already-sanitized code + cross-file chunks** to cloud `gemma-4-31b-it` on the Gemini API for deep cross-file logical bug analysis.

## 2. Repository Directory Structure & 4-Person Parallel Split

Every teammate works on isolated files that import shared contracts from `barakagate/models.py`:

```text
barakagate/
├── LICENSE                          # MIT License (Mandatory Gate 03)
├── README.md                        # Phase 1 Judging Portfolio + Benchmark Matrix (Mandatory Gate 05)
├── pyproject.toml                   # Package metadata & dependencies
├── requirements.txt                 # google-genai, fastapi, uvicorn, typer, rich, pydantic, pyyaml, pillow, httpx
├── .barakagate.yaml                 # Default customizable Policy-as-Code rules (General + Fintech + Research Lab)
├── .github/workflows/barakagate.yml # CI/CD Pull Request enforcement workflow
├── skills/
│   └── barakagate/
│       └── SKILL.md                 # Agent Skills Open Standard manifest (Case 01 requirement)
├── barakagate/
│   ├── __init__.py
│   ├── models.py                    # SHARED CONTRACT: Pydantic schemas (All 4 teammates import this)
│   ├── config.py                    # Role 1: Loads .barakagate.yaml presets & allowlists
│   ├── llm_router.py                # Role 1: Unified Gemini API (26b/31b) + Local Ollama (gemma4:e4b) + Fallback
│   ├── indexer.py                   # Role 2: AST/Regex Codebase Chunker, Symbol Graph & BM25 Context Retriever
│   ├── scanner.py                   # Role 2: Orchestrates Regex Baseline + Index Retrieval + Gemma 4 Analysis
│   ├── redactor.py                  # Role 3: Synthetic Twins, .env Extractor, Bug Patcher, Safe-Prompt & Pillow Blur
│   ├── cli.py                       # Role 3: Typer/Rich Interactive CLI & Git pre-commit hook installer
│   ├── server.py                    # Role 4: FastAPI Backend serving REST endpoints + static Web Studio
│   └── static/
│       └── index.html               # Role 4: Complete 4-Tab Interactive Frontend ("BarakaGate Studio")
├── samples/                         # Role 3 & 4: Pre-built realistic demo scenarios
│   ├── fintech_morocco/             # CMI checkout + RIB/CIN Darija fixture + float rounding & race condition bug
│   ├── research_lab_um6p/           # Student CNE dataset + .ipynb leak + ML train/test data leakage bug
│   ├── general_devsecops/           # Hardcoded JWT/AWS config + SQL injection & off-by-one bug
│   └── screenshots/                 # Sample DevTools & dashboard PNGs with visible keys/CINs for live blur
└── evaluate_benchmark.py            # Automated 12-case benchmark generator (Regex vs. Gemma 4)
```

### Parallel Team Role Assignment (4 Builders + AI Subscriptions)

| Teammate | Assigned AI Tool | Owned Files | Core Responsibility |
| :--- | :--- | :--- | :--- |
| **Builder 1 (AI & Policy Lead)** | **Gemini Pro** (best for `google-genai` & Gemma 4 nuances) | `models.py`, `config.py`, `llm_router.py`, `.barakagate.yaml` | Build the shared Pydantic schemas, `.barakagate.yaml` rule loader, and the dual `Gemini API` + `Ollama gemma4:e4b` router with automatic JSON repair and fallback. |
| **Builder 2 (Indexer & Bug/Leak Scanner Lead)** | **ChatGPT Pro** (strong at AST algorithms & graph indexing) | `indexer.py`, `scanner.py` | Build the pure-Python AST/Regex codebase chunker, symbol call-graph resolver, BM25 context retriever, and the unified Leak + Logical Bug prompt builder. |
| **Builder 3 (Remediation Engine, CLI & Benchmark Lead)** | **Claude Pro** (strong at file patching, CLI UX & realistic fixtures) | `redactor.py`, `cli.py`, `samples/**`, `evaluate_benchmark.py`, `SKILL.md`, `README.md` | Build the Synthetic Twin replacer, `.env` extractor, code bug patcher, Pillow bounding-box image blurrer, Rich interactive CLI, and the realistic Fintech/Lab demo fixtures. |
| **Builder 4 (Frontend Web Studio Lead)** | **Claude Pro** (strong at single-file Tailwind/Canvas UIs) | `server.py`, `static/index.html` | Build the FastAPI server and the dark-mode 4-Tab "BarakaGate Studio" Web UI (Code Diff + Bug/Leak HITL Triage, Interactive Canvas Image Blurrer, Safe-to-Prompt Firewall, Policy & Benchmark Runner). |

## 3. Shared Data Contract (`barakagate/models.py`)

Create `barakagate/models.py` **first** (in the first 10 minutes) and commit it so all 4 builders code against identical types:

```python
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class EngineMode(str, Enum):
    CLOUD_FAST = "cloud_fast"       # Gemini API: gemma-4-26b-a4b-it
    CLOUD_DEEP = "cloud_deep"       # Gemini API: gemma-4-31b-it
    LOCAL_EDGE = "local_edge"       # Local Ollama: gemma4:e4b
    HYBRID_SMART = "hybrid_smart"   # Local gemma4:e4b redact -> Cloud gemma-4-31b-it bug audit

class DomainPreset(str, Enum):
    ALL = "all"
    FINTECH_MOROCCO = "fintech_morocco"
    RESEARCH_LAB = "research_lab"
    GENERAL_DEVSECOPS = "general_devsecops"

class FindingCategory(str, Enum):
    SECURITY_LEAK = "security_leak" # API keys, tokens, credentials, internal URLs
    PRIVACY_PII = "privacy_pii"     # CIN, 24-digit RIB, CNE, Darija/French/Arabic PII, screenshot PII
    LOGICAL_BUG = "logical_bug"     # Race conditions, float currency bugs, ML data leakage, off-by-one, SQLi

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ActionType(str, Enum):
    SYNTHETIC_TWIN = "synthetic_twin" # Replace PII/test secret with format-valid mock data
    ENV_EXTRACT = "env_extract"       # Move secret to .env and reference os.getenv / process.env
    CODE_PATCH = "code_patch"         # Apply logical/security bug fix to code
    GAUSSIAN_BLUR = "gaussian_blur"   # Blur bounding box on image
    SOLID_MASK = "solid_mask"         # Draw solid redaction box on image
    WHITELIST = "whitelist"           # Human chose to keep/ignore (false positive)

class CodeChunk(BaseModel):
    chunk_id: str
    file_path: str
    symbol_name: str
    chunk_type: str                   # "function" | "class" | "module" | "notebook_cell"
    start_line: int
    end_line: int
    code: str
    imports: List[str] = Field(default_factory=list)
    called_symbols: List[str] = Field(default_factory=list)
    sha256: str

class Finding(BaseModel):
    id: str
    category: FindingCategory
    target_type: str = Field(description="'text' or 'image'")
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    rule_id: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    reason: str = Field(description="Clear explanation of why this is a leak or logical bug")
    cross_file_context_used: Optional[str] = Field(
        default=None,
        description="Name of external symbol/file from the codebase index that proved this bug/leak"
    )
    offending_snippet: Optional[str] = None
    recommended_action: ActionType
    replacement_snippet: Optional[str] = Field(
        default=None,
        description="Exact replacement code line(s): either a synthetic twin, env var call, or bug fix patch"
    )
    env_var_name: Optional[str] = None
    env_var_value: Optional[str] = None
    bbox_2d: Optional[List[int]] = Field(
        default=None,
        description="Normalized [ymin, xmin, ymax, xmax] (0 to 1000 scale) for image findings"
    )
    caught_by_regex_baseline: bool = False

class ScanResult(BaseModel):
    verdict: str                      # "PASS" | "WARN" | "BLOCK"
    engine_used: str
    preset_used: str
    summary: str
    thinking_trace: Optional[str] = None
    indexed_chunks_count: int = 0
    retrieved_context_Chunks: List[str] = Field(default_factory=list)
    regex_baseline_count: int = 0
    gemma_findings_count: int = 0
    findings: List[Finding] = Field(default_factory=list)
```

## 4. Codebase Chunker & Cross-File Context Indexer (`barakagate/indexer.py`)

To detect **logical bugs** and **cross-file PII leaks** (e.g., `checkout.py` logs `customer.to_dict()` where `Customer` in `models.py` holds a 24-digit Moroccan RIB, or `payment.py` calls `calculate_fee()` in `fees.py` which uses `float` instead of integer centimes), you must chunk and index the codebase before calling Gemma 4.

### Implementation Guidelines for `indexer.py` (Zero C++ Dependencies)
Do **not** use `chromadb`, `faiss`, or `tree-sitter` binary wheels (they frequently fail to compile or clash with system SQLite during hackathons). Use this deterministic **3-stage pure-Python indexer**:

1. **Stage 1: Structural AST & Regex Chunker**:
   * **Python (`.py`)**: Use Python's standard library `ast.parse(source)`. Walk `ast.FunctionDef`, `ast.AsyncFunctionDef`, and `ast.ClassDef`. For each node, extract `node.lineno`, `node.end_lineno`, the exact source lines, all `ast.Name` / `ast.Attribute` calls inside the node body (`called_symbols`), and module-level imports.
   * **TypeScript / JavaScript (`.ts`, `.tsx`, `.js`)**: Use regex + brace counting to split on `export function`, `function`, `class`, `interface`, and `const name = (...) =>`. Extract imported identifiers from `import { ... } from ...`.
   * **Jupyter Notebooks (`.ipynb`)**: Parse the `.ipynb` JSON. Treat each `"code"` cell as a `CodeChunk` (`symbol_name=f"cell_{idx}"`), and extract any `"image/png"` base64 payloads inside `cell["outputs"]` to temporary `.png` files in `.barakagate/tmp_nb_images/` so Gemma 4's vision engine inspects notebook plots/tables too!
   * **Config / Data Fixtures (`.json`, `.yaml`, `.sql`, `.env`)**: Chunk in 80-line windows with 10-line overlap.
2. **Stage 2: Fast Incremental Storage (`.barakagate/index.json`)**:
   * Compute `hashlib.sha256(content.encode()).hexdigest()` per file. On subsequent runs, only re-chunk files whose SHA-256 changed.
   * Build an in-memory lookup table: `symbol_map: Dict[str, CodeChunk]` mapping every function/class/interface name to its defining `CodeChunk`.
3. **Stage 3: Cross-File Context Retrieval (`get_context_for_target(target_files_or_diff)`)**:
   * **Step A (1-Hop Symbol Graph Resolution)**: Parse identifiers mentioned in the git diff or target file. If any identifier matches a `symbol_name` in `symbol_map` from *another* file, automatically include that `CodeChunk` (this guarantees Gemma 4 sees the exact definition of called functions and data models!).
   * **Step B (Pure-Python BM25 Ranking)**: Score remaining chunks using a 30-line pure-Python BM25 implementation (`math.log` + term frequency over tokenized identifiers) against the tokens in the diff.
   * **Step C (Token Budget Packing)**:
     * If `EngineMode` is `CLOUD_FAST` (`gemma-4-26b-a4b-it`) or `CLOUD_DEEP` (`gemma-4-31b-it`), pack up to **15 cross-file chunks** (leveraging Gemma 4's 256K context window).
     * If `EngineMode` is `LOCAL_EDGE` (`gemma4:e4b`), pack only the **top 4 cross-file chunks** (<3,000 tokens) so local laptop inference finishes in <4 seconds!

## 5. Dual LLM Router: Gemini API + Local Ollama `gemma4:e4b` (`barakagate/llm_router.py`)

Implement `llm_router.py` so it seamlessly handles both the **Google Gemini API** (`google-genai` SDK) and **Local Ollama** (`http://localhost:11434/api/chat`), plus the **Hybrid Smart Router**:

```python
import os
import re
import json
import base64
import httpx
from google import genai
from google.genai import types
from barakagate.models import EngineMode, ScanResult

def clean_json_text(raw_text: str) -> str:
    """Strips markdown fences or stray thinking tags if emitted by local Ollama or Gemini API."""
    text = re.sub(r"<\|channel>thought.*?<channel\|>", "", raw_text, flags=re.DOTALL).strip()
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()
    return text

class GemmaRouter:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        api_key = os.environ.get("GEMINI_API_KEY")
        self.gemini_client = genai.Client(api_key=api_key) if api_key else None

    def call_gemini_api(
        self,
        prompt: str,
        system_instruction: str,
        image_paths: list[str],
        response_schema: dict,
        model_id: str = "gemma-4-26b-a4b-it",
        thinking_level: str = "high"
    ) -> dict:
        if not self.gemini_client:
            raise RuntimeError("GEMINI_API_KEY is not set in environment.")
        contents = []
        # Mandatory Gemma 4 Modality Order: Images BEFORE Text
        for img_path in image_paths:
            uploaded = self.gemini_client.files.upload(file=img_path)
            contents.append(uploaded)
        contents.append(prompt)

        response = self.gemini_client.models.generate_content(
            model=model_id,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.1,
                response_mime_type="application/json",
                response_schema=response_schema,
                thinking_config=types.ThinkingConfig(thinking_level=thinking_level),
            ),
        )
        return json.loads(clean_json_text(response.text))

    def call_local_ollama(
        self,
        prompt: str,
        system_instruction: str,
        image_paths: list[str],
        response_schema: dict,
        model_id: str = "gemma4:e4b"
    ) -> dict:
        images_b64 = []
        for img_path in image_paths:
            with open(img_path, "rb") as f:
                images_b64.append(base64.b64encode(f.read()).decode("utf-8"))

        user_msg = {"role": "user", "content": prompt}
        if images_b64:
            user_msg["images"] = images_b64

        payload = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system_instruction},
                user_msg
            ],
            "format": response_schema,
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 16384}
        }
        with httpx.Client(timeout=90.0) as client:
            resp = client.post(f"{self.ollama_url}/api/chat", json=payload)
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
            return json.loads(clean_json_text(content))
```

## 6. Three Built-In Policy Presets (`.barakagate.yaml`)

Include all three domain sections in `.barakagate.yaml` so users can toggle between them in the UI or enforce all of them together:

### Section A: General Software Engineering (Universal DevSecOps & Bugs)
* **Leaks & Secrets**: Hardcoded API keys, Bearer/JWT tokens, private PEM/SSH keys, database connection URIs with passwords, internal IPv4/staging hosts, and credentials visible in terminal/browser screenshots.
* **Logical & Security Bugs**:
  * SQL injection via string interpolation (`f"SELECT ... {user_input}"`), command injection, or SSRF.
  * Off-by-one loop bounds, unhandled `None`/`null` dereferences determined from cross-file return types, and resource/file-handle leaks.
  * Missing authentication/authorization checks on state-mutating API endpoints compared to sibling routes in the codebase index.

### Section B: Moroccan Fintech & E-Commerce (Law 09-08 / CNDP & Payment Safety)
* **Privacy & Secrets**:
  * **Moroccan CIN (Carte Nationale d'Identité)**: 1–2 Latin letters followed by 5–6 digits (e.g., `AB123456`, `BE892341`) in JSON fixtures, SQL seeds, logs, or ID card screenshots ([Morocco Law 09-08](https://www.dpo-consulting.com/blog/morocco-data-protection-law-09-08)).
  * **Moroccan 24-Digit RIB (Relevé d'Identité Bancaire)**: `3-digit Bank Code + 3-digit Branch Code + 16-digit Account + 2-digit Key` ([RIB.ma Format](https://rib.ma/en)) or `MA` IBANs.
  * **Multilingual Customer PII**: Moroccan phone numbers (`+212 6...`, `+212 7...`, `06...`, `07...`) and customer support logs or addresses written in **Moroccan Darija** (e.g., *"salam khouya هاك رقم البطاقة ديالي..."*), **French**, or **Arabic**.
  * **Payment Gateway Secrets**: Hardcoded CMI (Centre Monétique Interbancaire), Payzone, or Stripe live merchant keys/storeKeys.
* **Logical & Financial Bugs**:
  * **Currency Float Rounding Bug**: Using IEEE-754 `float` instead of `Decimal` or integer centimes for `MAD` / `EUR` calculations (`amount * 0.20` TVA causing 1-centime reconciliation mismatches across files).
  * **TOCTOU Wallet Double-Spend / Race Condition**: Checking `if wallet.balance >= amount:` and deducting `wallet.balance -= amount` without a database transaction lock or atomic update when called from concurrent async endpoints.
  * **Missing Webhook Signature Verification**: Accepting a payment callback payload (`status == "APPROVED"`) without verifying the HMAC hash against the merchant secret defined in the config module.
  * **Negative Quantity / Promo Bypass**: Allowing negative item quantities or stacking percentage discounts above 100% due to missing bounds checks in the pricing helper.

### Section C: University & Research Lab (UM6P / Academic Reproducibility & Privacy)
* **Privacy & Secrets**:
  * **Student Identifiers**: Moroccan `CNE` / Massar codes (`1 letter + 9 digits`, e.g., `R130045892`), student grade/GPA sheets, scholarship financial aid records, or medical/counseling notes in `.csv`/`.json` files.
  * **Campus & HPC Infrastructure**: Hardcoded credentials or tokens for internal `*.um6p.ma` staging servers, Slurm/HPC cluster scripts, or shared lab cloud buckets.
  * **Jupyter Notebook (`.ipynb`) Leaks**: Printed DataFrame heads (`df.head()`) or matplotlib images left inside saved `.ipynb` output cells that expose real survey participants or API keys.
* **Logical & Scientific Bugs**:
  * **ML Train/Test Data Leakage**: Calling `scaler.fit_transform(X)` or target imputation on the *entire* dataset before calling `train_test_split(X, y)` across pipeline modules.
  * **Silent `NaN` / Division-by-Zero Propagation**: Computing sensor/experiment averages without masking missing values (`-999` or `NaN` sentinel values defined in the data loader file).
  * **Missing Reproducibility Seeds**: Running stochastic experiments (`random`, `numpy`, `torch`) without propagating the global seed parameter from the config file.

## 7. Interactive Frontend Specification ("BarakaGate Studio" — `barakagate/static/index.html`)

Instead of a fragile VS Code extension, build a polished, responsive single-page web application in `barakagate/static/index.html` using **Tailwind CSS (via CDN) + Vanilla JS** served directly by `barakagate/server.py` (`FastAPI`).

### Top Navigation & Control Bar
* **Brand Logo + Status Pill**: `BarakaGate v1.0 — Open-Weight Pre-Flight Security, Privacy & Bug Gate`
* **Model Engine Selector (`<select id="engineMode">`)**:
  * `⚡ Cloud Fast: gemma-4-26b-a4b-it (Gemini API MoE)`
  * `🧠 Cloud Deep: gemma-4-31b-it (Gemini API 256K)`
  * `🔒 Local Air-Gapped: gemma4:e4b (Laptop Ollama)`
  * `🛡️ Hybrid Smart Router (Local gemma4:e4b Redact → Cloud gemma-4-31b-it Bug Audit)`
* **Domain Policy Selector (`<select id="domainPreset">`)**:
  * `All Policy Packs` | `🇲🇦 Moroccan Fintech & E-Commerce` | `🎓 University & Research Lab` | `🌐 General DevSecOps`
* **Codebase Index Indicator**: Shows `Indexed: X Chunks / Y Symbols` with a `[Re-Index Codebase]` button (`POST /api/index`).

### Tab 1: Unified Code Diff, Leak & Logical Bug Inspector (Main Demo View)
* **Left Column (Input & Context)**:
  * **Quick Demo Scenario Loader Buttons**:
    1. `[Load Moroccan Fintech Checkout PR]` (loads `samples/fintech_morocco/`)
    2. `[Load Research Lab Notebook & Pipeline]` (loads `samples/research_lab_um6p/`)
    3. `[Load General DevSecOps API]` (loads `samples/general_devsecops/`)
    4. `[Scan Live Git Staged Diff]` (`git diff --cached`)
  * **Code / Diff Viewer**: Syntax-highlighted view of the target file/diff.
  * **Retrieved Cross-File Context Accordion**: Shows the exact `CodeChunk` blocks (`models.py:Customer`, `fees.py:calculate_tva`, etc.) that `indexer.py` automatically pulled from other files so judges see *how* the codebase index powers logical bug detection!
* **Right Column (Gemma 4 Findings & Human-in-the-Loop Controls)**:
  * **Comparison Scoreboard Banner**:
    * `Regex Baseline (Gitleaks): X Caught (0 Logical Bugs, 0 Contextual/Image Leaks)`
    * `BarakaGate (Gemma 4): Y Caught (Leaks + PII + Cross-File Logical Bugs)`
  * **Collapsible `<|think|>` Reasoning Trace Box**: Displays Gemma 4's step-by-step analysis.
  * **Interactive Finding Cards**: Each card displays:
    * Category badge: `🔴 PRIVACY / SECRET LEAK` or `🟣 LOGICAL / SECURITY BUG`
    * Severity badge (`CRITICAL` / `HIGH` / `MEDIUM`), File & Line number, and a **"Cross-File Proof"** tag showing which indexed symbol proved the bug/leak.
    * **Proposed Fix Diff**: Red line (`- offending_snippet`) vs. Green line (`+ replacement_snippet`).
    * **Human Decision Buttons (Radio toggle per card)**:
      * For Leaks/PII: `[✓ Swap Synthetic Twin]` | `[Extract to .env]` | `[Hard Mask]` | `[Keep / Whitelist]`
      * For Logical Bugs: `[✓ Apply Bug Fix Patch]` | `[Keep Original (Ignore)]`
  * **Bottom Action Bar**: `[Preview Combined Patched File]` and `[Apply Selected Fixes to Disk]`.

### Tab 2: Multimodal Screenshot & Notebook Image Sanitizer
* **Image Selector / Upload Dropzone**: Pre-loaded with 2 sample screenshots (`DevTools CMI Bearer Token + Moroccan CIN` and `Jupyter Notebook Research Table with Student CNEs`) plus drag-and-drop file upload.
* **Interactive HTML5 `<canvas>`**:
  * Renders the image and draws color-coded bounding boxes (`[ymin, xmin, ymax, xmax]`) returned by Gemma 4.
  * Clicking any box toggles whether it will be blurred or kept (Human-in-the-Loop visual control!).
  * Users can also click-and-drag on the canvas to draw a custom redaction box.
* **Action Bar**: `[Run Gemma 4 Vision Scan]`, Blur Style selector (`Gaussian Blur` vs. `Solid Cyber Redact Box`), and `[Apply Redaction & Download PNG]`.

### Tab 3: "Safe-to-Prompt" Outbound Agent Firewall
* **3-Pane Workflow**:
  1. **Pane 1 (Raw Developer Prompt / Stack Trace)**: User pastes a messy debugging prompt containing real Moroccan CINs, 24-digit RIBs, internal `*.um6p.ma` URLs, and buggy code.
  2. **Pane 2 (Sanitized Prompt + Local Token Vault)**: Clicking `[Sanitize with Local gemma4:e4b]` replaces every sensitive entity with `[CIN_TOKEN_1]`, `[RIB_TOKEN_1]`, `[SECRET_KEY_1]` and displays the local mapping table in browser memory.
  3. **Pane 3 (Send to Cloud AI & Auto-Rehydrate)**: Clicking `[Ask Cloud Gemma 4 31B & Restore Context]` sends *only* the sanitized prompt to the cloud, receives the bug fix explanation, and automatically swaps `[CIN_TOKEN_1]` back locally!

### Tab 4: Custom Rules (`.barakagate.yaml`) & Phase 1 Benchmark Generator
* **Live YAML Policy Editor**: Edit `.barakagate.yaml` natural-language rules in the browser and click `[Save Policy]`.
* **1-Click Benchmark Matrix Runner**: Clicking `[Run Full Benchmark Suite]` executes `evaluate_benchmark.py` and renders the Markdown table comparing Regex vs. `gemma-4-26b-a4b-it` vs. `gemma4:e4b` across all test cases.

## 8. Predicted Hackathon Pitfalls & Pre-Engineered Fixes

Read this section carefully—these are the exact bugs that break hackathon projects and how to prevent them upfront:

| Pitfall | What Goes Wrong | Mandatory Prevention in Your Code |
| :--- | :--- | :--- |
| **1. Wrong Google SDK Package** | Coding agents often import `import google.generativeai as genai` (the deprecated 2024 SDK), which fails on Gemma 4 thinking/structured configs. | **Strictly use `from google import genai` and `from google.genai import types`** (`pip install google-genai`). Never install `google-generativeai`. |
| **2. Local `gemma4:e4b` Latency / OOM on Large Prompts** | Sending 50KB of repository context to local `gemma4:e4b` on a laptop causes 45-second timeouts or VRAM thrashing. | In `indexer.py`, check `engine_mode`: when `local_edge` or `hybrid_smart` is selected, cap retrieved cross-file chunks to `max_chunks=3` (`<= 2500` chars) and set Ollama `"num_ctx": 8192`. |
| **3. Gemini API 429 Quota / Wi-Fi Drop During Live Demo** | Venue Wi-Fi at hackathons is congested, or burst requests hit free-tier RPM limits right on stage. | Implement automatic 3-tier fallback in `llm_router.py`: `gemma-4-26b-a4b-it` → `gemma-4-31b-it` → local `ollama/gemma4:e4b` → pre-cached deterministic JSON response in `.barakagate/demo_cache.json` if `--offline-safe` is enabled. |
| **4. Bounding Box Coordinate Mismatch (`[ymin, xmin, ymax, xmax]`)** | Developers assume `[x1, y1, x2, y2]` in pixels, causing blurred boxes to land on the wrong part of the screenshot. | Gemma 4 returns **`[ymin, xmin, ymax, xmax]` normalized to `0–1000`**. Always convert via `y1 = int((ymin/1000)*height)` and `x1 = int((xmin/1000)*width)`, and add 15% padding. |
| **5. Applying Multiple Line Replacements Corrupts Line Numbers** | Replacing line 10 with a 3-line patch shifts line 25 to line 27, so the second patch overwrites the wrong line. | In `redactor.py`, **sort all selected text findings in reverse line order (`line_start` descending)** before applying replacements, or match by exact `offending_snippet` substring replacement. |
| **6. Ollama Vision vs. Structured JSON Conflict** | On some Ollama versions, combining `images` + complex nested `format` JSON schemas in `gemma4:e4b` returns empty arrays. | For local `gemma4:e4b` image scans, pass a flat JSON schema in the prompt + `"format": "json"` in the Ollama payload, then validate/normalize in Python with Pydantic. |

## 9. Sample Demo Fixtures to Generate (`samples/`)

Generate these exact 3 sample scenarios so the live demo and benchmark suite work out-of-the-box:

1. **`samples/fintech_morocco/` (2 interconnected files illustrating Cross-File Context)**:
   * `models.py`: Defines `class MoroccanCustomer` with fields `full_name`, `cin_number` (Moroccan CIN), `rib_account` (24-digit RIB), and `wallet_balance_mad: float`. Also defines `CMI_WEBHOOK_SECRET = "cmi_live_sk_9988776655443322"`.
   * `checkout.py`: Imports `MoroccanCustomer` from `models.py`. Contains:
     * **Leak 1 (Darija/French PII Fixture)**: A hardcoded test dictionary `TEST_CLIENT = {"name": "Youssef El Amrani", "cin": "BE847291", "rib": "230780123456789012345678", "phone": "+212661234567", "note": "salam khouya هاك رقم البطاقة والحساب البنكي"}`.
     * **Leak 2 (Cross-File Object Dump)**: `logger.info(f"Debug payload: {customer.__dict__}")` (only detectable as a CRITICAL PII leak because `indexer.py` resolves `MoroccanCustomer` from `models.py`!).
     * **Logical Bug 1 (Float MAD Currency Bug)**: `tva = round(amount_mad * 0.20, 2)` using `float` arithmetic instead of integer centimes/`Decimal`, causing ledger drift.
     * **Logical Bug 2 (Missing CMI Webhook Verification & Race Condition)**: `def handle_cmi_callback(request):` credits `customer.wallet_balance_mad += request.amount` without checking the HMAC signature against `CMI_WEBHOOK_SECRET` and without an atomic lock.
2. **`samples/research_lab_um6p/`**:
   * `loader.py` & `train_pipeline.py`: Contains student `CNE` IDs (`R139482710`), an internal token for `https://hpc-staging.internal.um6p.ma/api/v1`, and a classic **ML Train/Test Data Leakage bug** (`StandardScaler().fit_transform(X)` called on the full dataset *before* `train_test_split(X, y)`).
3. **`samples/screenshots/devtools_leak.png`**:
   * Write a 25-line Pillow helper script (`generate_sample_screenshots.py`) that programmatically generates a crisp 1200x700 dark-mode mock browser DevTools / Fintech Admin screenshot containing visible text: `Authorization: Bearer eyJhbGciOiJIUzI1NiIs...`, `Customer CIN: AB654321`, `RIB: 011810000012345678901234`, and `Merchant Key: cmi_live_9823749283`. This guarantees Gemma 4's OCR and bounding-box detector hits 100% precision on stage!

## 10. Hour-by-Hour Execution Timeline (From Now Until 17:00 Submission)

* **Phase A (First 15 mins — Sync & Scaffold)**:
  * Create the public GitHub repository with an **MIT License** (`LICENSE`).
  * Commit `barakagate/models.py` and `.barakagate.yaml` so all 4 teammates pull the exact same data contract.
* **Phase B (Next 75 mins — Parallel Core Build across 4 Laptops)**:
  * **Builder 1 (Gemini Pro)**: Completes `config.py` + `llm_router.py` and tests both `gemma-4-26b-a4b-it` (Gemini API) and `gemma4:e4b` (local Ollama).
  * **Builder 2 (ChatGPT Pro)**: Completes `indexer.py` (AST/Regex chunker + symbol graph + BM25) and `scanner.py`.
  * **Builder 3 (Claude Pro)**: Completes `redactor.py`, `cli.py`, `samples/`, and `generate_sample_screenshots.py`.
  * **Builder 4 (Claude Pro)**: Completes `server.py` and `static/index.html` (4-Tab BarakaGate Studio UI).
* **Phase C (Next 45 mins — Integration & End-to-End Test)**:
  * Connect `server.py` and `cli.py` to `scanner.py`, `indexer.py`, and `redactor.py`.
  * Run the 3 sample scenarios (`fintech_morocco`, `research_lab_um6p`, and `devtools_leak.png`) across both **Cloud Gemini API (`gemma-4-26b-a4b-it`)** and **Local Ollama (`gemma4:e4b`)** and save cached fallback responses in `.barakagate/demo_cache.json`.
* **Phase D (Final 45 mins before 17:00 — Phase 1 Judging Proof & OrganizerHQ Submission)**:
  * Run `evaluate_benchmark.py` to populate the empirical accuracy table in `README.md`.
  * Capture 3 screenshots / 1 GIF of the Web Studio (Tab 1 Code & Bug Inspector, Tab 2 Screenshot Bounding-Box Blur, Tab 3 Hybrid Local-to-Cloud Firewall) and embed them at the top of `README.md`.
  * Verify `skills/barakagate/SKILL.md` is committed.
  * **Submit on OrganizerHQ before 16:45** (selecting **both** Case 01 and Case 02) and verify the repo opens in an incognito browser window.
