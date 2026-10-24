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


# ---------------------------------------------------------------------------
# Additive helper models (do not change the contract above)
# ---------------------------------------------------------------------------

class IndexStats(BaseModel):
    files_indexed: int = 0
    files_reused: int = 0
    chunks: int = 0
    symbols: int = 0
    notebook_images: List[str] = Field(default_factory=list)


class LLMFinding(BaseModel):
    """Loose schema the LLM fills in; normalized into `Finding` by `normalize_findings`."""
    category: str
    file_path: str = ""
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    rule_id: str = "gemma.generic"
    severity: str = "MEDIUM"
    confidence: float = 0.8
    title: str = ""
    reason: str = ""
    cross_file_context_used: Optional[str] = None
    offending_snippet: Optional[str] = None
    recommended_action: str = "code_patch"
    replacement_snippet: Optional[str] = None
    env_var_name: Optional[str] = None
    env_var_value: Optional[str] = None
    bbox_2d: Optional[List[int]] = None


class LLMScanResponse(BaseModel):
    summary: str = ""
    thinking_trace: Optional[str] = None
    findings: List[LLMFinding] = Field(default_factory=list)
