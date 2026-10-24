"""Pure-Python codebase chunker, symbol graph and BM25 context retriever (spec §4).

Stage 1  structural chunking: Python via ``ast`` (functions, classes and module-level
         UPPER_CASE constants), TS/JS via regex + brace counting, ``.ipynb`` code cells
         (text outputs rendered as comments, PNG outputs extracted for vision) and
         80-line / 10-overlap windows for config & data fixtures.
Stage 2  incremental storage in ``<root>/.plutonium/index.json`` keyed by file sha256.
Stage 3  ``get_context_for_target``: 1-hop symbol graph -> semantic hints -> BM25 -> budget.

No chromadb / faiss / tree-sitter: everything here is the standard library.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import keyword
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from plutonium.config import PlutoniumConfig, load_config
from plutonium.models import CodeChunk, EngineMode, IndexStats

INDEX_VERSION = 2
MAX_FILE_BYTES = 1_000_000
WINDOW = 80
OVERLAP = 10

PY_EXT = {".py"}
TS_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
NB_EXT = {".ipynb"}
WINDOW_EXT = {".json", ".yaml", ".yml", ".sql", ".env", ".csv", ".toml", ".ini", ".cfg", ".txt"}

CLOUD_MAX_CHUNKS = 15
LOCAL_MAX_CHUNKS = 3
LOCAL_MAX_CHARS = 2500

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CONST_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_STOP = set(keyword.kwlist) | {
    "self", "cls", "none", "true", "false", "return", "def", "class", "import", "from",
    "the", "and", "for", "in", "of", "to", "is", "it", "a", "an", "str", "int", "float",
    "list", "dict", "const", "let", "var", "function", "export", "async", "await", "new",
}


# --------------------------------------------------------------------------- tokens / BM25
def _split_ident(ident: str) -> List[str]:
    parts: List[str] = []
    for piece in ident.split("_"):
        if not piece:
            continue
        parts.extend(re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", piece))
    return parts


def tokenize(text: str) -> List[str]:
    """Identifier tokenizer: full identifier + camelCase / snake_case parts, lowercased."""
    out: List[str] = []
    for ident in _IDENT.findall(text or ""):
        low = ident.lower()
        if len(low) < 2 or low in _STOP:
            continue
        out.append(low)
        parts = _split_ident(ident)
        if len(parts) > 1:
            out.extend(p.lower() for p in parts if len(p) > 1 and p.lower() not in _STOP)
    return out


class BM25:
    """Okapi BM25 over pre-tokenized documents (pure Python, ~30 lines)."""

    def __init__(self, docs: List[List[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.docs = docs
        self.tfs = [Counter(d) for d in docs]
        self.lens = [len(d) for d in docs]
        self.n = len(docs)
        self.avgdl = (sum(self.lens) / self.n) if self.n else 0.0
        df: Counter = Counter()
        for tf in self.tfs:
            df.update(tf.keys())
        self.idf = {t: math.log(1 + (self.n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def score(self, query_tokens: Iterable[str]) -> List[float]:
        q = Counter(query_tokens)
        scores = [0.0] * self.n
        if not self.n or not q:
            return scores
        for i, tf in enumerate(self.tfs):
            norm = self.k1 * (1 - self.b + self.b * self.lens[i] / (self.avgdl or 1.0))
            s = 0.0
            for term, qf in q.items():
                f = tf.get(term)
                if f:
                    s += self.idf.get(term, 0.0) * (f * (self.k1 + 1)) / (f + norm) * (1 + math.log(qf))
            scores[i] = s
        return scores


# --------------------------------------------------------------------------- helpers
def _sha(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest()


def _chunk_id(rel: str, symbol: str, start: int) -> str:
    return hashlib.sha1(f"{rel}:{symbol}:{start}".encode()).hexdigest()[:12]


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _is_secret_file(rel: str) -> bool:
    name = rel.replace("\\", "/").rsplit("/", 1)[-1]
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def render_notebook(nb_text: str, nb_name: str = "notebook",
                    image_dir: Optional[Path] = None) -> Tuple[str, List[dict], List[str]]:
    """Render an .ipynb as line-numbered-friendly text.

    Returns (rendered_text, cells, image_paths); ``cells`` holds dicts with idx/start/end/
    source/code for code cells (lines are 1-based in the rendered text). Text outputs are
    included as ``# [out]`` comments so leaks in saved outputs are visible to scanners;
    ``image/png`` outputs are written to ``image_dir`` when given.
    """
    try:
        nb = json.loads(nb_text)
    except (json.JSONDecodeError, TypeError):
        return nb_text, [], []
    lines: List[str] = []
    cells: List[dict] = []
    images: List[str] = []
    for idx, cell in enumerate(nb.get("cells") or []):
        ctype = cell.get("cell_type", "code")
        src = cell.get("source", "")
        src = "".join(src) if isinstance(src, list) else str(src or "")
        header_ln = len(lines) + 1
        lines.append(f"# %% [cell {idx}] {ctype}")
        if ctype != "code":
            lines.extend(f"# {ln}" for ln in src.splitlines())
            continue
        src_lines = src.splitlines()
        lines.extend(src_lines)
        n_img = 0
        for out in cell.get("outputs") or []:
            texts: List[str] = []
            if out.get("output_type") == "stream":
                t = out.get("text", "")
                texts.append("".join(t) if isinstance(t, list) else str(t))
            elif out.get("output_type") == "error":
                texts.append(f"{out.get('ename', '')}: {out.get('evalue', '')}")
            data = out.get("data") or {}
            if "text/plain" in data and out.get("output_type") != "stream":
                t = data["text/plain"]
                texts.append("".join(t) if isinstance(t, list) else str(t))
            for t in texts:
                lines.extend(f"# [out] {ln}" for ln in t.splitlines())
            png = data.get("image/png")
            if png:
                n_img += 1
                img_name = f"{nb_name}_cell{idx}_{n_img}.png"
                if image_dir is not None:
                    try:
                        image_dir.mkdir(parents=True, exist_ok=True)
                        payload = "".join(png) if isinstance(png, list) else str(png)
                        target = image_dir / img_name
                        target.write_bytes(base64.b64decode(payload))
                        images.append(str(target))
                    except (OSError, ValueError):
                        pass
                lines.append(f"# [out:image/png] {img_name}")
        end_ln = len(lines)
        cells.append({"idx": idx, "start": header_ln, "end": end_ln, "source": src,
                      "code": "\n".join(lines[header_ln - 1:end_ln])})
    return "\n".join(lines) + "\n", cells, images


def _py_names_in(node: ast.AST) -> List[str]:
    seen: Dict[str, None] = {}
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            seen.setdefault(sub.id, None)
        elif isinstance(sub, ast.Attribute):
            seen.setdefault(sub.attr, None)
    return list(seen)


def _py_module_imports(tree: ast.Module) -> List[str]:
    names: List[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                names.append(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                names.append(a.asname or a.name)
    return names


_TS_START = [
    re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?"
               r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=>"),
]
_TS_IMPORT = re.compile(r"import\s+(?:type\s+)?(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{([^}]*)\})?"
                        r"(?:\*\s+as\s+([A-Za-z_$][\w$]*))?\s*from\s*['\"]")


# --------------------------------------------------------------------------- indexer
class CodebaseIndexer:
    def __init__(self, root: str | Path = ".", config: Optional[PlutoniumConfig] = None):
        self.root = Path(root).resolve()
        self.config = config or load_config(self.root)
        self.index_path = self.root / ".plutonium" / "index.json"
        self.image_dir = self.root / ".plutonium" / "tmp_nb_images"
        self.chunks: List[CodeChunk] = []
        self.symbol_map: Dict[str, CodeChunk] = {}
        self.symbols_by_name: Dict[str, List[CodeChunk]] = {}
        self.notebook_images: List[str] = []
        self._files: Dict[str, dict] = {}
        self._built = False
        self._bm25: Optional[BM25] = None
        self.last_graph_hits = 0

    # ------------------------------------------------------------------ paths
    def rel(self, path: str | Path) -> str:
        """Root-relative posix path for a file given absolute, cwd-relative or root-relative."""
        p = Path(path)
        cands = [p] if p.is_absolute() else [Path.cwd() / p, self.root / p]
        for c in cands:
            try:
                return c.resolve().relative_to(self.root).as_posix()
            except ValueError:
                continue
        return p.as_posix()

    def _iter_files(self) -> Iterable[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = Path(dirpath).relative_to(self.root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir + "/"
            dirnames[:] = sorted(d for d in dirnames
                                 if not self.config.is_ignored_path(f"{rel_dir}{d}/")
                                 and d not in (".git", ".plutonium", "__pycache__", "node_modules"))
            for fn in sorted(filenames):
                rel = f"{rel_dir}{fn}"
                if self.config.is_ignored_path(rel):
                    continue
                if self._supported(Path(fn)):
                    yield Path(dirpath) / fn

    @staticmethod
    def _supported(p: Path) -> bool:
        ext = p.suffix.lower()
        return (ext in PY_EXT or ext in TS_EXT or ext in NB_EXT or ext in WINDOW_EXT
                or _is_secret_file(p.name))

    # ------------------------------------------------------------------ build
    def build(self, force: bool = False) -> IndexStats:
        old: Dict[str, dict] = {}
        if not force and self.index_path.is_file():
            try:
                data = json.loads(self.index_path.read_text(encoding="utf-8"))
                if data.get("version") == INDEX_VERSION:
                    old = data.get("files") or {}
            except (json.JSONDecodeError, OSError):
                old = {}
        files: Dict[str, dict] = {}
        indexed = reused = 0
        for path in self._iter_files():
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            if _is_binary(raw):
                continue
            content = raw.decode("utf-8", "replace")
            rel = path.relative_to(self.root).as_posix()
            sha = _sha(content)
            prev = old.get(rel)
            if prev and prev.get("sha256") == sha and all(Path(i).is_file() for i in prev.get("images", [])):
                files[rel] = prev
                reused += 1
                continue
            chunks, images = self._chunk_content(rel, content, sha)
            files[rel] = {"sha256": sha, "chunks": [c.model_dump() for c in chunks], "images": images}
            indexed += 1
        self._files = files
        self._load_from_files()
        try:
            self.index_path.parent.mkdir(parents=True, exist_ok=True)
            self.index_path.write_text(json.dumps({"version": INDEX_VERSION, "files": files}, ensure_ascii=False),
                                       encoding="utf-8")
        except OSError:
            pass
        self._built = True
        return IndexStats(files_indexed=indexed, files_reused=reused, chunks=len(self.chunks),
                          symbols=len(self.symbol_map), notebook_images=list(self.notebook_images))

    def ensure_built(self) -> None:
        if not self._built:
            self.build()

    def _load_from_files(self) -> None:
        self.chunks = []
        self.notebook_images = []
        for rel in sorted(self._files):
            entry = self._files[rel]
            self.chunks.extend(CodeChunk(**c) for c in entry.get("chunks", []))
            self.notebook_images.extend(entry.get("images", []))
        self.symbol_map = {}
        self.symbols_by_name = {}
        for c in self.chunks:
            if c.chunk_type in ("function", "class", "module", "interface") and not c.symbol_name.startswith("<"):
                if "#L" in c.symbol_name:
                    continue
                self.symbols_by_name.setdefault(c.symbol_name, []).append(c)
                self.symbol_map.setdefault(c.symbol_name, c)
        self._bm25 = BM25([tokenize(c.symbol_name + "\n" + c.code) for c in self.chunks])

    def stats(self) -> IndexStats:
        self.ensure_built()
        return IndexStats(files_indexed=len(self._files), files_reused=0, chunks=len(self.chunks),
                          symbols=len(self.symbol_map), notebook_images=list(self.notebook_images))

    def chunks_for_file(self, path: str | Path) -> List[CodeChunk]:
        self.ensure_built()
        rel = self.rel(path)
        return [c for c in self.chunks if c.file_path == rel]

    def notebook_images_for(self, path: str | Path) -> List[str]:
        self.ensure_built()
        entry = self._files.get(self.rel(path)) or {}
        return list(entry.get("images", []))

    # ------------------------------------------------------------------ chunking
    def chunk_file(self, path: Path | str) -> List[CodeChunk]:
        p = Path(path)
        if not p.is_absolute():
            p = (self.root / p) if (self.root / p).exists() else p.resolve()
        content = p.read_text(encoding="utf-8", errors="replace")
        chunks, images = self._chunk_content(self.rel(p), content, _sha(content))
        for i in images:
            if i not in self.notebook_images:
                self.notebook_images.append(i)
        return chunks

    def _chunk_content(self, rel: str, content: str, sha: str) -> Tuple[List[CodeChunk], List[str]]:
        ext = Path(rel).suffix.lower()
        if ext in PY_EXT:
            return self._chunk_python(rel, content, sha), []
        if ext in TS_EXT:
            return self._chunk_ts(rel, content, sha), []
        if ext in NB_EXT:
            return self._chunk_notebook(rel, content, sha)
        return self._chunk_windows(rel, content, sha), []

    def _mk(self, rel, symbol, ctype, start, end, code, imports, called, sha) -> CodeChunk:
        return CodeChunk(chunk_id=_chunk_id(rel, symbol, start), file_path=rel, symbol_name=symbol,
                         chunk_type=ctype, start_line=start, end_line=end, code=code,
                         imports=list(imports), called_symbols=list(called), sha256=sha)

    def _chunk_python(self, rel: str, content: str, sha: str) -> List[CodeChunk]:
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return self._chunk_windows(rel, content, sha)
        lines = content.splitlines()
        imports = _py_module_imports(tree)
        out: List[CodeChunk] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                end = node.end_lineno or node.lineno
                ctype = "class" if isinstance(node, ast.ClassDef) else "function"
                called = [n for n in _py_names_in(node) if n != node.name]
                out.append(self._mk(rel, node.name, ctype, start, end, "\n".join(lines[start - 1:end]),
                                    imports, called, sha))
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [t.id for t in targets if isinstance(t, ast.Name) and _CONST_NAME.match(t.id)]
                if not names:
                    continue
                start, end = node.lineno, node.end_lineno or node.lineno
                called = [n for n in _py_names_in(node) if n not in names]
                for name in names:
                    out.append(self._mk(rel, name, "module", start, end, "\n".join(lines[start - 1:end]),
                                        imports, called, sha))
        if not out and content.strip():
            out = self._chunk_windows(rel, content, sha)
        return out

    def _chunk_ts(self, rel: str, content: str, sha: str) -> List[CodeChunk]:
        lines = content.splitlines()
        imports: List[str] = []
        for m in _TS_IMPORT.finditer(content):
            if m.group(1):
                imports.append(m.group(1))
            if m.group(2):
                for part in m.group(2).split(","):
                    part = part.strip()
                    if part:
                        imports.append(part.split(" as ")[-1].strip())
            if m.group(3):
                imports.append(m.group(3))
        out: List[CodeChunk] = []
        i = 0
        while i < len(lines):
            name, kind = None, None
            for k, rx in enumerate(_TS_START):
                m = rx.match(lines[i])
                if m:
                    name = m.group(1)
                    kind = ("function", "class", "interface", "function")[k]
                    break
            if not name:
                i += 1
                continue
            depth, seen_brace, j = 0, False, i
            while j < len(lines):
                code_line = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", "", lines[j])
                code_line = code_line.split("//", 1)[0]
                depth += code_line.count("{") - code_line.count("}")
                if "{" in code_line:
                    seen_brace = True
                if seen_brace and depth <= 0:
                    break
                if not seen_brace and code_line.rstrip().endswith(";"):
                    break
                j += 1
            j = min(j, len(lines) - 1)
            code = "\n".join(lines[i:j + 1])
            called = [t for t in dict.fromkeys(_IDENT.findall(code)) if t != name and t not in _STOP]
            out.append(self._mk(rel, name, kind, i + 1, j + 1, code, imports, called, sha))
            i = j + 1
        if not out and content.strip():
            out = self._chunk_windows(rel, content, sha)
        return out

    def _chunk_notebook(self, rel: str, content: str, sha: str) -> Tuple[List[CodeChunk], List[str]]:
        stem = Path(rel).stem
        _, cells, images = render_notebook(content, stem, self.image_dir)
        out: List[CodeChunk] = []
        imports: List[str] = []
        for cell in cells:
            for m in re.finditer(r"^\s*(?:from\s+[\w.]+\s+)?import\s+([^\n#]+)", cell["source"], re.M):
                for part in m.group(1).replace("(", "").replace(")", "").split(","):
                    part = part.strip()
                    if part:
                        imports.append(part.split(" as ")[-1].strip().split(".")[0])
        for cell in cells:
            called = [t for t in dict.fromkeys(_IDENT.findall(cell["source"])) if t not in _STOP]
            out.append(self._mk(rel, f"cell_{cell['idx']}", "notebook_cell", cell["start"], cell["end"],
                                cell["code"], imports, called, sha))
        return out, images

    def _chunk_windows(self, rel: str, content: str, sha: str) -> List[CodeChunk]:
        lines = content.splitlines()
        out: List[CodeChunk] = []
        if not lines:
            return out
        name = Path(rel).name
        start = 0
        while True:
            end = min(start + WINDOW, len(lines))
            code = "\n".join(lines[start:end])
            called = [t for t in dict.fromkeys(_IDENT.findall(code)) if t not in _STOP][:200]
            out.append(self._mk(rel, f"{name}#L{start + 1}-{end}", "module", start + 1, end, code, [], called, sha))
            if end >= len(lines):
                break
            start = end - OVERLAP
        return out

    # ------------------------------------------------------------------ retrieval
    def get_context_for_target(self, text: str, target_files: Optional[List[str]] = None,
                               mode: EngineMode = EngineMode.CLOUD_FAST,
                               max_chunks: Optional[int] = None,
                               max_chars: Optional[int] = None) -> List[CodeChunk]:
        """Cross-file context: (A) 1-hop symbol graph, (A2) semantic hints, (B) BM25, (C) budget."""
        self.ensure_built()
        mode = EngineMode(mode)
        targets = {self.rel(t) for t in (target_files or [])}
        excluded = lambda c: c.file_path in targets or _is_secret_file(c.file_path)  # noqa: E731

        # `from X import Y` -> prefer the definition of Y living in module X.
        import_src: Dict[str, str] = {}
        for m in re.finditer(r"^\s*from\s+\.*([\w.]*)\s+import\s+\(?([^\n)]+)", text or "", re.M):
            mod = m.group(1).split(".")[-1]
            for part in m.group(2).split(","):
                nm = part.strip().split(" as ")[0].strip()
                if nm and nm != "*":
                    import_src[nm] = mod
        local_defs = set(re.findall(r"^\s*(?:async\s+)?(?:def|class)\s+(\w+)", text or "", re.M))
        local_defs |= set(re.findall(r"^([A-Z][A-Z0-9_]*)\s*[:=]", text or "", re.M))

        picked: List[CodeChunk] = []
        seen: set = set()

        def add(c: CodeChunk) -> None:
            if c.chunk_id not in seen and not excluded(c):
                seen.add(c.chunk_id)
                picked.append(c)

        # Step A: 1-hop symbol graph resolution, in order of first mention.
        for ident in dict.fromkeys(_IDENT.findall(text or "")):
            cands = [c for c in self.symbols_by_name.get(ident, []) if not excluded(c)]
            if not cands or (ident in local_defs and ident not in import_src):
                continue
            mod = import_src.get(ident)
            if mod:
                cands.sort(key=lambda c: Path(c.file_path).stem != mod)
            add(cands[0])
        graph_hits = len(picked)

        # Step A2: semantic hints for config constants the target implicitly depends on.
        hint_patterns: List[str] = []
        if re.search(r"\b(random\.|np\.random|torch\.(rand|manual_seed)|shuffle\(|train_test_split)", text or ""):
            hint_patterns.append(r"SEED|RANDOM_STATE")
        if re.search(r"\b(sum\(|mean\(|average|/\s*len\()", text or ""):
            hint_patterns.append(r"SENTINEL|MISSING|NODATA|NAN_VALUE")
        if re.search(r"(callback|webhook|ipn)", text or "", re.I):
            hint_patterns.append(r"WEBHOOK|SIGNING|HMAC|MERCHANT_SECRET")
        if hint_patterns:
            rx = re.compile("|".join(hint_patterns))
            for c in self.chunks:
                if c.chunk_type == "module" and "#L" not in c.symbol_name and rx.search(c.symbol_name):
                    add(c)

        # Step B: BM25 over identifier tokens for the remaining chunks.
        if self._bm25 is not None and self.chunks:
            scores = self._bm25.score(tokenize(text or ""))
            # Structural chunks (definitions) beat raw data windows of equal lexical overlap.
            scores = [s * (0.5 if "#L" in c.symbol_name else 1.0) for s, c in zip(scores, self.chunks)]
            ranked = sorted(range(len(self.chunks)), key=lambda i: -scores[i])
            for i in ranked:
                if scores[i] <= 0:
                    break
                add(self.chunks[i])

        # Step C: token budget packing.
        if max_chunks is None:
            max_chunks = LOCAL_MAX_CHUNKS if mode in (EngineMode.LOCAL_EDGE, EngineMode.HYBRID_SMART) \
                else CLOUD_MAX_CHUNKS
        if max_chars is None and mode in (EngineMode.LOCAL_EDGE, EngineMode.HYBRID_SMART):
            max_chars = LOCAL_MAX_CHARS
        out: List[CodeChunk] = []
        used = 0
        for c in picked:
            if len(out) >= max_chunks:
                break
            if max_chars is not None and used + len(c.code) > max_chars:
                continue
            out.append(c)
            used += len(c.code)
        self.last_graph_hits = min(graph_hits, len(out))
        return out
