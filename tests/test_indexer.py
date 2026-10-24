import base64
import json
import shutil

import pytest

from barakagate.indexer import BM25, CodebaseIndexer, tokenize
from barakagate.models import EngineMode


@pytest.fixture
def samples(tmp_path, project_root):
    dst = tmp_path / "samples"
    shutil.copytree(project_root / "samples", dst, ignore=shutil.ignore_patterns(".barakagate", "*.png"))
    return dst


@pytest.fixture
def fintech(tmp_path, project_root):
    dst = tmp_path / "fintech"
    shutil.copytree(project_root / "samples" / "fintech_morocco", dst,
                    ignore=shutil.ignore_patterns(".barakagate", "__pycache__"))
    return dst


def _labels(chunks):
    return [f"{c.file_path}:{c.symbol_name}" for c in chunks]


def test_tokenize_splits_camel_and_snake():
    toks = tokenize("MoroccanCustomer wallet_balance_mad CMI_WEBHOOK_SECRET getHTTPResponse")
    assert "moroccancustomer" in toks and "moroccan" in toks and "customer" in toks
    assert {"wallet", "balance", "mad"} <= set(toks)
    assert {"cmi", "webhook", "secret"} <= set(toks)
    assert "response" in toks and "http" in toks


def test_bm25_ranking_sanity():
    docs = [tokenize("def apply_discounts(price, discounts_pct): total_pct = sum(discounts_pct)"),
            tokenize("def get_conn(): return sqlite3.connect('app.db')"),
            tokenize("SEED = 42")]
    scores = BM25(docs).score(tokenize("discounts = apply_discounts(price, discounts)"))
    assert scores[0] > scores[1] and scores[0] > scores[2]
    assert BM25([]).score(["x"]) == []


def test_python_chunking_and_symbol_map(fintech):
    ix = CodebaseIndexer(fintech)
    stats = ix.build()
    assert stats.files_indexed == 3 and stats.chunks > 0
    assert "MoroccanCustomer" in ix.symbol_map and "CMI_WEBHOOK_SECRET" in ix.symbol_map
    cust = ix.symbol_map["MoroccanCustomer"]
    assert cust.file_path == "models.py" and cust.chunk_type == "class"
    assert "cin_number" in cust.code and cust.start_line == 8  # includes @dataclass decorator
    secret = ix.symbol_map["CMI_WEBHOOK_SECRET"]
    assert secret.chunk_type == "module" and "cmi_live_sk" in secret.code
    checkout = ix.symbol_map["checkout"]
    assert "MoroccanCustomer" in checkout.imports and "CMI_WEBHOOK_SECRET" in checkout.imports
    assert "compute_total" in checkout.called_symbols and "wallet_balance_mad" in checkout.called_symbols
    assert (fintech / ".barakagate" / "index.json").is_file()


def test_syntax_error_falls_back_to_windows(tmp_path):
    (tmp_path / "broken.py").write_text("def oops(:\n    pass\n")
    ix = CodebaseIndexer(tmp_path)
    ix.build()
    assert ix.chunks and ix.chunks[0].symbol_name.startswith("broken.py#L1")


def test_ts_chunking(tmp_path):
    (tmp_path / "pay.ts").write_text(
        "import { Customer, CMI_KEY } from './models';\n"
        "import axios from 'axios';\n\n"
        "export interface Payload {\n  amount: number;\n}\n\n"
        "export async function charge(c: Customer, amount: number) {\n"
        "  if (amount > 0) {\n    return axios.post('/pay', { amount });\n  }\n  return null;\n}\n\n"
        "export const fee = (x: number) => {\n  return x * 0.2;\n};\n\n"
        "class Wallet {\n  balance = 0;\n}\n")
    ix = CodebaseIndexer(tmp_path)
    ix.build()
    by = {c.symbol_name: c for c in ix.chunks}
    assert set(by) >= {"Payload", "charge", "fee", "Wallet"}
    assert by["charge"].start_line == 8 and by["charge"].end_line == 13
    assert by["fee"].end_line == 17
    assert {"Customer", "CMI_KEY", "axios"} <= set(by["charge"].imports)


def test_notebook_cells_outputs_and_images(tmp_path):
    png = base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode()
    nb = {"cells": [
        {"cell_type": "markdown", "source": ["# title"]},
        {"cell_type": "code", "source": ["import pandas as pd\n", "df.head()"],
         "outputs": [{"output_type": "execute_result", "data": {"text/plain": ["cne R139482710"]}}]},
        {"cell_type": "code", "source": "df.plot()",
         "outputs": [{"output_type": "display_data", "data": {"image/png": png, "text/plain": "<Figure>"}}]},
    ], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    (tmp_path / "lab.ipynb").write_text(json.dumps(nb))
    ix = CodebaseIndexer(tmp_path)
    stats = ix.build()
    cells = [c for c in ix.chunks if c.chunk_type == "notebook_cell"]
    assert [c.symbol_name for c in cells] == ["cell_1", "cell_2"]
    assert "R139482710" in cells[0].code  # text outputs are visible to scanners
    assert len(stats.notebook_images) == 1
    img = stats.notebook_images[0]
    assert img.endswith("lab_cell2_1.png") and ".barakagate/tmp_nb_images" in img.replace("\\", "/")
    assert ix.notebook_images_for(tmp_path / "lab.ipynb") == [img]


def test_config_windows(tmp_path):
    (tmp_path / "data.json").write_text("\n".join(f'"k{i}": {i},' for i in range(200)))
    (tmp_path / "seed.sql").write_text("INSERT INTO t VALUES (1);\n")
    ix = CodebaseIndexer(tmp_path)
    ix.build()
    wins = [c for c in ix.chunks if c.file_path == "data.json"]
    assert [(c.start_line, c.end_line) for c in wins] == [(1, 80), (71, 150), (141, 200)]
    assert any(c.file_path == "seed.sql" for c in ix.chunks)


def test_skips_binary_large_and_ignored(tmp_path):
    (tmp_path / "bin.json").write_bytes(b"\x00\x01\x02")
    (tmp_path / "big.csv").write_text("a,b\n" * 300_000)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("function x() { return 1; }\n")
    (tmp_path / "ok.py").write_text("def ok():\n    return 1\n")
    ix = CodebaseIndexer(tmp_path)
    ix.build()
    assert {c.file_path for c in ix.chunks} == {"ok.py"}


def test_incremental_reuse_via_sha(fintech):
    ix = CodebaseIndexer(fintech)
    first = ix.build()
    assert first.files_indexed == 3 and first.files_reused == 0
    again = CodebaseIndexer(fintech).build()
    assert again.files_indexed == 0 and again.files_reused == 3
    (fintech / "fees.py").write_text((fintech / "fees.py").read_text() + "\n\ndef refund(x):\n    return x\n")
    ix3 = CodebaseIndexer(fintech)
    third = ix3.build()
    assert third.files_indexed == 1 and third.files_reused == 2
    assert "refund" in ix3.symbol_map
    assert CodebaseIndexer(fintech).build(force=True).files_indexed == 3


def test_context_symbol_graph_first(fintech):
    ix = CodebaseIndexer(fintech)
    text = (fintech / "checkout.py").read_text()
    ctx = ix.get_context_for_target(text, [str(fintech / "checkout.py")], EngineMode.CLOUD_FAST)
    labels = _labels(ctx)
    assert not any(lbl.startswith("checkout.py") for lbl in labels)
    head = labels[:4]
    assert "models.py:MoroccanCustomer" in head
    assert "models.py:CMI_WEBHOOK_SECRET" in head
    assert "fees.py:apply_discounts" in head
    assert len(ctx) <= 15


def test_context_from_import_prefers_named_module(tmp_path):
    (tmp_path / "a.py").write_text("def helper():\n    return 'a'\n")
    (tmp_path / "b.py").write_text("def helper():\n    return 'b'\n")
    ix = CodebaseIndexer(tmp_path)
    ctx = ix.get_context_for_target("from b import helper\nhelper()\n", ["main.py"])
    assert _labels(ctx)[0] == "b.py:helper"


def test_context_local_budget(samples):
    ix = CodebaseIndexer(samples)
    text = (samples / "fintech_morocco" / "checkout.py").read_text()
    for mode in (EngineMode.LOCAL_EDGE, EngineMode.HYBRID_SMART):
        ctx = ix.get_context_for_target(text, ["fintech_morocco/checkout.py"], mode)
        assert 1 <= len(ctx) <= 3
        assert sum(len(c.code) for c in ctx) <= 2500
        assert _labels(ctx)[0] == "fintech_morocco/models.py:CMI_WEBHOOK_SECRET"
    cloud = ix.get_context_for_target(text, ["fintech_morocco/checkout.py"], EngineMode.CLOUD_DEEP)
    assert 3 < len(cloud) <= 15


def test_context_semantic_hints_pull_config_constants(samples):
    ix = CodebaseIndexer(samples)
    text = (samples / "research_lab_um6p" / "train_pipeline.py").read_text()
    labels = _labels(ix.get_context_for_target(text, ["research_lab_um6p/train_pipeline.py"]))
    assert "research_lab_um6p/loader.py:STUDENTS" in labels[:3]
    assert "research_lab_um6p/config.py:SEED" in labels
    assert "research_lab_um6p/config.py:MISSING_SENTINEL" in labels


def test_context_never_ships_env_files(tmp_path):
    (tmp_path / ".env").write_text("GEMINI_API_KEY=supersecretvalue\n")
    (tmp_path / "app.py").write_text("import os\nKEY = os.getenv('GEMINI_API_KEY')\n")
    ix = CodebaseIndexer(tmp_path)
    ix.build()
    assert any(c.file_path == ".env" for c in ix.chunks)
    ctx = ix.get_context_for_target("GEMINI_API_KEY supersecretvalue", ["other.py"])
    assert all(c.file_path != ".env" for c in ctx)
