"""Leak-through of the deterministic on-device sanitizer (Safe-to-Prompt firewall) on the held-out fixtures.

    python3 benchmarks/firewall_bench.py

For every raw sensitive value planted in benchmarks/realworld, sanitize the whole file the way the firewall /
hybrid mode would before a cloud call, and check whether the raw value survives. No LLM is involved, so this
measures the deterministic floor; the local gemma4:e4b pass in hybrid mode is layered on top of it.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from plutonium.redactor import sanitize_prompt  # noqa: E402

F = HERE / "realworld"
VALUES = {
    "Stripe live key": ("souk_shop/config.py", "sk_live_51NxQe2LkT9vB3mZ0pQwErTyUiOp"),
    "DB password": ("souk_shop/config.py", "Atlas2026!"),
    "CIN (JSON fixture)": ("souk_shop/data/test_buyers.json", "JK129834"),
    "IBAN 4-digit groups": ("souk_shop/data/test_buyers.json", "MA64 0117 8000 0001 2345 6789 0123"),
    "Phone, irregular spacing": ("souk_shop/data/test_buyers.json", "+212 6 61 23 45 67"),
    "CIN in Arabic text": ("souk_shop/support/tickets.csv", "K394817"),
    "Phone in Arabic text": ("souk_shop/support/tickets.csv", "0612-345-678"),
    "RIB 4-digit groups": ("souk_shop/support/tickets.csv", "1818 1021 1112 2223 3334 4455"),
    "Full name (French)": ("souk_shop/support/tickets.csv", "Fatima Zahra Alaoui"),
    "Home address (French)": ("souk_shop/support/tickets.csv", "14 rue Ibn Sina"),
    "Split CMI key (2nd half)": ("atlas_wallet_ts/src/config.ts", "88c1f0a9d2e47b3f"),
    "OpenAI key": ("atlas_wallet_ts/src/config.ts", "sk-proj-Xk2v9QmP4tR7wY1zL8nB3cD6fG0hJ5aS"),
    "Student CNE #1": ("oasis_ml_lab/students.csv", "R139482711"),
    "Student CNE #2": ("oasis_ml_lab/students.csv", "D132457890"),
    "Unquoted WANDB key": ("oasis_ml_lab/slurm/train.sbatch", "7c1e4f9a2b8d3e6f0a1b2c3d4e5f6a7b8c9d0e1f"),
    "Internal HPC host": ("oasis_ml_lab/slurm/train.sbatch", "gpu-node03.hpc.um6p.ma"),
    "HF token in notebook output": ("oasis_ml_lab/notebooks/explore.ipynb", "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"),
}

if __name__ == "__main__":
    items = []
    for name, (f, v) in VALUES.items():
        text = (F / f).read_text(encoding="utf-8")
        assert v in text, (name, f)
        sanitized, _ = sanitize_prompt(text)
        items.append({"value": name, "file": f, "removed": v not in sanitized})
    k = sum(i["removed"] for i in items)
    out = HERE / "results" / "firewall.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"removed": k, "total": len(items), "items": items}, indent=1), encoding="utf-8")
    print(f"deterministic sanitizer removed {k}/{len(items)} raw values")
    for i in items:
        print(("  ✅ " if i["removed"] else "  ❌ ") + i["value"])
