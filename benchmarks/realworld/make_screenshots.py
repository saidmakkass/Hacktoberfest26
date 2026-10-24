"""Generate the held-out benchmark screenshots + pixel-exact ground truth.

Ground truth goes to screenshots/_truth.json (NOT the `<png>.boxes.json` sidecar the scanner can read
as an offline cache), so only a real vision model can score on these images.
"""
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "screenshots"


def font(size, mono=True):
    for p in (["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"] if mono else []) + \
             ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]:
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default(size=size)


def norm(box, w, h):
    x1, y1, x2, y2 = box
    return [round(y1 / h * 1000), round(x1 / w * 1000), round(y2 / h * 1000), round(x2 / w * 1000)]


def terminal(truth):
    w, h = 1280, 560
    im = Image.new("RGB", (w, h), "#1e1f29"); d = ImageDraw.Draw(im); f = font(22)
    d.rectangle([0, 0, w, 40], fill="#2b2d3a")
    for i, c in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
        d.ellipse([16 + i * 26, 12, 32 + i * 26, 28], fill=c)
    d.text((540, 9), "salma@oasis-lab: ~", font=font(18, False), fill="#c8c8d0")
    rows = [("$ env | sort", None), ("HOME=/home/salma", None),
            ("OPENAI_API_KEY=", "sk-proj-Rb7kQ2xW9mN4pL6tV1yZ8cH3"),
            ("PATH=/usr/local/bin:/usr/bin:/bin", None), ("SHELL=/bin/zsh", None),
            ("STRIPE_SECRET_KEY=", "sk_live_51Hc8TqLmN2pR5vX7zA9bK3d"), ("TERM=xterm-256color", None)]
    y = 70
    for prefix, secret in rows:
        d.text((30, y), prefix, font=f, fill="#50fa7b" if prefix.startswith("$") else "#f8f8f2")
        if secret:
            x = 30 + d.textlength(prefix, font=f)
            d.text((x, y), secret, font=f, fill="#f8f8f2")
            truth.append({"image": "terminal_env.png", "kind": prefix.rstrip("=").lower(),
                          "keywords": ["openai", "sk-proj"] if "OPENAI" in prefix else ["stripe", "sk_live"],
                          "bbox_2d": norm(d.textbbox((x, y), secret, font=f), w, h)})
        y += 62
    im.save(OUT / "terminal_env.png")


def cin_card(truth):
    w, h = 1000, 620
    im = Image.new("RGB", (w, h), "#e9e4d8"); d = ImageDraw.Draw(im)
    d.rounded_rectangle([40, 40, w - 40, h - 40], 28, fill="#f4efe2", outline="#8a7f63", width=3)
    d.text((80, 70), "ROYAUME DU MAROC", font=font(30, False), fill="#7a1f1f")
    d.text((80, 112), "CARTE NATIONALE D'IDENTITE", font=font(24, False), fill="#333")
    d.text((650, 72), "SPECIMEN", font=font(34, False), fill="#c0392b")
    d.rectangle([80, 170, 300, 440], fill="#cfc8b6", outline="#8a7f63")
    d.text((140, 290), "PHOTO", font=font(26, False), fill="#7d7563")
    fields = [("Nom / Name:", "BENJELLOUN", "name"), ("Prenom:", "Salma", "name"),
              ("Ne(e) le:", "12.03.1998 a Fes", None), ("N° CIN:", "BK482913", "cin")]
    y = 190
    for label, value, kind in fields:
        d.text((340, y), label, font=font(24, False), fill="#555")
        fv = font(30, False)
        d.text((560, y - 3), value, font=fv, fill="#111")
        if kind:
            truth.append({"image": "cin_card.png", "kind": kind,
                          "keywords": ["cin", "national", "identit", "id number"] if kind == "cin" else ["name", "nom", "prenom", "holder"],
                          "bbox_2d": norm(d.textbbox((560, y - 3), value, font=fv), w, h)})
        y += 62
    im.save(OUT / "cin_card.png")


def clean_dashboard(truth):
    w, h = 1200, 520
    im = Image.new("RGB", (w, h), "#0f172a"); d = ImageDraw.Draw(im)
    d.text((40, 30), "Souk.ma — Daily KPIs", font=font(30, False), fill="#e2e8f0")
    for i, (k, v) in enumerate([("Orders today", "1,284"), ("Revenue", "312,450 MAD"), ("Conversion", "3.2 %"),
                                ("Avg basket", "243 MAD")]):
        x = 40 + i * 285
        d.rounded_rectangle([x, 110, x + 260, 260], 16, fill="#1e293b")
        d.text((x + 20, 130), k, font=font(20, False), fill="#94a3b8")
        d.text((x + 20, 180), v, font=font(34, False), fill="#f8fafc")
    for i in range(12):
        d.rectangle([60 + i * 90, 470 - (i * 37 % 160) - 40, 110 + i * 90, 470], fill="#22c55e")
    im.save(OUT / "clean_dashboard.png")  # negative control: no truth entries


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    truth: list = []
    terminal(truth); cin_card(truth); clean_dashboard(truth)
    (OUT / "_truth.json").write_text(json.dumps(truth, indent=1), encoding="utf-8")
    print(f"wrote 3 images, {len(truth)} ground-truth boxes")
