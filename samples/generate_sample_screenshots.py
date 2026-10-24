"""Generates the demo screenshots + `<png>.boxes.json` ground-truth sidecars (offline vision cache)."""
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent / "screenshots"


def font(size, mono=True):
    name = "DejaVuSansMono.ttf" if mono else "DejaVuSans-Bold.ttf"
    for d in ("/usr/share/fonts/truetype/dejavu/", "/usr/share/fonts/dejavu/", "/Library/Fonts/", ""):
        try:
            return ImageFont.truetype(d + name, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def render(name, size, chrome, rows):
    """rows: (xy, text, color, finding|None). Findings get bbox_2d from the exact drawn text box."""
    img = Image.new("RGB", size, (24, 26, 31))
    d = ImageDraw.Draw(img)
    chrome(d)
    W, H, boxes = size[0], size[1], []
    for (x, y), text, color, finding in rows:
        f = font(22)
        d.text((x, y), text, fill=color, font=f)
        if finding:
            label, value, cat, sev, reason = finding
            off = d.textlength(text[: text.index(value)], font=f)
            x1, y1, x2, y2 = d.textbbox((x + off, y), value, font=f)
            boxes.append({"label": label, "category": cat, "severity": sev, "value": value, "reason": reason,
                          "bbox_2d": [round(y1 / H * 1000), round(x1 / W * 1000), round(y2 / H * 1000), round(x2 / W * 1000)]})
    OUT.mkdir(exist_ok=True)
    img.save(OUT / name)
    (OUT / f"{name}.boxes.json").write_text(json.dumps(boxes, indent=1, ensure_ascii=False) + "\n")
    return OUT / name


def devtools_chrome(d):
    d.rectangle([0, 0, 1200, 44], fill=(41, 42, 45))
    d.text((16, 10), "Atlas Pay Admin  |  DevTools - Network - /api/v2/checkout", fill=(200, 200, 200), font=font(20, False))
    d.rectangle([0, 44, 1200, 84], fill=(32, 33, 36))
    for i, tab in enumerate(["Elements", "Console", "Sources", "Network", "Application"]):
        d.text((20 + i * 150, 54), tab, fill=(138, 180, 248) if tab == "Network" else (150, 150, 150), font=font(18, False))


def notebook_chrome(d):
    d.rectangle([0, 0, 1200, 50], fill=(240, 240, 240))
    d.text((16, 12), "Jupyter  exploration.ipynb  (dropout risk - UM6P lab)", fill=(30, 30, 30), font=font(20, False))
    d.text((20, 70), "In [3]:  df[['cne', 'name', 'gpa', 'scholarship']].head()", fill=(120, 200, 255), font=font(20))
    d.line([20, 150, 1180, 150], fill=(90, 90, 90), width=1)


G, W, Y, R = (152, 195, 121), (220, 220, 220), (229, 192, 123), (224, 108, 117)
DEVTOOLS = [
    ((24, 110), "Request URL: https://api.atlaspay.ma/v2/checkout/confirm", W, None),
    ((24, 160), "Authorization: Bearer eyJhbGciOiJIUzI1NiIs...", Y,
     ("Bearer JWT token", "eyJhbGciOiJIUzI1NiIs...", "security_leak", "HIGH", "JWT bearer token visible in DevTools headers")),
    ((24, 230), "Response Preview  { order_id: 'AP-20261024-118' }", W, None),
    ((24, 290), "Customer CIN: AB654321", G,
     ("Moroccan CIN", "AB654321", "privacy_pii", "HIGH", "National ID number (Law 09-08 PII) shown in admin panel")),
    ((24, 350), "RIB: 011810000012345678901234", G,
     ("Moroccan 24-digit RIB", "011810000012345678901234", "privacy_pii", "CRITICAL", "Customer bank account (RIB) visible")),
    ((24, 410), "Merchant Key: cmi_live_9823749283", R,
     ("CMI live merchant key", "cmi_live_9823749283", "security_leak", "CRITICAL", "Live CMI payment gateway key visible")),
    ((24, 480), "Status: 200 OK   Time: 182 ms   Size: 2.1 kB", (150, 150, 150), None),
]
CNES = [("R139482710", "Salma Bennani", "15.4", "True"), ("G130045892", "Amine Tazi", "12.1", "False"),
        ("K120398471", "Hiba Alaoui", "17.9", "True"), ("P141127365", "Omar Idrissi", "9.8", "False")]
NOTEBOOK = [((40, 110), "    cne          name              gpa    scholarship", W, None)] + [
    ((40, 170 + i * 60), f"{i}   {cne}   {name:<16}  {gpa:<5}  {sch}", W,
     (f"Student CNE {cne}", cne, "privacy_pii", "HIGH", "Student CNE/Massar identifier in notebook output"))
    for i, (cne, name, gpa, sch) in enumerate(CNES)]

if __name__ == "__main__":
    print(render("devtools_leak.png", (1200, 700), devtools_chrome, DEVTOOLS))
    print(render("notebook_cne_table.png", (1200, 500), notebook_chrome, NOTEBOOK))
