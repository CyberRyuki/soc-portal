"""Comparación visual de portales: el contenedor soc-screens hace la captura y aquí se compara.

Se compara con la captura de la versión aprobada: ambas se reducen a escala de grises de 192×126, se suavizan y se
cuenta el % de celdas que cambiaron de forma apreciable. Así no alertan el antialiasing ni pequeños desplazamientos,
pero sí un cambio de portada, un banner nuevo de atacante o una página en blanco.
La imagen de diferencias resalta en rojo las zonas que cambiaron.
"""
import io
import os
import time

import requests

URL = (os.getenv("SCREENS_URL") or "http://soc-screens:8090").rstrip("/")
TOKEN = os.getenv("SCREENS_TOKEN", "")
W, H = 192, 126
PIXEL_DELTA = 32  # diferencia de gris (0-255) a partir de la cual una celda «cambió»


def enabled() -> bool:
    return bool(TOKEN)


def capture(url: str, timeout=75) -> bytes:
    r = requests.post(f"{URL}/shot", json={"url": url}, headers={"X-Token": TOKEN}, timeout=timeout)
    if r.status_code != 200:
        try:
            msg = r.json().get("detail", "")
        except ValueError:
            msg = r.text[:200]
        raise RuntimeError(f"soc-screens {r.status_code}: {msg}")
    return r.content


def health() -> dict:
    try:
        r = requests.get(f"{URL}/health", timeout=5)
        return {"ok": r.ok and r.json().get("token", False), "detalle": "" if r.ok else f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"ok": False, "detalle": f"no responde soc-screens ({type(exc).__name__})"}


def _small(img_bytes):
    from PIL import Image, ImageFilter
    im = Image.open(io.BytesIO(img_bytes)).convert("L").resize((W, H), Image.LANCZOS)
    return im.filter(ImageFilter.GaussianBlur(1))


def compare(base: bytes, now: bytes) -> tuple:
    """(% de la página que cambió, imagen JPEG con las diferencias en rojo)."""
    from PIL import Image, ImageChops
    a, b = _small(base), _small(now)
    d = ImageChops.difference(a, b)
    mask = d.point(lambda v: 255 if v > PIXEL_DELTA else 0)
    changed = mask.histogram()[255] / (W * H) * 100
    cur = Image.open(io.BytesIO(now)).convert("RGB")
    big = mask.resize(cur.size, Image.NEAREST)
    red = Image.new("RGB", cur.size, (230, 30, 30))
    over = Image.composite(Image.blend(cur, red, 0.55), Image.blend(cur, Image.new("RGB", cur.size, (255, 255, 255)), 0.35), big)
    out = io.BytesIO()
    over.save(out, "JPEG", quality=60)
    return round(changed, 1), out.getvalue()


def level(pct: float, change=30, alert=60) -> str:
    return "sospecha" if pct >= alert else "cambio" if pct >= change else "ok"


class Store:
    """Imágenes en /data/screens/<id>/{baseline,current,diff}.jpg."""

    def __init__(self, root: str):
        self.root = root

    def path(self, sid: int, which: str) -> str:
        return os.path.join(self.root, str(int(sid)), f"{which}.jpg")

    def save(self, sid: int, which: str, data: bytes):
        p = self.path(sid, which)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + f".{int(time.time() * 1000)}.tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, p)

    def read(self, sid: int, which: str):
        p = self.path(sid, which)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as fh:
            return fh.read()

    def promote(self, sid: int):
        """La captura actual pasa a ser la aprobada."""
        cur = self.read(sid, "current")
        if cur:
            self.save(sid, "baseline", cur)
        try:
            os.remove(self.path(sid, "diff"))
        except OSError:
            pass

    def remove(self, sid: int):
        for w in ("baseline", "current", "diff"):
            try:
                os.remove(self.path(sid, w))
            except OSError:
                pass
