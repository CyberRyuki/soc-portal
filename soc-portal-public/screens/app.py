"""soc-screens: captura de pantalla de portales para la comparación visual (Chromium sin interfaz).

Aislado a propósito: renderizar páginas web de terceros es la parte más arriesgada del portal. Este contenedor
no tiene el .env, ni acceso a los datos, corre como usuario sin privilegios, con sistema de archivos de solo
lectura y memoria limitada. Solo atiende al bridge, que se identifica con SCREENS_TOKEN.
"""
import asyncio
import hmac
import os
from urllib.parse import urlparse

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import Response
from playwright.async_api import async_playwright

TOKEN = os.getenv("SCREENS_TOKEN", "")
PARALLEL = int(os.getenv("SCREENS_PARALLEL", "3") or 3)
CHROME = os.getenv("CHROME_PATH", "/usr/bin/chromium")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131 Safari/537.36 SOC-ACME-monitor"
ARGS = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--no-first-run", "--disable-extensions",
        "--disable-background-networking", "--disable-sync", "--mute-audio", "--hide-scrollbars"]

app = FastAPI(title="soc-screens", docs_url=None, redoc_url=None, openapi_url=None)
sem = asyncio.Semaphore(PARALLEL)
state = {"pw": None, "browser": None, "lock": asyncio.Lock()}


async def browser():
    async with state["lock"]:
        b = state["browser"]
        if b is None or not b.is_connected():
            if state["pw"] is None:
                state["pw"] = await async_playwright().start()
            state["browser"] = await state["pw"].chromium.launch(executable_path=CHROME, args=ARGS, headless=True)
        return state["browser"]


@app.get("/health")
async def health():
    return {"ok": True, "token": bool(TOKEN)}


@app.post("/shot")
async def shot(data: dict = Body(...), x_token: str = Header(default="")):
    if not TOKEN:
        raise HTTPException(503, "SCREENS_TOKEN no está definido en el .env")
    if not hmac.compare_digest(x_token, TOKEN):
        raise HTTPException(401, "Token no válido")
    url = str(data.get("url") or "")
    if urlparse(url).scheme not in ("http", "https"):
        raise HTTPException(400, "Solo URL http(s)")
    w, h = int(data.get("width") or 1366), int(data.get("height") or 900)
    async with sem:
        b = await browser()
        ctx = await b.new_context(viewport={"width": w, "height": h}, user_agent=UA, ignore_https_errors=True,
                                  accept_downloads=False, locale="es-DO", service_workers="block")
        try:
            page = await ctx.new_page()
            page.set_default_timeout(25000)
            try:
                await page.goto(url, wait_until="load", timeout=30000)
            except Exception as exc:  # aun así se intenta capturar lo que haya cargado
                if "Timeout" not in str(exc):
                    raise HTTPException(502, f"No carga: {str(exc)[:200]}")
            await page.wait_for_timeout(int(data.get("settle_ms") or 2500))  # animaciones, sliders, banners
            img = await page.screenshot(type="jpeg", quality=int(data.get("quality") or 60), full_page=False)
            return Response(img, media_type="image/jpeg", headers={"X-Final-Url": page.url[:500]})
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(502, f"Error al capturar: {str(exc)[:200]}")
        finally:
            await ctx.close()
