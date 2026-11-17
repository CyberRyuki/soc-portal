#!/usr/bin/env python3
"""
Carga o actualiza en el portal todos los runbooks de bridge/seed/runbooks/*.md.
Los que ya existen (mismo identificador) se actualizan; los nuevos se crean.
Uso:  python3 scripts/cargar_runbooks.py            (usa BRIDGE_TOKEN del .env)
      python3 scripts/cargar_runbooks.py --url http://127.0.0.1:8088
"""
import argparse, pathlib, re, sys
import requests

ROOT = pathlib.Path(__file__).resolve().parent.parent
env = {}
for line in (ROOT / ".env").read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1); env[k.strip()] = v.strip()
token = env.get("BRIDGE_TOKEN", "")
if not token or token.startswith("CAMBIAR"):
    sys.exit("Define BRIDGE_TOKEN en el .env (openssl rand -hex 24) y reinicia el portal.")

ap = argparse.ArgumentParser()
ap.add_argument("--url", default="http://127.0.0.1:8088")
a = ap.parse_args()

sys.path.insert(0, str(ROOT / "bridge"))
from store import Store  # mismo lector de cabeceras que usa el portal

for f in sorted((ROOT / "bridge/seed/runbooks").glob("*.md")):
    d = Store.parse_runbook(f.read_text(encoding="utf-8"), f.stem)
    r = requests.put(f"{a.url}/portal/api/runbooks/{f.stem}", headers={"X-API-Key": token}, timeout=30, json=d)
    print(f"  {f.stem:<26} {'OK' if r.ok else 'ERROR ' + str(r.status_code) + ' ' + r.text[:80]}")
    if r.status_code == 401:
        sys.exit("El BRIDGE_TOKEN no coincide con el del portal en marcha.")
print("Listo: abre el portal → Runbooks.")
