#!/usr/bin/env python3
"""
Crea en la API de Wazuh (puerto 55000) un usuario de SOLO LECTURA para soc-bridge.
Se ejecuta una vez, con un usuario administrador de la API (p. ej. wazuh-wui).

  python3 crear_usuario_api_lectura.py --api https://10.0.0.20:55000 \
          --admin wazuh-wui --usuario soc-bridge
(pide las contraseñas por teclado; no quedan en el historial)
La contraseña debe tener 8-64 caracteres, mayúscula, minúscula, número y símbolo.
"""
import argparse
import getpass
import sys

import requests
import urllib3

urllib3.disable_warnings()

ap = argparse.ArgumentParser()
ap.add_argument("--api", required=True)
ap.add_argument("--admin", default="wazuh-wui")
ap.add_argument("--usuario", default="soc-bridge")
ap.add_argument("--verify", action="store_true", help="verificar TLS")
a = ap.parse_args()
api = a.api.rstrip("/")

admin_pwd = getpass.getpass(f"Contraseña de {a.admin}: ")
new_pwd = getpass.getpass(f"Contraseña nueva para {a.usuario}: ")

r = requests.post(f"{api}/security/user/authenticate", auth=(a.admin, admin_pwd),
                  verify=a.verify, timeout=90)
r.raise_for_status()
H = {"Authorization": f"Bearer {r.json()['data']['token']}"}

roles = requests.get(f"{api}/security/roles", headers=H, verify=a.verify, timeout=90,
                     params={"limit": 500}).json()["data"]["affected_items"]
role = next((x for x in roles if x["name"] == "readonly"), None)
if not role:
    sys.exit("No existe el rol 'readonly' en esta instalación")

users = requests.get(f"{api}/security/users", headers=H, verify=a.verify, timeout=90,
                     params={"limit": 500}).json()["data"]["affected_items"]
user = next((u for u in users if u["username"] == a.usuario), None)
if user:
    print(f"El usuario {a.usuario} ya existe (id {user['id']}); se le asigna el rol readonly")
else:
    r = requests.post(f"{api}/security/users", headers=H, verify=a.verify, timeout=90,
                      json={"username": a.usuario, "password": new_pwd})
    data = r.json()
    if r.status_code != 200 or not data["data"]["affected_items"]:
        sys.exit(f"No se pudo crear: {data}")
    user = data["data"]["affected_items"][0]
    print(f"Usuario {a.usuario} creado (id {user['id']})")

r = requests.post(f"{api}/security/users/{user['id']}/roles", headers=H, verify=a.verify,
                  timeout=90, params={"role_ids": role["id"]})
print("Rol readonly asignado" if r.status_code == 200 else f"Error asignando rol: {r.text}")
print(f"\nPon en .env del portal: WAZUH_API_USER={a.usuario}  WAZUH_API_PASSWORD=<la que escribiste>")
