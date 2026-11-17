#!/usr/bin/env python3
"""
Crea (si no existen) o cambia la contraseña de los dos usuarios de solo lectura
del portal en Wazuh y actualiza /opt/soc-portal/.env:
  soc-api      -> API de Wazuh (55000), rol readonly
  soc-indexer  -> Indexer (9200), rol soc_bridge_read (lectura de wazuh-alerts-*)
Pide las contraseñas por teclado (no quedan en el historial).
Uso:  python3 scripts/claves_wazuh.py [--wazuh 10.10.10.54]
"""
import argparse, getpass, pathlib, sys
import requests, urllib3

urllib3.disable_warnings()
T = 90
ENV = pathlib.Path(__file__).resolve().parent.parent / ".env"

ap = argparse.ArgumentParser()
ap.add_argument("--wazuh", default=None, help="IP del servidor Wazuh (por defecto WAZUH_HOST de .env)")
ap.add_argument("--api-user", default="soc-api")
ap.add_argument("--idx-user", default="soc-indexer")
a = ap.parse_args()

env = {}
for line in ENV.read_text().splitlines():
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1); env[k.strip()] = v.strip()
host = a.wazuh or env.get("WAZUH_HOST")
if not host or host.startswith("IP_"):
    sys.exit("Indica la IP de Wazuh con --wazuh o en WAZUH_HOST de .env")
API, IDX = f"https://{host}:55000", f"https://{host}:9200"


def ask(prompt):
    p1 = getpass.getpass(prompt)
    if p1 and prompt.startswith("Nueva"):
        if getpass.getpass("   Repite la contraseña: ") != p1:
            sys.exit("Las contraseñas no coinciden")
    return p1


def set_env(key, value):
    lines, done = ENV.read_text().splitlines(), False
    for i, l in enumerate(lines):
        if l.startswith(key + "="):
            lines[i] = f"{key}={value}"; done = True
    if not done:
        lines.append(f"{key}={value}")
    ENV.write_text("\n".join(lines) + "\n")


ok = True
# ------------------------------------------------------------------ API (55000)
print(f"\n== API de Wazuh ({API}) · usuario {a.api_user}")
wui = ask("Contraseña de wazuh-wui (admin de la API): ")
new_api = ask(f"Nueva contraseña para {a.api_user}: ")
try:
    r = requests.post(f"{API}/security/user/authenticate", auth=("wazuh-wui", wui), verify=False, timeout=T)
    r.raise_for_status()
    H = {"Authorization": f"Bearer {r.json()['data']['token']}"}
    users = requests.get(f"{API}/security/users", headers=H, verify=False, timeout=T,
                         params={"limit": 500}).json()["data"]["affected_items"]
    u = next((x for x in users if x["username"] == a.api_user), None)
    if u:
        r = requests.put(f"{API}/security/users/{u['id']}", headers=H, verify=False, timeout=T,
                         json={"password": new_api})
        print("   Contraseña cambiada" if r.ok else f"   ERROR: {r.text}")
    else:
        r = requests.post(f"{API}/security/users", headers=H, verify=False, timeout=T,
                          json={"username": a.api_user, "password": new_api})
        if not r.ok or not r.json()["data"]["affected_items"]:
            raise RuntimeError(r.text)
        u = r.json()["data"]["affected_items"][0]
        roles = requests.get(f"{API}/security/roles", headers=H, verify=False, timeout=T,
                             params={"limit": 500}).json()["data"]["affected_items"]
        ro = next(x for x in roles if x["name"] == "readonly")
        requests.post(f"{API}/security/users/{u['id']}/roles", headers=H, verify=False, timeout=T,
                      params={"role_ids": ro["id"]})
        print(f"   Usuario creado (id {u['id']}) con rol readonly")
    t = requests.post(f"{API}/security/user/authenticate", auth=(a.api_user, new_api), verify=False, timeout=T)
    print("   Prueba de acceso: OK" if t.ok else f"   Prueba de acceso FALLÓ: {t.status_code}")
    if t.ok:
        set_env("WAZUH_API_USER", a.api_user); set_env("WAZUH_API_PASSWORD", new_api)
    ok &= t.ok
except Exception as e:
    print(f"   ERROR con la API: {e}"); ok = False

# ------------------------------------------------------------------ Indexer (9200)
print(f"\n== Indexer de Wazuh ({IDX}) · usuario {a.idx_user}")
adm = ask("Contraseña de 'admin' del indexer (la de la web de Wazuh): ")
new_idx = ask(f"Nueva contraseña para {a.idx_user}: ")
S = f"{IDX}/_plugins/_security/api"
A = ("admin", adm)
try:
    requests.get(IDX, auth=A, verify=False, timeout=T).raise_for_status()
    # Rol de solo lectura (se crea si falta)
    if requests.get(f"{S}/roles/soc_bridge_read", auth=A, verify=False, timeout=T).status_code == 404:
        requests.put(f"{S}/roles/soc_bridge_read", auth=A, verify=False, timeout=T, json={
            "cluster_permissions": ["cluster_composite_ops_ro"],
            "index_permissions": [{"index_patterns": ["wazuh-alerts-*", "wazuh-monitoring-*"], "allowed_actions": ["read", "search"]}],
        }).raise_for_status()
        print("   Rol soc_bridge_read creado")
    # Usuario: conserva sus roles/atributos y cambia la contraseña
    g = requests.get(f"{S}/internalusers/{a.idx_user}", auth=A, verify=False, timeout=T)
    cur = g.json().get(a.idx_user, {}) if g.ok else {}
    body = {"password": new_idx, "backend_roles": cur.get("backend_roles", []),
            "attributes": cur.get("attributes", {})}
    r = requests.put(f"{S}/internalusers/{a.idx_user}", auth=A, verify=False, timeout=T, json=body)
    r.raise_for_status()
    print("   Contraseña cambiada" if g.ok else "   Usuario creado")
    # Mapeo del rol al usuario (sin quitar a otros)
    m = requests.get(f"{S}/rolesmapping/soc_bridge_read", auth=A, verify=False, timeout=T)
    mp = m.json().get("soc_bridge_read", {}) if m.ok else {}
    users = sorted(set(mp.get("users", [])) | {a.idx_user})
    requests.put(f"{S}/rolesmapping/soc_bridge_read", auth=A, verify=False, timeout=T, json={
        "users": users, "backend_roles": mp.get("backend_roles", []), "hosts": mp.get("hosts", []),
    }).raise_for_status()
    print(f"   Rol soc_bridge_read asignado a: {', '.join(users)}")
    t = requests.get(f"{IDX}/wazuh-alerts-*/_count", auth=(a.idx_user, new_idx), verify=False, timeout=T)
    print(f"   Prueba de acceso: OK ({t.json().get('count')} alertas)" if t.ok
          else f"   Prueba de acceso FALLÓ: {t.status_code} {t.text[:120]}")
    if t.ok:
        set_env("WAZUH_INDEXER_USER", a.idx_user); set_env("WAZUH_INDEXER_PASSWORD", new_idx)
    ok &= t.ok
except requests.exceptions.ConnectionError:
    print(f"   ERROR: no hay conexión con {IDX}. Revisa el puerto 9200 / network.host del indexer.")
    ok = False
except Exception as e:
    print(f"   ERROR con el indexer: {e}"); ok = False

print("\n.env actualizado con los usuarios que pasaron la prueba." if ok
      else "\nRevisa los errores de arriba; solo se guardó en .env lo que funcionó.")
