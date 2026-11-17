#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Integración Wazuh -> MISP.
Wazuh ejecuta: custom-misp.py <archivo_alerta> <api_key> <hook_url>
Extrae IoC de la alerta (IP, hash, dominio), busca en MISP y, si hay
coincidencia, inyecta un evento "misp" en Wazuh que dispara las reglas 100620+.
"""
import json
import sys
import ipaddress
from socket import socket, AF_UNIX, SOCK_DGRAM

import requests
import urllib3

urllib3.disable_warnings()

SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
VERIFY_TLS = False  # Cambia a la ruta del CA de MISP en producción
TIMEOUT = 10


def send_event(msg: dict, agent: dict | None) -> None:
    if not agent or agent.get("id") == "000":
        location = "misp"
    else:
        location = "[{0}] ({1}) {2}->misp".format(
            agent.get("id"), agent.get("name"), agent.get("ip", "any"))
    string = "1:{0}:{1}".format(location, json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(string.encode())
    sock.close()


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved
                    or ip.is_multicast or ip.is_link_local)
    except ValueError:
        return False


def extract_iocs(alert: dict) -> list[tuple[str, str]]:
    """Devuelve lista de (tipo, valor)."""
    iocs = []
    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})
    win = data.get("win", {}).get("eventdata", {})

    for key in ("srcip", "dstip"):
        v = data.get(key)
        if v and is_public_ip(v):
            iocs.append(("ip", v))

    for key in ("sha256_after", "md5_after", "sha1_after"):
        v = syscheck.get(key)
        if v:
            iocs.append(("hash", v))

    # Sysmon
    if win.get("hashes"):
        for part in win["hashes"].split(","):
            if "=" in part:
                iocs.append(("hash", part.split("=", 1)[1]))
    if win.get("destinationIp") and is_public_ip(win["destinationIp"]):
        iocs.append(("ip", win["destinationIp"]))
    if win.get("queryName"):
        iocs.append(("domain", win["queryName"]))

    # Únicos, máximo 5 por alerta
    seen, out = set(), []
    for t, v in iocs:
        if v not in seen:
            seen.add(v)
            out.append((t, v))
    return out[:5]


def search_misp(base_url: str, api_key: str, value: str) -> dict | None:
    url = base_url.rstrip("/") + "/attributes/restSearch"
    headers = {"Authorization": api_key, "Accept": "application/json",
               "Content-Type": "application/json"}
    body = {"returnFormat": "json", "value": value, "limit": 1,
            "to_ids": 1, "includeEventTags": 1}
    r = requests.post(url, headers=headers, json=body,
                      verify=VERIFY_TLS, timeout=TIMEOUT)
    r.raise_for_status()
    attrs = r.json().get("response", {}).get("Attribute", [])
    return attrs[0] if attrs else None


def main() -> None:
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as f:
        alert = json.load(f)

    for ioc_type, value in extract_iocs(alert):
        try:
            attr = search_misp(hook_url, api_key, value)
        except Exception as exc:  # error de red/API: se reporta y se sigue
            send_event({"integration": "misp", "misp": {
                "error": str(exc)[:200], "value": value}}, alert.get("agent"))
            continue
        if not attr:
            continue
        event = attr.get("Event", {})
        send_event({
            "integration": "misp",
            "misp": {
                "found": 1,
                "ioc_type": ioc_type,
                "value": value,
                "category": attr.get("category"),
                "type": attr.get("type"),
                "event_id": attr.get("event_id"),
                "event_info": event.get("info"),
                "threat_level_id": event.get("threat_level_id"),
                "source_rule_id": alert.get("rule", {}).get("id"),
                "source_alert_id": alert.get("id"),
                "source_description": alert.get("rule", {}).get("description"),
            },
        }, alert.get("agent"))


if __name__ == "__main__":
    main()
