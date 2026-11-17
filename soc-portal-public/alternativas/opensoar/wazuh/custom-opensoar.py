#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Integración Wazuh -> OpenSOAR.
Wazuh ejecuta: custom-opensoar.py <archivo_alerta> <api_key> <hook_url>

La integración nativa "shuffle" de Wazuh no permite añadir cabeceras, y el
webhook de OpenSOAR exige X-API-Key. Este script:
  - traduce la alerta al formato que normaliza OpenSOAR (title, severity,
    source_ip, hostname, tags...) con source="wazuh" para disparar playbooks
    con trigger="wazuh";
  - firma el cuerpo con HMAC-SHA256 (X-Webhook-Signature) usando la API key;
  - registra errores en /var/ossec/logs/integrations.log.
"""
import hashlib
import hmac
import json
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
VERIFY_TLS = False  # True o ruta del CA si OpenSOAR va detrás de HTTPS interno
TIMEOUT = 10
LOG = "/var/ossec/logs/integrations.log"


def log(msg: str) -> None:
    with open(LOG, "a") as f:
        f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} custom-opensoar: {msg}\n")


def severity(level: int) -> str:
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def build_payload(alert: dict) -> dict:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    syscheck = alert.get("syscheck", {})
    win = data.get("win", {}).get("eventdata", {})
    level = int(rule.get("level", 0))

    # Las claves deben contener "hash" para que OpenSOAR las extraiga como IoC
    hashes = {f"{k.split('_')[0]}_hash": syscheck[k]
              for k in ("md5_after", "sha1_after", "sha256_after") if syscheck.get(k)}
    if win.get("hashes"):
        for part in win["hashes"].split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                hashes[f"{k.lower()}_hash"] = v

    return {
        "source": "wazuh",
        "source_id": alert.get("id"),
        "title": f"[Wazuh {rule.get('id')}] {rule.get('description', 'Alerta Wazuh')}",
        "description": alert.get("full_log") or rule.get("description"),
        "severity": severity(level),
        "source_ip": data.get("srcip") or win.get("sourceIp"),
        "dest_ip": data.get("dstip") or win.get("destinationIp"),
        "hostname": agent.get("name"),
        "tags": list(rule.get("groups", [])) + [f"wazuh-level-{level}"],
        "domain": win.get("queryName"),
        "file_hashes": hashes,
        "url": data.get("url") if str(data.get("url", "")).startswith(("http://", "https://")) else None,
        "wazuh": {
            "rule_id": rule.get("id"),
            "level": level,
            "groups": rule.get("groups"),
            "mitre": rule.get("mitre"),
            "agent": agent,
            "manager": alert.get("manager", {}).get("name"),
            "location": alert.get("location"),
            "decoder": alert.get("decoder", {}).get("name"),
            "timestamp": alert.get("timestamp"),
            "file": syscheck.get("path"),
            "user": data.get("dstuser") or data.get("srcuser") or win.get("user"),
        },
    }


def main() -> None:
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as f:
        alert = json.load(f)

    body = json.dumps(build_payload(alert), separators=(",", ":")).encode()
    sig = "sha256=" + hmac.new(api_key.encode(), body, hashlib.sha256).hexdigest()
    headers = {"Content-Type": "application/json", "X-API-Key": api_key,
               "X-Webhook-Signature": sig}
    try:
        r = requests.post(hook_url, data=body, headers=headers,
                          verify=VERIFY_TLS, timeout=TIMEOUT)
        if r.status_code >= 300:
            log(f"HTTP {r.status_code} alerta {alert.get('id')}: {r.text[:200]}")
    except Exception as exc:
        log(f"error enviando alerta {alert.get('id')}: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
