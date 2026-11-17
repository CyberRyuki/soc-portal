"""
Playbook SOC: triage de alertas de Wazuh con inteligencia de MISP.

Disparo: alertas con source="wazuh" (las envía custom-opensoar.py) y
severidad high/critical (nivel Wazuh >= 10).

1. Reúne los indicadores normalizados (IP públicas, dominios, hashes, URLs).
2. Los busca en MISP (solo atributos to_ids).
3. Comenta el resultado en la alerta.
4. Si hay coincidencia: pasa la alerta a "in_progress" y determinación "suspicious".
   No ejecuta contención: eso requiere decisión de un analista.
"""
import ipaddress
import logging
import os

import httpx

from opensoar import action, add_current_alert_comment, playbook, update_current_alert

logger = logging.getLogger(__name__)

MISP_URL = os.getenv("MISP_URL", "").rstrip("/")
MISP_KEY = os.getenv("MISP_API_KEY", "")
MISP_LINK = os.getenv("MISP_LINK_URL", MISP_URL).rstrip("/")
MISP_VERIFY = os.getenv("MISP_VERIFY_TLS", "false").lower() in ("1", "true", "yes")
MAX_IOCS = 20
THREAT = {"1": "Alto", "2": "Medio", "3": "Bajo", "4": "Indefinido"}


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved
                or ip.is_multicast or ip.is_link_local)


def collect_indicators(data: dict) -> list[str]:
    iocs = data.get("iocs") or {}
    values = []
    for ip in [data.get("source_ip"), data.get("dest_ip"), *iocs.get("ips", [])]:
        if ip and _public_ip(ip):
            values.append(ip)
    values += iocs.get("hashes", []) + iocs.get("domains", []) + iocs.get("urls", [])
    seen, out = set(), []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out[:MAX_IOCS]


@action(name="misp_lookup", timeout=60, retries=2, retry_backoff=2.0)
async def misp_lookup(values: list[str]) -> dict:
    if not MISP_URL or not MISP_KEY:
        return {"checked": 0, "hits": [], "error": "MISP_URL / MISP_API_KEY no configurados"}
    if not values:
        return {"checked": 0, "hits": []}

    headers = {"Authorization": MISP_KEY, "Accept": "application/json",
               "Content-Type": "application/json"}
    hits = []
    async with httpx.AsyncClient(verify=MISP_VERIFY, timeout=20) as client:
        for value in values:
            r = await client.post(f"{MISP_URL}/attributes/restSearch", headers=headers, json={
                "returnFormat": "json", "value": value, "to_ids": 1,
                "limit": 3, "includeEventTags": 1,
            })
            r.raise_for_status()
            for attr in r.json().get("response", {}).get("Attribute", []):
                event = attr.get("Event", {})
                hits.append({
                    "value": value,
                    "type": attr.get("type"),
                    "category": attr.get("category"),
                    "event_id": attr.get("event_id"),
                    "event_info": event.get("info"),
                    "threat_level": THREAT.get(str(event.get("threat_level_id")), "-"),
                    "tags": [t.get("name") for t in attr.get("Tag", [])][:5],
                })
    return {"checked": len(values), "hits": hits}


@playbook(
    trigger="wazuh",
    conditions={"severity": ["high", "critical"]},
    description="Wazuh (nivel >= 10): buscar IoC en MISP y marcar como sospechosa si coincide",
    order=10,
)
async def wazuh_misp_triage(alert_data):
    data = alert_data.normalized if hasattr(alert_data, "normalized") else alert_data
    values = collect_indicators(data)
    result = await misp_lookup(values)

    if result.get("error"):
        await add_current_alert_comment(f"MISP: no consultado ({result['error']}).")
        return result

    hits = result["hits"]
    if not hits:
        await add_current_alert_comment(
            f"MISP: sin coincidencias para {result['checked']} indicador(es). "
            "La ausencia de coincidencias no garantiza que sean seguros.",
            metadata={"misp_checked": values},
        )
        return result

    lines = [f"MISP: {len(hits)} coincidencia(s):"]
    for h in hits:
        lines.append(f"- {h['value']} [{h['type']}] → evento #{h['event_id']} "
                     f"«{h['event_info']}» (amenaza {h['threat_level']})")
    if MISP_LINK:
        lines.append(f"Ver: {MISP_LINK}/events/view/{hits[0]['event_id']}")
    lines.append("Siguiente paso: runbook SOC/runbooks/ioc-misp en la Wiki.")
    await add_current_alert_comment("\n".join(lines), metadata={"misp_hits": hits})
    await update_current_alert(
        status="in_progress",
        determination="suspicious",
        reason="Indicador presente en MISP",
    )
    logger.info("wazuh_misp_triage: %d coincidencias MISP", len(hits))
    return result
