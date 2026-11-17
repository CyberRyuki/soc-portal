---
title: Coincidencia de IoC en MISP
description: Un indicador de una alerta de Wazuh existe en MISP
level: Intermedio
category: Inteligencia
severity: High
mitre: T1071, T1566
owasp: 
---
# Runbook — Coincidencia de IoC en MISP

> **Disparador:** regla Wazuh **100622** o nodo MISP de Shuffle con resultados · **Severidad:** Alta · **Workflow:** `SOC-Wazuh-Alert-Triage`

## ⚙️ Automatizado por Shuffle
1. Recibe la alerta de Wazuh (nivel ≥ 10) por webhook.
2. Extrae los IoC del `full_log` (IP, dominio, hash, URL).
3. Busca cada IoC en MISP y, si hay coincidencia, consulta su reputación (AbuseIPDB / VirusTotal).
4. Crea el incidente en el portal con severidad **High**, el IoC, el agente y el evento MISP.
5. Avisa a la guardia con el enlace al incidente y a este runbook.

## 👤 Pasos del analista
1. **Verifica el IoC en MISP:** evento, fecha, fuente, `to_ids`, etiquetas TLP y nivel de amenaza.
2. **Revisa el contexto del activo:** qué agente es, si es crítico y si la conexión fue entrante o saliente.
3. **Busca actividad relacionada** en Wazuh: la misma IP o hash en las últimas 72 h y en otros agentes.
4. **Decide:**
    - **Falso positivo** → documéntalo, registra un *sighting* de falso positivo en MISP y cierra el incidente.
    - **Verdadero positivo** → pasa el incidente a *Investigating* y solicita la contención.
5. **Contén (con aprobación):** bloqueo de la IP o dominio en el firewall o con *active response* de Wazuh.
6. **Cierra:** registra un *sighting* en MISP, la causa raíz y las lecciones aprendidas.

## Criterios
- Un indicador con más de 90 días o sin `to_ids` **no justifica un bloqueo** por sí solo.
- No publiques IoC con TLP:RED o AMBER fuera del SOC.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Webhook `wazuh` | Lo llama la integración `shuffle` de Wazuh |
| 2 | Shuffle Tools · Parse IOC | `input_string` = `$exec.all_fields.full_log` |
| 3 | MISP · Simplified attribute search | `data` = `$parse_ioc.#.data` |
| 4 | Condición | `$misp` **contains** `event_id` |
| 5 | Http · POST al portal | Crea el incidente (ver *Integración con el portal*) |
| 6 | Email / Teams | Aviso con los enlaces |
