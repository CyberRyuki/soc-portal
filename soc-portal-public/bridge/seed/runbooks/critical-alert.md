---
title: Alerta crítica de Wazuh
description: Alertas de nivel 13 a 15
level: Básico
category: General
severity: Critical
mitre: 
owasp: 
---
# Runbook — Alerta crítica de Wazuh (nivel 13–15)

> **Disparador:** cualquier alerta con `rule.level` ≥ 13 · **Severidad:** Crítica · **Tiempo de respuesta:** 15 min · **Workflow:** `SOC-Critical-Alert`

## ⚙️ Automatizado por Shuffle
1. Filtra las alertas con nivel ≥ 13.
2. Agrupa las repeticiones (misma regla y mismo agente durante 10 min) para no duplicar casos.
3. Crea el incidente en el portal con severidad **Critical**, este runbook y los datos de la alerta.
4. Avisa a la guardia por Teams o correo, con prioridad alta.

## 👤 Pasos del analista
1. **Confirma la alerta** en el Wazuh Dashboard: regla, agente, `full_log` y MITRE ATT&CK.
2. **Avisa a la guardia en ≤ 15 min** si el aviso automático no llegó.
3. **Preserva evidencias** antes de tocar nada: logs, hashes, capturas, procesos y conexiones activas.
4. **Delimita el alcance:** busca la misma regla, usuario o IoC en otros agentes durante las últimas 24 h.
5. **Contén (con aprobación):** aislamiento del equipo, bloqueo de IP o desactivación de la cuenta, según el caso.
6. **Escala** al responsable de seguridad y, si aplica, al CSIRT nacional.
7. **Cierra:** cronología completa, causa raíz y lecciones aprendidas.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Webhook `wazuh` | El mismo de `SOC-Wazuh-Alert-Triage` o uno propio |
| 2 | Condición | `$exec.all_fields.rule.level` **larger than** `12` |
| 3 | Shuffle Tools · Set cache / Get cache | Clave `regla+agente`, 10 min, para no duplicar casos |
| 4 | Http · POST al portal | `severity: Critical`, `runbook: critical-alert` |
| 5 | Teams / Email | Mensaje urgente con el enlace al incidente |
