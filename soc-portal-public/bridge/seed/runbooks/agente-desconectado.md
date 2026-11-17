---
title: Agente de Wazuh desconectado
description: Equipos que han dejado de enviar eventos
level: Básico
category: Monitoreo
severity: Medium
mitre: T1562.001
owasp: A09:2025
---
# Runbook — Agente de Wazuh desconectado

> **Disparador:** informe diario programado o regla **504** (agente desconectado) en un servidor crítico · **Severidad:** Media (Alta si el servidor es crítico) · **Workflow:** `SOC-Disconnected-Agents`

## ⚙️ Automatizado por Shuffle
1. Cada día a las 08:00 consulta el índice `wazuh-monitoring-*` y obtiene los agentes `disconnected` y `never_connected`.
2. Calcula cuántos días lleva cada uno desconectado.
3. Envía el informe a la guardia y, si hay un **servidor crítico** desconectado, crea un incidente.

## 👤 Pasos del analista
1. **Clasifica** los agentes desconectados:
    - **Equipo apagado o dado de baja** → confirma con el responsable y elimina el agente de Wazuh.
    - **Servicio detenido** → reinicia `wazuh-agent` en el equipo.
    - **Problema de red** → comprueba la conectividad con el manager (puertos 1514 y 1515).
2. **Un servidor crítico sin monitorización es un riesgo:** desconectar el agente es una técnica conocida de los atacantes. Revisa los últimos eventos que envió antes de desconectarse.
3. **Agentes "never connected":** revisa la instalación y el registro (claves, nombre, grupo).
4. **Cierra** cuando el agente vuelva a estar *active*.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Schedule | Diario a las 08:00 |
| 2 | Http · Wazuh indexer | `wazuh-monitoring-*`, la última foto, `status != active` |
| 3 | Shuffle Tools · Filter list | Separa los servidores críticos |
| 4 | Email / Teams | Informe diario |
| 5 | Http · POST al portal | Solo para servidores críticos · `runbook: agente-desconectado` |
