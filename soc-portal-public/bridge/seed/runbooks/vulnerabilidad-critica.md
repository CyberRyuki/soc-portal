---
title: Vulnerabilidad crítica
description: CVE crítica detectada por Wazuh en un activo
level: Intermedio
category: Vulnerabilidades
severity: High
mitre: T1190
owasp: A03:2025
---
# Runbook — Vulnerabilidad crítica

> **Disparador:** detección de vulnerabilidades de Wazuh con severidad **Critical** (índice `wazuh-states-vulnerabilities-*`) · **Severidad:** Alta · **Workflow:** `SOC-Critical-Vulnerabilities`

## ⚙️ Automatizado por Shuffle
1. Cada día consulta las vulnerabilidades críticas nuevas por agente.
2. Destaca las que aparecen en el catálogo **CISA KEV** (explotadas activamente).
3. Agrupa por servidor y responsable y envía el informe.
4. Crea un incidente si la CVE está en KEV y el servidor está expuesto a Internet.

## 👤 Pasos del analista
1. **Confirma** el paquete y la versión afectada en el equipo.
2. **Prioriza:** explotación activa (KEV) > expuesto a Internet > servidor crítico > resto.
3. **Coordina el parche** con el responsable del servidor y acuerda una fecha.
4. **Si no se puede parchear,** aplica una mitigación: deshabilitar el servicio, restringir el acceso o una regla en el firewall o WAF.
5. **Comprueba** tras el parche que Wazuh ya no la reporta.
6. **Cierra** con la fecha de corrección.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Schedule | Diario |
| 2 | Http · Wazuh indexer | `wazuh-states-vulnerabilities-*`, `vulnerability.severity: Critical` |
| 3 | Http · CISA KEV | Catálogo JSON de vulnerabilidades explotadas |
| 4 | Email / Teams | Informe por responsable |
| 5 | Http · POST al portal | Solo KEV en servidores expuestos · `runbook: vulnerabilidad-critica` |
