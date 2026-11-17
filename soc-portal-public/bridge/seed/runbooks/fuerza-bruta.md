---
title: Ataque de fuerza bruta
description: Intentos repetidos de inicio de sesión fallidos (SSH, RDP, Windows, VPN)
level: Básico
category: Identidad
severity: High
mitre: T1110.001, T1110.003
owasp: A07:2025
---
# Runbook — Ataque de fuerza bruta

> **Disparador:** reglas Wazuh de autenticación múltiple fallida (p. ej. **5712, 5763** SSH · **60204** Windows) · **Severidad:** Alta · **Workflow:** `SOC-Brute-Force`
> Confirma los ID de regla en tu Wazuh: pueden variar según la versión.

## ⚙️ Automatizado por Shuffle
1. Recibe la alerta y extrae la **IP de origen**, el **usuario** y el **agente**.
2. Consulta la reputación de la IP en AbuseIPDB y MISP, y si es interna o externa.
3. Busca en Wazuh si después hubo un **inicio de sesión correcto** desde esa IP (indicio de compromiso).
4. Agrupa las alertas repetidas de la misma IP durante 30 min en un solo incidente.
5. Crea el incidente: **High** si hubo un acceso correcto o la IP es maliciosa, **Medium** en otro caso.

## 👤 Pasos del analista
1. **¿Hubo un acceso exitoso?** Si lo hubo, pasa directamente al runbook **Cuenta comprometida**.
2. **¿La IP es interna?** Localiza el equipo de origen; puede estar infectado o mal configurado (por ejemplo, una contraseña antigua guardada).
3. **¿La cuenta existe y es privilegiada?** Prioriza las cuentas de administrador y de servicio.
4. **Contén (con aprobación):** bloquea la IP con *active response* `firewall-drop` o en el firewall perimetral y, si hace falta, bloquea temporalmente la cuenta.
5. **Mejora:** si el servicio está expuesto a Internet, valora MFA, VPN o limitar el acceso por IP.
6. **Cierra** con la decisión y los IoC registrados.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Webhook `wazuh` | Condición: `rule.groups` contiene `authentication_failures` |
| 2 | AbuseIPDB · Check IP | `$exec.all_fields.data.srcip` |
| 3 | Http · Wazuh indexer | Busca un acceso correcto de esa IP en los últimos 30 min |
| 4 | Http · POST al portal | `runbook: fuerza-bruta` |
| 5 | User Input (opcional) | Aprobación para bloquear la IP |
| 6 | Wazuh · Active response | `firewall-drop` sobre el agente afectado |
