---
title: Cuenta comprometida
description: Indicios de que un atacante usa credenciales válidas
level: Intermedio
category: Identidad
severity: Critical
mitre: T1078
owasp: A07:2025
---
# Runbook — Cuenta comprometida

> **Disparador:** acceso correcto tras varios fallos, inicio de sesión desde un país o IP inusual, MFA rechazado de forma repetida o aviso del usuario · **Severidad:** Crítica · **Workflow:** `SOC-Compromised-Account`

## ⚙️ Automatizado por Shuffle
1. Reúne los inicios de sesión de la cuenta de las últimas 24 h: IP, país, equipo y resultado.
2. Consulta la reputación de las IP de origen.
3. Crea el incidente **Critical** con la línea de tiempo de accesos.
4. Pide aprobación para **deshabilitar la cuenta** y cerrar sus sesiones.

## 👤 Pasos del analista
1. **Contacta al usuario** por otro canal (teléfono) y confirma si fue él.
2. **Contén (con aprobación):** deshabilita la cuenta o fuerza el cambio de contraseña, revoca sesiones y tokens, y reinicia el MFA.
3. **Revisa la actividad posterior al acceso:** correos enviados, reglas de reenvío, archivos descargados, accesos a otros sistemas y creación de cuentas.
4. **Busca movimiento lateral:** la misma IP o el mismo usuario en otros servidores.
5. **Restablece** el acceso con una contraseña nueva y MFA verificado.
6. **Cierra:** indica el origen probable (phishing, reutilización de contraseña, fuga) y las lecciones aprendidas.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Webhook `wazuh` | Reglas de acceso tras fallos (p. ej. 40112) |
| 2 | Http · Wazuh indexer | Inicios de sesión del usuario en las últimas 24 h |
| 3 | Http · POST al portal | `severity: Critical`, `runbook: cuenta-comprometida` |
| 4 | User Input | Aprobación del responsable de seguridad |
| 5 | Active Directory / Entra ID | Deshabilitar la cuenta y revocar sesiones |
