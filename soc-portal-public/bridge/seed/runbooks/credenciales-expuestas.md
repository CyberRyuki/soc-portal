---
title: "Credenciales expuestas o filtradas"
description: "Usuario y contraseña institucional aparecen en una filtración, pegados en un sitio público o enviados por error"
level: Básico
category: Identidad
severity: High
mitre: T1078, T1589.001
owasp: A07:2025
---
# Runbook — Credenciales expuestas o filtradas

> **Nivel:** Básico · **Severidad típica:** Alta · **Categoría:** Identidad  
> **MITRE ATT&CK:** [T1078](#/mitre?t=T1078) · [T1589.001](#/mitre?t=T1589.001) · **OWASP:** A07:2025

## Cuándo usarlo
- Aviso del CSIRT, de h8mail/Have I Been Pwned o de un proveedor de inteligencia.
- Un usuario pegó su contraseña en un chat, ticket o repositorio.

## Señales e indicadores
- Correos institucionales en listas de credenciales («combolists»).
- Inicios de sesión desde países o IPs no habituales.

## ⚙️ Automatizado por Shuffle
1. Buscar los usuarios afectados en AD y su último inicio de sesión.
2. Comprobar en Wazuh accesos correctos desde IPs del motor de IoC.
3. Forzar el cambio de contraseña (con aprobación) y notificar al usuario.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Confirma que la cuenta existe y está activa; identifica si es privilegiada o de servicio.
- [ ] Comprueba si la contraseña filtrada es la actual (pregunta al usuario, no la escribas en el ticket).
- [ ] Revisa inicios de sesión de los últimos 30 días.

### 2. Contención
- [ ] Fuerza el cambio de contraseña y cierra todas las sesiones.
- [ ] Activa o revisa el MFA de la cuenta.
- [ ] Si hubo acceso no autorizado → runbook **Cuenta comprometida**.

### 3. Erradicación
- [ ] Comprueba que no se reutiliza la misma contraseña en otros sistemas.

### 4. Recuperación
- [ ] Explica al usuario cómo crear una contraseña única y usar el gestor de contraseñas.

### 5. Cierre y lecciones aprendidas
- [ ] Guarda la fuente de la filtración en MISP si aporta valor (sin las contraseñas).
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Origen de la filtración, fecha, cuentas afectadas (sin contraseñas en claro).

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"authentication_success" AND data.win.eventdata.targetUserName:"<usuario>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[h8mail](#/tools?q=h8mail) · [TruffleHog](#/tools?q=TruffleHog) · [Gitleaks](#/tools?q=Gitleaks)
