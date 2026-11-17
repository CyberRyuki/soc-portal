---
title: "Compromiso de correo institucional (BEC)"
description: "Cuenta de correo usada por un atacante para fraude: reglas de reenvío, suplantación interna o cambios de cuentas bancarias"
level: Intermedio
category: Correo
severity: High
mitre: T1114.003, T1534, T1078
owasp: A07:2025
---
# Runbook — Compromiso de correo institucional (BEC)

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Correo  
> **MITRE ATT&CK:** [T1114.003](#/mitre?t=T1114.003) · [T1534](#/mitre?t=T1534) · [T1078](#/mitre?t=T1078) · **OWASP:** A07:2025

## Cuándo usarlo
- Regla de reenvío externo o de borrado automático creada en un buzón.
- Proveedores reportan solicitudes de cambio de cuenta bancaria «desde» la institución.

## Señales e indicadores
- Inicio de sesión desde país nuevo seguido de creación de reglas.
- Correos enviados que el usuario no reconoce, respuestas desviadas.

## ⚙️ Automatizado por Shuffle
1. Listar reglas del buzón y reenvíos (Office 365 / Exchange).
2. Buscar inicios de sesión de la cuenta desde IPs del motor de IoC.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Confirma con el usuario por otro canal (teléfono).
- [ ] Identifica correos enviados por el atacante y destinatarios externos afectados.

### 2. Contención
- [ ] Cambia la contraseña, revoca sesiones y tokens, exige MFA.
- [ ] Elimina reglas de reenvío y delegaciones añadidas.
- [ ] Avisa a los destinatarios del fraude y a finanzas para detener pagos.

### 3. Erradicación
- [ ] Revisa aplicaciones OAuth autorizadas por la cuenta (runbook **Compromiso de nube**).

### 4. Recuperación
- [ ] Vigila la cuenta 30 días; bloquea reenvío externo por política.

### 5. Cierre y lecciones aprendidas
- [ ] Si hubo pérdida económica: denuncia y contacto con el banco en menos de 24 h.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Registro de auditoría del buzón, cabeceras de correos fraudulentos, reglas creadas.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
data.office365.Operation:"New-InboxRule" OR data.office365.Operation:"Set-Mailbox"
data.office365.UserId:"<usuario>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Hayabusa](#/tools?q=Hayabusa) · [jq](#/tools?q=jq)
