---
title: "Password spraying y fatiga de MFA"
description: "Pocas contraseñas probadas contra muchas cuentas, o bombardeo de notificaciones MFA para que el usuario apruebe"
level: Intermedio
category: Identidad
severity: High
mitre: T1110.003, T1621
owasp: A07:2025
---
# Runbook — Password spraying y fatiga de MFA

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Identidad  
> **MITRE ATT&CK:** [T1110.003](#/mitre?t=T1110.003) · [T1621](#/mitre?t=T1621) · **OWASP:** A07:2025

## Cuándo usarlo
- Muchos usuarios distintos con 1–3 fallos desde la misma IP o ASN.
- Un usuario recibe decenas de notificaciones MFA seguidas.

## Señales e indicadores
- Fallos repartidos en el tiempo para evitar bloqueos.
- Aprobación MFA a horas inusuales tras muchas denegaciones.

## ⚙️ Automatizado por Shuffle
1. Agrupar fallos por IP y contar usuarios distintos (≥ 10 en 1 h).
2. Proponer el bloqueo de la IP en el borde y avisar a los usuarios con aprobaciones MFA sospechosas.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿Algún inicio correcto desde la IP atacante? → runbook **Cuenta comprometida** para esas cuentas.
- [ ] ¿Alguien aprobó un MFA que no pidió?

### 2. Contención
- [ ] Bloquea IPs/ASN, activa acceso condicional por país y número coincidente en MFA.
- [ ] Restablece contraseñas de cuentas con acceso correcto.

### 3. Erradicación
- [ ] Revisa cuentas sin MFA y obliga su registro.

### 4. Recuperación
- [ ] Comunica a la plantilla que nunca debe aprobar notificaciones que no inició.

### 5. Cierre y lecciones aprendidas
- [ ] Añade las IPs al motor de IoC con confianza 80.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Logs de autenticación (AD, VPN, M365) del periodo.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"authentication_failed" AND data.srcip:"<ip>"
rule.groups:"authentication_success" AND data.srcip:"<ip>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Hayabusa](#/tools?q=Hayabusa) · [Chainsaw](#/tools?q=Chainsaw) · [DeepBlueCLI](#/tools?q=DeepBlueCLI)
