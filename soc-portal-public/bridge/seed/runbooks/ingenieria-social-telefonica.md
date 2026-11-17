---
title: "Ingeniería social telefónica (vishing)"
description: "Llamadas o mensajes que suplantan a soporte técnico, bancos o directivos para obtener claves, códigos MFA o acceso remoto"
level: Básico
category: Identidad
severity: Medium
mitre: T1566.004, T1656, T1219
owasp: 
---
# Runbook — Ingeniería social telefónica (vishing)

> **Nivel:** Básico · **Severidad típica:** Media · **Categoría:** Identidad  
> **MITRE ATT&CK:** [T1566.004](#/mitre?t=T1566.004) · [T1656](#/mitre?t=T1656) · [T1219](#/mitre?t=T1219)

## Cuándo usarlo
- Un usuario informa de una llamada sospechosa de «soporte» o de un «directivo».
- Varios usuarios reciben solicitudes de aprobar notificaciones MFA.

## Señales e indicadores
- Urgencia y presión, petición de códigos MFA o de instalar un programa de acceso remoto.
- Número desconocido o que imita a la institución.

## ⚙️ Automatizado por Shuffle
1. Buscar instalaciones recientes de software de acceso remoto en el equipo del usuario.
2. Comprobar inicios de sesión y aprobaciones MFA de la cuenta en la última hora.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿El usuario dio su contraseña, un código MFA o instaló algo?
- [ ] Si dio credenciales → runbook **Cuenta comprometida**. Si instaló un programa → aísla el equipo.

### 2. Contención
- [ ] Cambia la contraseña y revoca sesiones si hubo exposición.
- [ ] Bloquea el número o la cuenta de mensajería origen.

### 3. Erradicación
- [ ] Desinstala herramientas de acceso remoto instaladas por el atacante.

### 4. Recuperación
- [ ] Aviso general a la plantilla con el modus operandi (sin culpar al usuario).

### 5. Cierre y lecciones aprendidas
- [ ] Registra el número y la narrativa en MISP para compartir con otras instituciones.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Número, hora, resumen de la conversación, capturas de mensajes.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"authentication_success" AND data.win.eventdata.targetUserName:"<usuario>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.
