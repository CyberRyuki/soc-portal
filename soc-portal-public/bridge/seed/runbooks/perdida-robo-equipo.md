---
title: "Pérdida o robo de equipo o móvil"
description: "Portátil, móvil, tableta o memoria institucional perdida o robada"
level: Básico
category: Activos
severity: Medium
mitre: T1078
owasp: 
---
# Runbook — Pérdida o robo de equipo o móvil

> **Nivel:** Básico · **Severidad típica:** Media · **Categoría:** Activos  
> **MITRE ATT&CK:** [T1078](#/mitre?t=T1078)

## Cuándo usarlo
- Un empleado notifica la pérdida o el robo de un dispositivo.
- Inventario detecta un equipo que no se conecta desde hace días (agente Wazuh desconectado).

## Señales e indicadores
- Dispositivo con sesiones abiertas de correo, VPN o aplicaciones internas.
- Datos sensibles almacenados localmente.

## ⚙️ Automatizado por Shuffle
1. Crear incidente con el nombre del equipo y su último usuario.
2. Consultar el último contacto del agente Wazuh y su IP.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Identifica el equipo (inventario, agente Wazuh), su dueño y qué datos contenía.
- [ ] ¿Tenía el disco cifrado (BitLocker/FileVault)? ¿Bloqueo con PIN?
- [ ] Si se robó: pide al usuario la denuncia policial.

### 2. Contención
- [ ] Cambia la contraseña del usuario y revoca sesiones (correo, VPN, M365, portal).
- [ ] Bloquea o borra en remoto el móvil desde el MDM.
- [ ] Desactiva el certificado/equipo en VPN y el objeto de equipo en AD.
- [ ] Revoca claves de recuperación BitLocker expuestas.

### 3. Erradicación
- [ ] Revisa accesos posteriores a la pérdida desde cuentas del usuario (inicios desde IPs nuevas).

### 4. Recuperación
- [ ] Entrega un equipo nuevo con la imagen estándar y restaura datos desde la copia.

### 5. Cierre y lecciones aprendidas
- [ ] Si había datos personales sin cifrar, valora la notificación de brecha según la normativa aplicable.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Denuncia, hora de pérdida, último acceso del equipo, lista de datos afectados.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
agent.name:"<equipo>"
data.win.eventdata.targetUserName:"<usuario>" AND rule.groups:"authentication_success"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.
