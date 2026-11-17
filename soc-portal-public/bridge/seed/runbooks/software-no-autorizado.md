---
title: "Software no autorizado o uso indebido"
description: "Instalación de programas no aprobados (escritorio remoto, P2P, juegos, herramientas de hacking) o uso indebido de recursos"
level: Básico
category: Activos
severity: Low
mitre: T1072, T1219
owasp: 
---
# Runbook — Software no autorizado o uso indebido

> **Nivel:** Básico · **Severidad típica:** Baja · **Categoría:** Activos  
> **MITRE ATT&CK:** [T1072](#/mitre?t=T1072) · [T1219](#/mitre?t=T1219)

## Cuándo usarlo
- Wazuh detecta instalación de software nuevo (inventario o regla de paquetes).
- Herramientas de acceso remoto (AnyDesk, TeamViewer, ngrok) en equipos sin autorización.

## Señales e indicadores
- Procesos o servicios nuevos sin firmar.
- Tráfico a servicios de acceso remoto o P2P.

## ⚙️ Automatizado por Shuffle
1. Listar el software nuevo del agente y compararlo con la lista aprobada.
2. Notificar al responsable del área.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿Quién lo instaló y para qué? ¿Tiene justificación de negocio?
- [ ] Si es una herramienta de acceso remoto no autorizada, comprueba si hubo conexiones entrantes (posible fraude de soporte técnico).

### 2. Contención
- [ ] Desinstala el software y bloquéalo por política (AppLocker/WDAC o GPO).
- [ ] Si hubo sesiones remotas de terceros → runbook **Ingeniería social telefónica**.

### 3. Erradicación
- [ ] Revisa privilegios de administrador local del usuario (LAPS, quitar admin).

### 4. Recuperación
- [ ] Ofrece la alternativa aprobada.

### 5. Cierre y lecciones aprendidas
- [ ] Recuerda la política de uso aceptable al usuario y a su responsable.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Inventario de software del agente, hora de instalación, usuario.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"syscollector" OR rule.description:*installed*
data.win.eventdata.image:*anydesk* OR data.win.eventdata.image:*teamviewer*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Autoruns](#/tools?q=Autoruns) · [Process Explorer](#/tools?q=Process%20Explorer) · [osquery](#/tools?q=osquery)
