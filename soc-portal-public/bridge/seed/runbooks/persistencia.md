---
title: "Persistencia en un equipo"
description: "Mecanismos para que el malware o el atacante sobrevivan a reinicios: tareas, servicios, claves Run, WMI, cuentas nuevas"
level: Intermedio
category: Endpoint
severity: High
mitre: T1053.005, T1543.003, T1547.001, T1546.003, T1136
owasp: 
---
# Runbook — Persistencia en un equipo

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Endpoint  
> **MITRE ATT&CK:** [T1053.005](#/mitre?t=T1053.005) · [T1543.003](#/mitre?t=T1543.003) · [T1547.001](#/mitre?t=T1547.001) · [T1546.003](#/mitre?t=T1546.003) · [T1136](#/mitre?t=T1136)

## Cuándo usarlo
- Tarea programada o servicio nuevo con binario en rutas de usuario o temporales.
- Modificación de claves Run/RunOnce o suscripciones WMI (Sysmon 12/13, 19-21).

## Señales e indicadores
- Nombres que imitan a Windows (`svchost` fuera de System32).
- Comandos codificados en Base64 en la tarea.

## ⚙️ Automatizado por Shuffle
1. Extraer la ruta del binario, calcular su hash y consultarlo en MISP y el motor de IoC.
2. Ejecutar Autoruns remoto (Velociraptor) en el equipo.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿Quién creó el mecanismo y cuándo? ¿Coincide con una instalación legítima?
- [ ] Analiza el binario o script referenciado.

### 2. Contención
- [ ] Desactiva la tarea/servicio y aísla el equipo si es malicioso.

### 3. Erradicación
- [ ] Elimina todos los mecanismos encontrados y los binarios asociados.
- [ ] Busca el mismo hash o nombre de tarea en todo el parque.

### 4. Recuperación
- [ ] Reimagina el equipo si no hay certeza de limpieza.

### 5. Cierre y lecciones aprendidas
- [ ] Crea una regla de detección específica para el mecanismo observado.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Exportación de Autoruns, XML de la tarea, binario y hash.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
data.win.system.eventID:("4698" OR "7045")
data.win.system.eventID:("12" OR "13") AND data.win.eventdata.targetObject:*CurrentVersion\\Run*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Autoruns](#/tools?q=Autoruns) · [Velociraptor](#/tools?q=Velociraptor) · [Sysmon](#/tools?q=Sysmon) · [KAPE](#/tools?q=KAPE)
