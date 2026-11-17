---
title: "Medio extraíble sospechoso (USB)"
description: "Memoria USB desconocida conectada, ejecución automática o copia masiva de datos a un medio extraíble"
level: Básico
category: Malware
severity: Medium
mitre: T1091, T1052.001
owasp: 
---
# Runbook — Medio extraíble sospechoso (USB)

> **Nivel:** Básico · **Severidad típica:** Media · **Categoría:** Malware  
> **MITRE ATT&CK:** [T1091](#/mitre?t=T1091) · [T1052.001](#/mitre?t=T1052.001)

## Cuándo usarlo
- Wazuh/Sysmon registra un dispositivo USB nuevo o la ejecución de un programa desde una unidad extraíble.
- Un empleado encuentra una memoria USB en la oficina.

## Señales e indicadores
- Archivos .lnk, .exe o scripts en la raíz del USB.
- Copia de muchos archivos hacia la unidad (posible fuga).

## ⚙️ Automatizado por Shuffle
1. Identificar el equipo, el usuario y el número de serie del dispositivo.
2. Buscar ejecuciones desde la letra de la unidad.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Si la memoria fue encontrada: **no la conectes** a equipos de la red; analízala en una máquina aislada.
- [ ] Si se ejecutó algo desde el USB → runbook **Malware en un equipo**.
- [ ] Si se copiaron datos hacia el USB → runbook **Fuga de datos**.

### 2. Contención
- [ ] Aísla el equipo si hubo ejecución sospechosa.
- [ ] Bloquea el número de serie o los medios extraíbles por GPO si procede.

### 3. Erradicación
- [ ] Analiza el contenido con antivirus y YARA en una máquina aislada.

### 4. Recuperación
- [ ] Devuelve el equipo a producción tras un escaneo limpio.

### 5. Cierre y lecciones aprendidas
- [ ] Recuerda la política de medios extraíbles.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Número de serie, hora de conexión, lista de archivos, hashes.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
data.win.system.eventID:"6416" OR rule.description:*USB*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[YARA](#/tools?q=YARA) · [Loki](#/tools?q=Loki) · [Sysmon](#/tools?q=Sysmon)
