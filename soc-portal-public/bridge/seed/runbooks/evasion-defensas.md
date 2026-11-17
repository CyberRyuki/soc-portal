---
title: "Desactivación de defensas o borrado de registros"
description: "Detención del antivirus, del agente Wazuh o Sysmon, borrado de registros de eventos o desactivación de auditoría (Defense Impairment)"
level: Avanzado
category: Endpoint
severity: Critical
mitre: T1562.001, T1070.001, T1562.002, T1562.006
owasp: A09:2025
---
# Runbook — Desactivación de defensas o borrado de registros

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Endpoint  
> **MITRE ATT&CK:** [T1562.001](#/mitre?t=T1562.001) · [T1070.001](#/mitre?t=T1070.001) · [T1562.002](#/mitre?t=T1562.002) · [T1562.006](#/mitre?t=T1562.006) · **OWASP:** A09:2025

## Cuándo usarlo
- Evento 1102 (registro de seguridad borrado) o 104 (registro del sistema borrado).
- Agente Wazuh o antivirus detenido/desinstalado fuera de mantenimiento; cambios de política de auditoría (4719).

## Señales e indicadores
- Exclusiones nuevas en Defender, servicios de seguridad deshabilitados, silencio repentino de un equipo.

## ⚙️ Automatizado por Shuffle
1. Correlacionar la desconexión del agente con la última actividad del equipo; abrir incidente crítico.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Casi siempre indica actividad maliciosa ya en curso: busca qué ocurrió justo antes.

### 2. Contención
- [ ] Aísla el equipo; deshabilita la cuenta que hizo el cambio.

### 3. Erradicación
- [ ] Reinstala el agente y el antivirus, protege su configuración (tamper protection).

### 4. Recuperación
- [ ] Reenvía los registros en tiempo real a Wazuh para que el borrado local no elimine la evidencia.

### 5. Cierre y lecciones aprendidas
- [ ] Revisa el control OWASP A09:2025 (registro y alertas) para las aplicaciones.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Logs ya centralizados en Wazuh del periodo previo, imagen del equipo.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
data.win.system.eventID:("1102" OR "104" OR "4719")
rule.groups:"wazuh" AND rule.description:*disconnected*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Hayabusa](#/tools?q=Hayabusa) · [Chainsaw](#/tools?q=Chainsaw) · [DeepBlueCLI](#/tools?q=DeepBlueCLI) · [Sysmon](#/tools?q=Sysmon)
