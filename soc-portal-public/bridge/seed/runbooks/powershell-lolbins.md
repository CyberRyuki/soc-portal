---
title: "PowerShell sospechoso y abuso de binarios del sistema (LOLBins)"
description: "Ejecución de PowerShell ofuscado o abuso de certutil, mshta, rundll32, regsvr32, bitsadmin para descargar o ejecutar código"
level: Intermedio
category: Endpoint
severity: High
mitre: T1059.001, T1218, T1027, T1105
owasp: 
---
# Runbook — PowerShell sospechoso y abuso de binarios del sistema (LOLBins)

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Endpoint  
> **MITRE ATT&CK:** [T1059.001](#/mitre?t=T1059.001) · [T1218](#/mitre?t=T1218) · [T1027](#/mitre?t=T1027) · [T1105](#/mitre?t=T1105)

## Cuándo usarlo
- Comandos con `-enc`, `IEX`, `DownloadString`, `FromBase64String`.
- certutil `-urlcache`, mshta con URL, rundll32 con JavaScript, bitsadmin `/transfer`.

## Señales e indicadores
- Proceso padre inusual (Word/Excel → PowerShell).
- Conexiones salientes de binarios del sistema.

## ⚙️ Automatizado por Shuffle
1. Decodificar el comando (Base64) y extraer URLs/IPs.
2. Consultar indicadores en el motor de IoC y MISP; aislar si hay coincidencia.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Decodifica el script (CyberChef) y entiende qué hace.
- [ ] Identifica el origen: documento, correo, tarea programada, usuario.

### 2. Contención
- [ ] Aísla el equipo y bloquea las URLs/dominios en el proxy.

### 3. Erradicación
- [ ] Elimina lo descargado y la persistencia; aplica Constrained Language Mode/AMSI y reglas ASR.

### 4. Recuperación
- [ ] Activa el registro de bloques de script de PowerShell (4104) en todos los equipos.

### 5. Cierre y lecciones aprendidas
- [ ] Añade los indicadores al motor de IoC.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Eventos 4104/4103, Sysmon 1/3/11, el script decodificado.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
data.win.eventdata.commandLine:*-enc* OR data.win.eventdata.commandLine:*DownloadString*
data.win.eventdata.image:*certutil.exe* AND data.win.eventdata.commandLine:*urlcache*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[CyberChef](#/tools?q=CyberChef) · [DeepBlueCLI](#/tools?q=DeepBlueCLI) · [Hayabusa](#/tools?q=Hayabusa) · [Sysmon](#/tools?q=Sysmon)
