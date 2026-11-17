---
title: "Rootkit, bootkit o compromiso de firmware"
description: "Malware que se oculta en el núcleo, el arranque o el firmware para sobrevivir a reinstalaciones"
level: Avanzado
category: Endpoint
severity: Critical
mitre: T1014, T1542.003, T1542.001, T1601
owasp: 
---
# Runbook — Rootkit, bootkit o compromiso de firmware

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Endpoint  
> **MITRE ATT&CK:** [T1014](#/mitre?t=T1014) · [T1542.003](#/mitre?t=T1542.003) · [T1542.001](#/mitre?t=T1542.001) · [T1601](#/mitre?t=T1601)

## Cuándo usarlo
- Wazuh rootcheck detecta procesos o archivos ocultos.
- Drivers sin firma cargados, Secure Boot desactivado, discrepancias entre vistas del sistema.

## Señales e indicadores
- Puertos abiertos que no aparecen en netstat local, procesos invisibles en el listado.

## ⚙️ Automatizado por Shuffle
1. Marcar el equipo como crítico y aislarlo de la red con aprobación.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Analiza la memoria (Volatility) desde un volcado, no confíes en el sistema en vivo.

### 2. Contención
- [ ] Aísla el equipo físicamente; no lo vuelvas a conectar.

### 3. Erradicación
- [ ] Reflashea el firmware (BIOS/UEFI) desde el fabricante y reinstala desde cero; en algunos casos, sustituye el hardware.

### 4. Recuperación
- [ ] Activa Secure Boot, firma de drivers y medición de arranque.

### 5. Cierre y lecciones aprendidas
- [ ] Comparte el análisis con el fabricante y el CSIRT.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Volcado de memoria, imagen de disco, volcado del firmware si es posible.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"rootcheck"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Volatility 3](#/tools?q=Volatility%203) · [WinPmem](#/tools?q=WinPmem) · [LiME](#/tools?q=LiME) · [FTK Imager](#/tools?q=FTK%20Imager)
