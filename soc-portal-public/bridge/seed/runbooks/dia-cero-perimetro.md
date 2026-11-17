---
title: "Explotación de día cero en equipos perimetrales"
description: "Explotación de una vulnerabilidad sin parche en VPN, firewall, correo o balanceadores expuestos"
level: Avanzado
category: Intrusión
severity: Critical
mitre: T1190, T1133, T1505
owasp: A02:2025
---
# Runbook — Explotación de día cero en equipos perimetrales

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Intrusión  
> **MITRE ATT&CK:** [T1190](#/mitre?t=T1190) · [T1133](#/mitre?t=T1133) · [T1505](#/mitre?t=T1505) · **OWASP:** A02:2025

## Cuándo usarlo
- Aviso de CISA KEV, del fabricante o del CSIRT sobre explotación activa.
- Comportamiento anómalo del equipo perimetral (reinicios, cuentas nuevas, conexiones salientes).

## Señales e indicadores
- Archivos nuevos en el equipo, cambios de configuración no registrados, sesiones VPN extrañas.

## ⚙️ Automatizado por Shuffle
1. Cruzar la versión del equipo con el aviso; cargar IoC del fabricante en el motor de IoC con retrobúsqueda.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Aplica la herramienta de comprobación de integridad del fabricante si existe.
- [ ] Revisa logs del equipo y conexiones internas desde su IP.

### 2. Contención
- [ ] Aplica la mitigación temporal del fabricante o desconecta el servicio expuesto.
- [ ] Restablece credenciales almacenadas en el equipo.

### 3. Erradicación
- [ ] Parchea o reinstala con firmware limpio; busca movimiento lateral desde el equipo.

### 4. Recuperación
- [ ] Registra el CVE en **Vulnerabilidades** con fecha límite crítica de 7 días.

### 5. Cierre y lecciones aprendidas
- [ ] Plan para reducir la exposición de interfaces de gestión a Internet.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Logs del equipo, volcado de configuración, resultados de la herramienta de integridad.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
data.srcip:"<ip-del-equipo>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Nuclei](#/tools?q=Nuclei) · [Nmap](#/tools?q=Nmap) · [Shodan CLI](#/tools?q=Shodan%20CLI)
