---
title: "Compromiso de Active Directory"
description: "DCSync, Golden/Silver Ticket, Kerberoasting, cambios de GPO o controladores de dominio falsos"
level: Avanzado
category: Identidad
severity: Critical
mitre: T1003.006, T1558.001, T1558.003, T1484.001, T1207
owasp: 
---
# Runbook — Compromiso de Active Directory

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Identidad  
> **MITRE ATT&CK:** [T1003.006](#/mitre?t=T1003.006) · [T1558.001](#/mitre?t=T1558.001) · [T1558.003](#/mitre?t=T1558.003) · [T1484.001](#/mitre?t=T1484.001) · [T1207](#/mitre?t=T1207)

## Cuándo usarlo
- Replicación de directorio (4662 con GUID de replicación) desde un equipo que no es DC.
- Tickets Kerberos anómalos (RC4, duración larga), muchas peticiones TGS de cuentas de servicio.

## Señales e indicadores
- Cambios en GPO o en AdminSDHolder, cuentas nuevas en Domain Admins.
- Herramientas como Mimikatz, Rubeus, Impacket.

## ⚙️ Automatizado por Shuffle
1. Alerta crítica inmediata a la guardia; listar cambios en grupos privilegiados y GPO de las últimas 24 h.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Asume compromiso total del dominio si se confirma DCSync o Golden Ticket.
- [ ] Identifica las cuentas y equipos usados por el atacante.

### 2. Contención
- [ ] Aísla los equipos del atacante; deshabilita cuentas comprometidas.
- [ ] Restablece **dos veces krbtgt** (con 10–12 h de intervalo) y contraseñas de cuentas privilegiadas y de servicio.

### 3. Erradicación
- [ ] Revierte GPO y permisos modificados; busca persistencia en AD (AdminSDHolder, SIDHistory, delegaciones).
- [ ] Analiza el dominio con PingCastle y BloodHound.

### 4. Recuperación
- [ ] Modelo de niveles (tiering), estaciones de administración privilegiada, LAPS, desactivar RC4.

### 5. Cierre y lecciones aprendidas
- [ ] Plan de endurecimiento de AD con fechas en **Vulnerabilidades**.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Eventos de seguridad de todos los DC, copia del NTDS si es necesario, informes PingCastle.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
data.win.system.eventID:"4662" AND data.win.eventdata.properties:*1131f6aa*
data.win.system.eventID:"4769" AND data.win.eventdata.ticketEncryptionType:"0x17"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[PingCastle](#/tools?q=PingCastle) · [BloodHound](#/tools?q=BloodHound) · [Purple Knight](#/tools?q=Purple%20Knight) · [Hayabusa](#/tools?q=Hayabusa) · [Chainsaw](#/tools?q=Chainsaw)
