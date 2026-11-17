---
title: "Movimiento lateral"
description: "El atacante salta de un equipo a otro con RDP, SMB/PsExec, WMI, WinRM o credenciales robadas"
level: Intermedio
category: Red interna
severity: High
mitre: T1021.001, T1021.002, T1047, T1570, T1550.002
owasp: 
---
# Runbook — Movimiento lateral

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Red interna  
> **MITRE ATT&CK:** [T1021.001](#/mitre?t=T1021.001) · [T1021.002](#/mitre?t=T1021.002) · [T1047](#/mitre?t=T1047) · [T1570](#/mitre?t=T1570) · [T1550.002](#/mitre?t=T1550.002)

## Cuándo usarlo
- Inicios de sesión tipo 3/10 de una misma cuenta en muchos equipos en poco tiempo.
- Servicios creados de forma remota (PSEXESVC), WMI o WinRM desde estaciones de usuario.

## Señales e indicadores
- Cuentas de administrador usadas desde estaciones de trabajo.
- Herramientas de administración (PsExec, wmic) en equipos que no las usan.

## ⚙️ Automatizado por Shuffle
1. Listar equipos tocados por la cuenta en la última hora.
2. Generar el grafo origen → destino para el analista.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Identifica el «paciente cero» y la cuenta usada.
- [ ] Determina si es administración legítima (ventana de cambios, equipo de soporte).

### 2. Contención
- [ ] Deshabilita la cuenta, aísla los equipos afectados (Wazuh active response o EDR).
- [ ] Bloquea SMB/RDP entre estaciones de trabajo por firewall.

### 3. Erradicación
- [ ] Busca persistencia en cada equipo; restablece contraseñas de cuentas usadas (incluida krbtgt si hay indicios de AD).

### 4. Recuperación
- [ ] Segmenta la red y usa LAPS para cuentas locales.

### 5. Cierre y lecciones aprendidas
- [ ] Si afectó a servidores críticos, escala a runbook **Intrusión avanzada (APT)**.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Eventos 4624/4648/7045, Sysmon 1/3, logs de firewall internos.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
data.win.system.eventID:"7045" AND data.win.eventdata.serviceName:*PSEXE*
data.win.system.eventID:"4624" AND data.win.eventdata.logonType:("3" OR "10")
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Velociraptor](#/tools?q=Velociraptor) · [BloodHound](#/tools?q=BloodHound) · [Hayabusa](#/tools?q=Hayabusa) · [Chainsaw](#/tools?q=Chainsaw)
