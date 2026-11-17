---
title: "Escalada de privilegios"
description: "Un usuario o proceso obtiene permisos de administrador o de sistema sin autorización"
level: Intermedio
category: Endpoint
severity: High
mitre: T1068, T1548.002, T1078.002, T1098
owasp: A01:2025
---
# Runbook — Escalada de privilegios

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Endpoint  
> **MITRE ATT&CK:** [T1068](#/mitre?t=T1068) · [T1548.002](#/mitre?t=T1548.002) · [T1078.002](#/mitre?t=T1078.002) · [T1098](#/mitre?t=T1098) · **OWASP:** A01:2025

## Cuándo usarlo
- Usuario añadido a grupos privilegiados (Domain Admins, Administradores locales, sudoers).
- Explotación de vulnerabilidad local o bypass de UAC detectado por Sysmon/Wazuh.

## Señales e indicadores
- Eventos 4728/4732/4756 (alta en grupo), 4672 (privilegios especiales) fuera de horario.
- Procesos de sistema lanzados por usuarios estándar.

## ⚙️ Automatizado por Shuffle
1. Identificar quién hizo el cambio y desde qué equipo.
2. Comparar con las solicitudes de cambio aprobadas.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿Hay un cambio aprobado que lo justifique? Si no, trata como compromiso.
- [ ] Revisa la actividad de la cuenta antes y después de la escalada.

### 2. Contención
- [ ] Revierte la pertenencia al grupo y deshabilita la cuenta implicada.
- [ ] Aísla el equipo origen si hubo explotación.

### 3. Erradicación
- [ ] Parchea la vulnerabilidad explotada; revisa persistencia (runbook **Persistencia**).

### 4. Recuperación
- [ ] Revisa la lista de miembros de grupos privilegiados y aplica mínimo privilegio.

### 5. Cierre y lecciones aprendidas
- [ ] Valora un análisis de Active Directory con PingCastle.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Eventos de seguridad del DC y del equipo, lista de cambios.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
data.win.system.eventID:("4728" OR "4732" OR "4756")
rule.mitre.id:"T1548.002"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[PingCastle](#/tools?q=PingCastle) · [BloodHound](#/tools?q=BloodHound) · [AccessChk](#/tools?q=AccessChk) · [Autoruns](#/tools?q=Autoruns)
