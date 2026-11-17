---
title: "Amenaza interna"
description: "Un empleado o contratista accede, copia o destruye información sin autorización"
level: Intermedio
category: Datos
severity: High
mitre: T1078, T1530, T1213
owasp: A01:2025
---
# Runbook — Amenaza interna

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Datos  
> **MITRE ATT&CK:** [T1078](#/mitre?t=T1078) · [T1530](#/mitre?t=T1530) · [T1213](#/mitre?t=T1213) · **OWASP:** A01:2025

## Cuándo usarlo
- Accesos masivos a carpetas o sistemas fuera de su función.
- Actividad de una cuenta de alguien que va a salir de la institución.

## Señales e indicadores
- Descargas fuera de horario, uso de USB o correo personal, borrado de registros.

## ⚙️ Automatizado por Shuffle
1. Resumen de accesos y volumen del usuario de los últimos 30 días (sin alertar al usuario).

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Coordina con RR. HH. y legal **antes** de cualquier contacto con la persona.
- [ ] Documenta los hechos con evidencias objetivas.

### 2. Contención
- [ ] Restringe accesos de forma discreta según indique legal; preserva el equipo.

### 3. Erradicación
- [ ] Revoca accesos y credenciales compartidas que conociera.

### 4. Recuperación
- [ ] Revisa permisos del área (mínimo privilegio).

### 5. Cierre y lecciones aprendidas
- [ ] Cierre coordinado con RR. HH. y legal; confidencialidad del expediente.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Logs con cadena de custodia, imagen forense del equipo si procede.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
data.win.eventdata.subjectUserName:"<usuario>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[FTK Imager](#/tools?q=FTK%20Imager) · [KAPE](#/tools?q=KAPE) · [Velociraptor](#/tools?q=Velociraptor)
