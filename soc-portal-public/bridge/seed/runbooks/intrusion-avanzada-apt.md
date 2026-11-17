---
title: "Intrusión avanzada persistente (APT)"
description: "Actor sofisticado con acceso prolongado, sigilo y objetivos de espionaje"
level: Avanzado
category: Intrusión
severity: Critical
mitre: T1190, T1078, T1021, T1003, T1071, T1560
owasp: 
---
# Runbook — Intrusión avanzada persistente (APT)

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Intrusión  
> **MITRE ATT&CK:** [T1190](#/mitre?t=T1190) · [T1078](#/mitre?t=T1078) · [T1021](#/mitre?t=T1021) · [T1003](#/mitre?t=T1003) · [T1071](#/mitre?t=T1071) · [T1560](#/mitre?t=T1560)

## Cuándo usarlo
- Varias detecciones de distintas tácticas en semanas (acceso inicial, credenciales, movimiento lateral, C2).
- Aviso de un socio, del CSIRT o de inteligencia sobre una campaña contra el sector.

## Señales e indicadores
- Uso de herramientas legítimas (living off the land), horarios regulares, cuentas válidas.
- Archivos comprimidos preparados para salir.

## ⚙️ Automatizado por Shuffle
1. Correlación en el motor de IoC con informes del actor; marcar todos los equipos con coincidencias.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Trabaja con discreción: evita alertar al actor hasta tener el alcance completo.
- [ ] Construye la línea de tiempo (Plaso/Timesketch) y el mapa de tácticas en **MITRE ATT&CK**.

### 2. Contención
- [ ] Planifica una contención coordinada (todo a la vez): cuentas, equipos, C2, accesos externos.

### 3. Erradicación
- [ ] Elimina todos los puntos de persistencia identificados; reconstruye sistemas críticos.
- [ ] Restablece credenciales del dominio (krbtgt doble).

### 4. Recuperación
- [ ] Caza de amenazas (threat hunting) continua 90 días con las TTP del actor.

### 5. Cierre y lecciones aprendidas
- [ ] Informe a dirección y CSIRT nacional; comparte TTP e IoC en MISP.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Imágenes forenses, memoria, logs centralizados, cadena de custodia.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
rule.mitre.tactic:"Lateral Movement" OR rule.mitre.tactic:"Credential Access"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Velociraptor](#/tools?q=Velociraptor) · [Plaso (log2timeline)](#/tools?q=Plaso) · [Timesketch](#/tools?q=Timesketch) · [OpenCTI](#/tools?q=OpenCTI) · [ATT&CK Navigator](#/tools?q=ATT&CK%20Navigator) · [DFIR-IRIS](#/tools?q=DFIR-IRIS)
