---
title: "Ransomware"
description: "Cifrado de archivos y sistemas con petición de rescate, a menudo con robo previo de datos (doble extorsión)"
level: Avanzado
category: Malware
severity: Critical
mitre: T1486, T1490, T1489, T1562.001, T1567
owasp: 
---
# Runbook — Ransomware

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Malware  
> **MITRE ATT&CK:** [T1486](#/mitre?t=T1486) · [T1490](#/mitre?t=T1490) · [T1489](#/mitre?t=T1489) · [T1562.001](#/mitre?t=T1562.001) · [T1567](#/mitre?t=T1567)

## Cuándo usarlo
- Muchos archivos renombrados o modificados en minutos (FIM), notas de rescate.
- Borrado de copias de sombra (`vssadmin delete shadows`, `wbadmin delete`), detención de servicios de copia y antivirus.

## Señales e indicadores
- Extensiones nuevas en archivos, procesos con alto I/O de disco.
- Herramientas previas: Cobalt Strike, AnyDesk, rclone, PsExec masivo.

## ⚙️ Automatizado por Shuffle
1. Proponer el aislamiento del equipo en cuanto el FIM supere el umbral de cambios (un clic de aprobación en Shuffle).
2. Notificar de inmediato a la guardia y al responsable de seguridad.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] **Minuto 0**: no apagues los equipos (se pierde la memoria); desconéctalos de la red.
- [ ] Identifica variante (nota de rescate, extensión) en ID Ransomware / ransomware.live.
- [ ] Determina alcance: equipos, servidores, copias de seguridad, AD.

### 2. Contención
- [ ] Aísla segmentos completos si se propaga; corta VPN y accesos remotos.
- [ ] Deshabilita cuentas usadas por el atacante; protege y desconecta las copias de seguridad.
- [ ] Bloquea C2 e IoC conocidos de la variante.

### 3. Erradicación
- [ ] Busca el punto de entrada y la persistencia antes de restaurar.
- [ ] Restablece contraseñas de todas las cuentas privilegiadas y **dos veces krbtgt**.
- [ ] Parchea la vulnerabilidad de entrada.

### 4. Recuperación
- [ ] Restaura desde copias verificadas en una red limpia, por prioridad de negocio.
- [ ] Monitorización reforzada 30 días; vigila ransomware.live por si publican datos.

### 5. Cierre y lecciones aprendidas
- [ ] Decisión sobre el rescate: corresponde a la dirección con asesoría legal (en general, no se recomienda pagar).
- [ ] Informe post-incidente y simulacro de restauración.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Imagen de memoria y disco de equipos clave, nota de rescate, muestra del binario, logs del periodo.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"syscheck" AND agent.name:"<equipo>"
data.win.eventdata.commandLine:*shadowcopy* OR data.win.eventdata.commandLine:*vssadmin*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Ransomware.live](#/tools?q=Ransomware.live) · [Volatility 3](#/tools?q=Volatility%203) · [Velociraptor](#/tools?q=Velociraptor) · [KAPE](#/tools?q=KAPE) · [Hayabusa](#/tools?q=Hayabusa) · [FTK Imager](#/tools?q=FTK%20Imager)
