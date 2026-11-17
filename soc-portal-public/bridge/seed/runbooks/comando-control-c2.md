---
title: "Comunicación con servidor de comando y control (C2)"
description: "Un equipo contacta periódicamente con infraestructura del atacante (beaconing)"
level: Intermedio
category: Red interna
severity: Critical
mitre: T1071, T1573, T1071.004, T1095
owasp: 
---
# Runbook — Comunicación con servidor de comando y control (C2)

> **Nivel:** Intermedio · **Severidad típica:** Crítica · **Categoría:** Red interna  
> **MITRE ATT&CK:** [T1071](#/mitre?t=T1071) · [T1573](#/mitre?t=T1573) · [T1071.004](#/mitre?t=T1071.004) · [T1095](#/mitre?t=T1095)

## Cuándo usarlo
- Coincidencia del **motor de IoC** con IP/dominio de C2 (Feodo, ThreatFox).
- RITA detecta beaconing o DNS con subdominios largos.

## Señales e indicadores
- Conexiones a intervalos regulares, User-Agent raros, certificados autofirmados.
- Consultas DNS TXT frecuentes.

## ⚙️ Automatizado por Shuffle
1. Identificar el proceso que conecta (Sysmon 3/22) y proponer el aislamiento si la puntuación de riesgo es ≥ 80.
2. Buscar el mismo destino en todo el parque.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Confirma con el proceso y el binario; descarta falsos positivos (CDN compartida).

### 2. Contención
- [ ] Aísla los equipos, bloquea dominio/IP en DNS, proxy y firewall.

### 3. Erradicación
- [ ] Analiza el malware (runbook **Malware en un equipo**) y busca movimiento lateral.

### 4. Recuperación
- [ ] Reimagina los equipos infectados y rota credenciales usadas en ellos.

### 5. Cierre y lecciones aprendidas
- [ ] Comparte la infraestructura C2 en MISP.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- PCAP o logs Zeek, eventos Sysmon, binario.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"misp" OR rule.groups:"ioc"
data.win.eventdata.destinationIp:"<ip>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[RITA](#/tools?q=RITA) · [Zeek](#/tools?q=Zeek) · [Suricata](#/tools?q=Suricata) · [Velociraptor](#/tools?q=Velociraptor)
