---
title: "Denegación de servicio (DoS/DDoS)"
description: "Saturación de un servicio por volumen de tráfico o de peticiones"
level: Intermedio
category: Disponibilidad
severity: High
mitre: T1498, T1499
owasp: A10:2025
---
# Runbook — Denegación de servicio (DoS/DDoS)

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Disponibilidad  
> **MITRE ATT&CK:** [T1498](#/mitre?t=T1498) · [T1499](#/mitre?t=T1499) · **OWASP:** A10:2025

## Cuándo usarlo
- Pico anómalo de conexiones en firewall/Suricata o de peticiones en el servidor web.
- Portal caído en el monitor con muchas alertas web al mismo tiempo.

## Señales e indicadores
- Miles de peticiones por segundo desde muchas IPs (botnet) o pocas IPs muy activas.
- Mismo User-Agent o misma URL repetida.

## ⚙️ Automatizado por Shuffle
1. Calcular las IPs, países y URLs más activas en los últimos 15 minutos.
2. Avisar a infraestructura y al proveedor de Internet.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Confirma que es un ataque y no una subida legítima (campaña, trámite masivo).
- [ ] Clasifica: volumétrico (ancho de banda), de protocolo (SYN) o de aplicación (HTTP).

### 2. Contención
- [ ] Pide mitigación al ISP o al servicio anti-DDoS/CDN.
- [ ] Aplica limitación de tasa y bloqueo geográfico temporal en WAF/firewall.
- [ ] Activa caché agresiva o página estática.

### 3. Erradicación
- [ ] Revisa si el DoS ocultaba otro ataque (intento de intrusión simultáneo).

### 4. Recuperación
- [ ] Retira gradualmente los bloqueos y vigila el monitor de portales.

### 5. Cierre y lecciones aprendidas
- [ ] Documenta volumen, duración y efectividad de la mitigación; acuerda un plan con el ISP.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Capturas de tráfico (PCAP), logs del firewall/WAF, gráficas.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"web" AND agent.name:"<servidor>"
rule.groups:"firewall"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Wireshark](#/tools?q=Wireshark) · [Zeek](#/tools?q=Zeek) · [Suricata](#/tools?q=Suricata) · [tcpdump](#/tools?q=tcpdump)
