---
title: "Portal web caído o degradado"
description: "Un portal institucional no responde, responde con errores o muy lento"
level: Básico
category: Disponibilidad
severity: High
mitre: T1499, T1498
owasp: A10:2025
---
# Runbook — Portal web caído o degradado

> **Nivel:** Básico · **Severidad típica:** Alta · **Categoría:** Disponibilidad  
> **MITRE ATT&CK:** [T1499](#/mitre?t=T1499) · [T1498](#/mitre?t=T1498) · **OWASP:** A10:2025

## Cuándo usarlo
- El monitor de **Portales** marca el sitio como caído (2 fallos seguidos).
- Reportes de usuarios o ciudadanos.

## Señales e indicadores
- Códigos 5xx, tiempo de espera agotado, error de DNS o de certificado.

## ⚙️ Automatizado por Shuffle
1. El monitor crea el incidente automáticamente si está configurado.
2. Shuffle puede avisar a infraestructura por el canal acordado.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿Es solo el portal o toda la red/hosting? Prueba desde dentro y desde fuera.
- [ ] Revisa en Wazuh si hay un pico de tráfico o de errores (posible DoS → runbook **Denegación de servicio**).
- [ ] Comprueba si el contenido cambió (posible desfiguración).

### 2. Contención
- [ ] Coordina con infraestructura/hosting el reinicio de servicios o la conmutación a respaldo.

### 3. Erradicación
- [ ] Identifica la causa raíz (cambio reciente, disco lleno, certificado, ataque).

### 4. Recuperación
- [ ] Confirma el restablecimiento en el monitor de portales durante al menos 30 minutos.

### 5. Cierre y lecciones aprendidas
- [ ] Documenta tiempo de caída e impacto.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Historial del monitor, logs del servidor web.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
agent.name:"<servidor-web>" AND rule.groups:"web"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[httpx](#/tools?q=httpx)
