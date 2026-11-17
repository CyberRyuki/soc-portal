---
title: "Criptominería no autorizada"
description: "Uso de servidores o equipos de la institución para minar criptomonedas"
level: Intermedio
category: Malware
severity: Medium
mitre: T1496
owasp: 
---
# Runbook — Criptominería no autorizada

> **Nivel:** Intermedio · **Severidad típica:** Media · **Categoría:** Malware  
> **MITRE ATT&CK:** [T1496](#/mitre?t=T1496)

## Cuándo usarlo
- CPU sostenida al 100 % sin motivo.
- Conexiones a pools de minería (puertos 3333, 4444, 14444; dominios *pool*).

## Señales e indicadores
- Procesos xmrig o con nombres falsos; tareas cron nuevas en Linux.

## ⚙️ Automatizado por Shuffle
1. Buscar el dominio/IP de destino en el motor de IoC; bloquear en firewall con aprobación.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Identifica el proceso, el usuario y la vía de entrada (vulnerabilidad expuesta, credencial SSH).

### 2. Contención
- [ ] Mata el proceso, bloquea los pools y aísla el servidor si fue una intrusión.

### 3. Erradicación
- [ ] Elimina cron/servicios y claves SSH añadidas; parchea la vulnerabilidad.

### 4. Recuperación
- [ ] Rota credenciales del servidor y vigila el consumo de CPU.

### 5. Cierre y lecciones aprendidas
- [ ] Comparte IoC en MISP.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Binario, configuración del minero (billetera, pool), cron, logs SSH.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
rule.description:*xmrig* OR data.dstport:("3333" OR "14444")
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[osquery](#/tools?q=osquery) · [Loki](#/tools?q=Loki) · [YARA](#/tools?q=YARA)
