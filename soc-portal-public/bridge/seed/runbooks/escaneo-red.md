---
title: Escaneo de red o reconocimiento
description: Barridos de puertos o servicios contra la red
level: Básico
category: Red interna
severity: Medium
mitre: T1046, T1595
owasp: 
---
# Runbook — Escaneo de red o reconocimiento

> **Disparador:** reglas de Suricata o del firewall de escaneo (p. ej. *ET SCAN*), o muchos puertos o destinos desde una misma IP · **Severidad:** Baja/Media (Alta si el origen es interno) · **Workflow:** `SOC-Network-Scan`

## ⚙️ Automatizado por Shuffle
1. Agrupa los eventos de escaneo por IP de origen durante 1 h.
2. Consulta la reputación de la IP (GreyNoise / AbuseIPDB). Un escáner conocido de Internet es "ruido".
3. **Origen externo y reputación conocida** → solo lo registra en el informe diario.
4. **Origen interno** → crea un incidente **High**: puede ser un equipo comprometido haciendo reconocimiento.

## 👤 Pasos del analista
1. **¿El origen es interno?** Identifica el equipo y el usuario. ¿Es un escaneo autorizado (inventario, pentest)?
2. **¿Fue un escaneo dirigido?** Muchos puertos contra pocos destinos sugiere preparación de un ataque.
3. **Revisa si hubo explotación** después del escaneo: alertas en los destinos escaneados.
4. **Contén (con aprobación):** bloquea la IP externa o aísla el equipo interno.
5. **Cierra** como ruido, escaneo autorizado o incidente.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Webhook `wazuh` | Grupos `ids`, `suricata` o `firewall` con firma *SCAN* |
| 2 | GreyNoise / AbuseIPDB | IP de origen |
| 3 | Condición | ¿IP privada (10/8, 172.16/12, 192.168/16)? |
| 4 | Http · POST al portal | `runbook: escaneo-red` |
