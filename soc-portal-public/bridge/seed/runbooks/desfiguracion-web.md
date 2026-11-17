---
title: "Desfiguración de portal (defacement)"
description: "El contenido público de un portal institucional fue alterado por terceros"
level: Intermedio
category: Aplicaciones web
severity: High
mitre: T1491.002, T1190
owasp: A01:2025, A02:2025
---
# Runbook — Desfiguración de portal (defacement)

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Aplicaciones web  
> **MITRE ATT&CK:** [T1491.002](#/mitre?t=T1491.002) · [T1190](#/mitre?t=T1190) · **OWASP:** A01:2025, A02:2025

## Cuándo usarlo
- El monitor de **Portales** detecta un cambio de contenido o falta el texto obligatorio.
- Reportes ciudadanos o en redes sociales.

## Señales e indicadores
- Mensajes de grupos hacktivistas, imágenes o enlaces ajenos.
- Archivos index modificados en el FIM.

## ⚙️ Automatizado por Shuffle
1. El monitor de portales abre el incidente; Shuffle puede notificar a dirección y comunicación.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Captura la página (pantallazo y HTML) como evidencia.
- [ ] Determina si es en el servidor (archivos cambiados) o en el DNS/CDN (secuestro).

### 2. Contención
- [ ] Retira el sitio o muestra una página de mantenimiento.
- [ ] Cambia credenciales de administración del CMS, FTP/SSH y panel del hosting.

### 3. Erradicación
- [ ] Busca webshells y cuentas creadas por el atacante (runbook **Webshell**).
- [ ] Actualiza CMS, plugins y temas.

### 4. Recuperación
- [ ] Restaura desde una copia verificada y vuelve a publicar.
- [ ] Activa «vigilar cambios» en el monitor de portales.

### 5. Cierre y lecciones aprendidas
- [ ] Coordina un comunicado oficial con el área de comunicación.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Capturas, HTML alterado, logs del servidor y del CMS.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"syscheck" AND syscheck.path:*index*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[WPScan](#/tools?q=WPScan) · [Nuclei](#/tools?q=Nuclei) · [httpx](#/tools?q=httpx)
