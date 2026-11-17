---
title: "Webshell en servidor web"
description: "Archivo malicioso en el servidor web que permite ejecutar comandos de forma remota"
level: Intermedio
category: Aplicaciones web
severity: Critical
mitre: T1505.003, T1190, T1059
owasp: A05:2025, A08:2025
---
# Runbook — Webshell en servidor web

> **Nivel:** Intermedio · **Severidad típica:** Crítica · **Categoría:** Aplicaciones web  
> **MITRE ATT&CK:** [T1505.003](#/mitre?t=T1505.003) · [T1190](#/mitre?t=T1190) · [T1059](#/mitre?t=T1059) · **OWASP:** A05:2025, A08:2025

## Cuándo usarlo
- FIM de Wazuh detecta un archivo nuevo .php/.aspx/.jsp en directorios web.
- El proceso del servidor web (w3wp, httpd, php-fpm) lanza cmd, powershell, sh o whoami.

## Señales e indicadores
- Archivos con nombres aleatorios o que imitan legítimos (`img.php`, `config.bak.php`).
- Funciones `eval`, `base64_decode`, `system`, `assert` en el código.
- Peticiones POST a un archivo que antes no existía.

## ⚙️ Automatizado por Shuffle
1. Calcular el hash del archivo y buscarlo en MISP y el motor de IoC.
2. Escanear el directorio web con YARA (reglas de webshells).

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Confirma el archivo y su hora de creación; busca en el log de acceso qué IP lo subió y quién lo usó.
- [ ] Revisa procesos hijos del servidor web y conexiones salientes.

### 2. Contención
- [ ] Aísla el servidor o restringe el acceso al sitio.
- [ ] Bloquea las IPs que usaron la webshell.
- [ ] **No borres aún el archivo**: copia y calcula hash primero.

### 3. Erradicación
- [ ] Elimina la webshell y busca otras (YARA, archivos modificados recientemente).
- [ ] Corrige la vía de entrada (vulnerabilidad, subida de archivos, CMS desactualizado).
- [ ] Rota credenciales almacenadas en el servidor (BD, API keys).

### 4. Recuperación
- [ ] Restaura desde una copia limpia si no puedes garantizar la integridad.
- [ ] Vigila el FIM del directorio web 30 días.

### 5. Cierre y lecciones aprendidas
- [ ] Comparte hash e IPs en MISP.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Copia de la webshell, logs de acceso y error, lista de procesos, imagen del servidor si es crítico.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"syscheck" AND syscheck.path:*wwwroot* OR syscheck.path:*/var/www*
data.win.eventdata.parentImage:*w3wp.exe*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[YARA](#/tools?q=YARA) · [Loki](#/tools?q=Loki) · [signature-base](#/tools?q=signature-base) · [Velociraptor](#/tools?q=Velociraptor)
