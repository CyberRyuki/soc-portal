---
title: "Ataque web: inyección SQL, XSS o comandos"
description: "Intentos o explotación de inyección (SQL, XSS, comandos, path traversal) contra una aplicación web"
level: Intermedio
category: Aplicaciones web
severity: High
mitre: T1190, T1059
owasp: A05:2025, A01:2025
---
# Runbook — Ataque web: inyección SQL, XSS o comandos

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Aplicaciones web  
> **MITRE ATT&CK:** [T1190](#/mitre?t=T1190) · [T1059](#/mitre?t=T1059) · **OWASP:** A05:2025, A01:2025

## Cuándo usarlo
- Reglas web de Wazuh (grupo `web`/`attack`: SQL injection, XSS, command injection, directory traversal).
- Alertas de Suricata/WAF sobre la misma aplicación.

## Señales e indicadores
- Parámetros con `' OR 1=1`, `UNION SELECT`, `<script>`, `../`, `;id`.
- Respuestas 200 a esas peticiones (posible explotación) frente a 403/404 (bloqueadas).

## ⚙️ Automatizado por Shuffle
1. Agrupar por IP de origen y URL atacada.
2. Consultar la IP en el motor de IoC y AbuseIPDB.
3. Si hay respuestas 200 o 500 a payloads: severidad Alta y aviso al responsable de la aplicación.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿Es un escaneo automático (muchas URLs, muchas firmas) o un ataque dirigido (pocas URLs, iteración)?
- [ ] Revisa los códigos de respuesta y el tamaño: un 200 con mucho contenido puede indicar extracción de datos.
- [ ] Identifica la aplicación, su versión y si hay CVE conocidos.

### 2. Contención
- [ ] Bloquea la IP (active response `firewall-drop` o WAF) con aprobación.
- [ ] Si se confirmó explotación: pon la aplicación en mantenimiento o restringe el acceso.

### 3. Erradicación
- [ ] Corrige la vulnerabilidad (consultas parametrizadas, validación de entrada, escape de salida).
- [ ] Busca webshells subidas (runbook **Webshell en servidor web**).

### 4. Recuperación
- [ ] Repite la prueba con ZAP o sqlmap (autorizado) antes de reabrir.
- [ ] Rota credenciales de la base de datos si pudieron leerse.

### 5. Cierre y lecciones aprendidas
- [ ] Registra el hallazgo en **Vulnerabilidades** con su fecha límite.
- [ ] Revisa el control OWASP correspondiente en el apartado OWASP Top 10.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Logs de acceso del servidor web, alertas WAF, consultas de la base de datos del periodo.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"web" AND rule.groups:"attack"
rule.description:*SQL* OR rule.description:*XSS*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[ZAP (Zed Attack Proxy)](#/tools?q=ZAP) · [sqlmap](#/tools?q=sqlmap) · [Nuclei](#/tools?q=Nuclei) · [Nikto](#/tools?q=Nikto)
