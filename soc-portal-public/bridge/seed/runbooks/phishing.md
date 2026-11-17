---
title: Phishing reportado
description: Análisis de un correo sospechoso enviado por un usuario
level: Básico
category: Correo
severity: High
mitre: T1566.001, T1566.002, T1204
owasp: 
---
# Runbook — Phishing reportado

> **Disparador:** un usuario reenvía un correo al buzón `phishing@` · **Severidad:** Media/Alta · **Workflow:** `SOC-Phishing`

## ⚙️ Automatizado por Shuffle
1. Lee los correos nuevos del buzón de reportes (Office 365 / IMAP).
2. Extrae el remitente, el *reply-to*, los dominios, las URLs y los adjuntos (con su SHA256).
3. Consulta cada IoC en MISP y VirusTotal.
4. Crea el incidente en el portal con los IoC y la puntuación obtenida.
5. Responde al usuario: *"Recibido; el SOC lo está analizando"*.

## 👤 Pasos del analista
1. **Revisa las cabeceras** del `.eml` original: SPF, DKIM, DMARC, `Received` y `Return-Path`.
2. **Analiza las URLs y adjuntos** en un entorno aislado (sandbox). **Nunca** los abras en tu equipo.
3. **Busca otros destinatarios** y clics en los logs de correo y proxy.
4. **Decide:**
    - **Legítimo / spam** → responde al usuario y cierra.
    - **Phishing** → continúa con la contención.
5. **Contén (con aprobación):** bloquea el remitente, el dominio y las URLs; elimina el correo de todos los buzones; cambia las credenciales si alguien las introdujo.
6. **Comparte la inteligencia:** crea el evento en MISP con el TLP adecuado.
7. **Cierra:** informa a los usuarios afectados y registra las lecciones aprendidas.

## Configuración en Shuffle
| # | Nodo | Configuración |
|---|---|---|
| 1 | Schedule (cada 5 min) | Dispara la lectura del buzón |
| 2 | Outlook / Email · Get emails | Buzón `phishing@`, solo los no leídos |
| 3 | Shuffle Tools · Parse IOC | Cuerpo y cabeceras del correo |
| 4 | MISP + VirusTotal | Reputación de cada IoC |
| 5 | Http · POST al portal | `runbook: phishing` |
| 6 | Email · Reply | Acuse de recibo al usuario |
