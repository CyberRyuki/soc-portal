---
title: "Certificado SSL caducado o inválido"
description: "Un portal institucional muestra un certificado caducado, a punto de caducar o no válido"
level: Básico
category: Disponibilidad
severity: Medium
mitre: 
owasp: A04:2025, A02:2025
---
# Runbook — Certificado SSL caducado o inválido

> **Nivel:** Básico · **Severidad típica:** Media · **Categoría:** Disponibilidad  
> **MITRE ATT&CK:** — · **OWASP:** A04:2025, A02:2025

## Cuándo usarlo
- El monitor de **Portales** avisa de que el certificado caduca en 30 días o menos o da error.
- Usuarios reportan avisos de seguridad del navegador.

## Señales e indicadores
- Error de nombre (CN/SAN), cadena incompleta o autoridad no reconocida.

## ⚙️ Automatizado por Shuffle
1. El monitor de portales registra la fecha de caducidad y abre incidente si está configurado.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Comprueba con testssl.sh la cadena, protocolos y fecha.
- [ ] Descarta un ataque de intermediario (certificado inesperado) comparando la huella con la del servidor.

### 2. Contención
- [ ] Si el certificado presentado no es el vuestro → trata como posible secuestro DNS/MITM y escala.

### 3. Erradicación
- [ ] Renueva el certificado (ACME/Let's Encrypt o CA institucional) e instala la cadena completa.

### 4. Recuperación
- [ ] Verifica con testssl.sh y desde el monitor de portales.

### 5. Cierre y lecciones aprendidas
- [ ] Automatiza la renovación y deja la alerta de 30 días activa.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Salida de testssl.sh antes y después.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Herramientas recomendadas
[testssl.sh](#/tools?q=testssl.sh) · [SSLyze](#/tools?q=SSLyze)
