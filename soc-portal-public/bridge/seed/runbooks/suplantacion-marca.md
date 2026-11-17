---
title: "Suplantación de la institución (dominios y redes sociales)"
description: "Dominios parecidos (typosquatting), perfiles falsos o sitios que imitan a la institución"
level: Básico
category: Marca
severity: Medium
mitre: T1583.001, T1585.001
owasp: 
---
# Runbook — Suplantación de la institución (dominios y redes sociales)

> **Nivel:** Básico · **Severidad típica:** Media · **Categoría:** Marca  
> **MITRE ATT&CK:** [T1583.001](#/mitre?t=T1583.001) · [T1585.001](#/mitre?t=T1585.001)

## Cuándo usarlo
- Aviso ciudadano o del CSIRT de un sitio o perfil falso.
- Registro de un dominio parecido detectado por un servicio de vigilancia de marca.

## Señales e indicadores
- Dominio con letras cambiadas (ogtlc.gob, acme-pagos.com).
- Formularios que piden datos personales, claves o pagos.

## ⚙️ Automatizado por Shuffle
1. Resolver el dominio (IP, registrador, fecha de alta, certificado).
2. Añadir dominio e IP al motor de IoC y comprobar si alguien de la red lo visitó.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Captura el sitio o perfil (pantallazo, URL, fecha) antes de que desaparezca.
- [ ] Comprueba si roba credenciales institucionales (→ runbook **Phishing**).

### 2. Contención
- [ ] Bloquea dominio e IP en DNS/proxy/firewall.
- [ ] Solicita la baja (takedown) al registrador, al hosting y a la red social.
- [ ] Avisa a la ciudadanía por canales oficiales si hay riesgo de fraude.

### 3. Erradicación
- [ ] Registra variantes defensivas del dominio si procede.

### 4. Recuperación
- [ ] Sigue el estado del takedown hasta su cierre.

### 5. Cierre y lecciones aprendidas
- [ ] Comparte los indicadores en MISP con el CSIRT nacional.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Capturas, WHOIS, certificados, cabeceras HTTP.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
data.win.eventdata.queryName:*<dominio>*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[DNSRecon](#/tools?q=DNSRecon) · [theHarvester](#/tools?q=theHarvester) · [Sherlock](#/tools?q=Sherlock) · [SpiderFoot](#/tools?q=SpiderFoot)
