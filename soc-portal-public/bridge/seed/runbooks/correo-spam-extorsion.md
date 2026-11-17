---
title: "Correo de spam o extorsión"
description: "Spam masivo, sextorsión o amenazas por correo sin enlaces ni adjuntos maliciosos confirmados"
level: Básico
category: Correo
severity: Low
mitre: T1566, T1598
owasp: 
---
# Runbook — Correo de spam o extorsión

> **Nivel:** Básico · **Severidad típica:** Baja · **Categoría:** Correo  
> **MITRE ATT&CK:** [T1566](#/mitre?t=T1566) · [T1598](#/mitre?t=T1598)

## Cuándo usarlo
- Un usuario reporta un correo de extorsión («tengo tus fotos», «paga en bitcoin»).
- El filtro antispam marca una campaña masiva hacia la institución.

## Señales e indicadores
- Remitente falso o suplantando al propio destinatario.
- Mención de una contraseña antigua del usuario (procede de una filtración pública).
- Petición de pago en criptomonedas con plazo.

## ⚙️ Automatizado por Shuffle
1. Extraer remitente, IPs de cabecera, URLs y direcciones de billetera.
2. Consultar remitente y URLs en el motor de IoC y MISP.
3. Si no hay coincidencias ni adjuntos: clasificar como Baja y responder al usuario con la plantilla.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Confirma que no hay adjuntos ni enlaces a sitios maliciosos (si los hay → runbook **Phishing reportado**).
- [ ] Si menciona una contraseña real: compruébala con el usuario y trata la cuenta como expuesta (runbook **Credenciales expuestas**).
- [ ] Busca si el mismo remitente o asunto llegó a más buzones.

### 2. Contención
- [ ] Bloquea remitente/dominio en la pasarela de correo y elimina los mensajes de todos los buzones.
- [ ] Añade las billeteras e IPs al motor de IoC (origen «Campaña spam», confianza 50).

### 3. Erradicación
- [ ] Ajusta reglas antispam (asunto, patrón del cuerpo).

### 4. Recuperación
- [ ] Tranquiliza al usuario: es una estafa masiva; no pagar ni responder.

### 5. Cierre y lecciones aprendidas
- [ ] Registra la campaña para estadísticas; comunica un aviso general si afecta a muchos usuarios.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Correo original en formato .eml con cabeceras completas.

## Escalamiento
Analista nivel 1. Escala a nivel 2 si hay indicios de compromiso real, datos sensibles o más de un equipo afectado.

## Consultas útiles en Wazuh (Discover)
```
rule.groups:"spam" OR data.subject:*bitcoin*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Sherlock](#/tools?q=Sherlock) · [CyberChef](#/tools?q=CyberChef)
