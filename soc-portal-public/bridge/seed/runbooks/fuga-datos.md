---
title: "Fuga o exfiltración de datos"
description: "Salida no autorizada de información: subidas masivas a la nube, correo personal, USB o canales cifrados"
level: Intermedio
category: Datos
severity: High
mitre: T1041, T1567.002, T1048, T1052.001
owasp: A01:2025
---
# Runbook — Fuga o exfiltración de datos

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Datos  
> **MITRE ATT&CK:** [T1041](#/mitre?t=T1041) · [T1567.002](#/mitre?t=T1567.002) · [T1048](#/mitre?t=T1048) · [T1052.001](#/mitre?t=T1052.001) · **OWASP:** A01:2025

## Cuándo usarlo
- Volumen de subida anómalo de un equipo o usuario.
- Subidas a servicios de almacenamiento personales (Mega, Drive personal) o herramientas como rclone.

## Señales e indicadores
- Compresión previa de muchos archivos (7z, rar con contraseña).
- Tráfico DNS con subdominios largos (túnel).

## ⚙️ Automatizado por Shuffle
1. Calcular el volumen de datos salientes por equipo en las últimas 24 h.
2. Identificar destinos y reputación.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] ¿Qué datos salieron, de quién y hacia dónde? ¿Es una tarea legítima (copia, migración)?
- [ ] Determina si es un interno (runbook **Amenaza interna**) o un atacante externo.

### 2. Contención
- [ ] Bloquea el destino, desactiva la cuenta y aísla el equipo.
- [ ] Revoca enlaces compartidos públicos.

### 3. Erradicación
- [ ] Elimina las herramientas de exfiltración y la vía de entrada.

### 4. Recuperación
- [ ] Evalúa con legal si hay datos personales: posible notificación de brecha.

### 5. Cierre y lecciones aprendidas
- [ ] Mejora reglas DLP y alertas de volumen.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Logs de proxy/firewall, Zeek, lista de archivos accedidos.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Consultas útiles en Wazuh (Discover)
```
data.win.eventdata.image:*rclone*
rule.groups:"firewall" AND data.srcip:"<ip>"
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[Zeek](#/tools?q=Zeek) · [RITA](#/tools?q=RITA) · [Arkime](#/tools?q=Arkime) · [Wireshark](#/tools?q=Wireshark)
