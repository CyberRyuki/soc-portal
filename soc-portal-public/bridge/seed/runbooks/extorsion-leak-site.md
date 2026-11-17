---
title: "Datos publicados en un sitio de filtración"
description: "La institución aparece como víctima en el sitio de un grupo de ransomware o de extorsión"
level: Avanzado
category: Datos
severity: Critical
mitre: T1657, T1567, T1486
owasp: 
---
# Runbook — Datos publicados en un sitio de filtración

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Datos  
> **MITRE ATT&CK:** [T1657](#/mitre?t=T1657) · [T1567](#/mitre?t=T1567) · [T1486](#/mitre?t=T1486)

## Cuándo usarlo
- Alerta de **Crawler-Scanner**, ransomware.live o RansomWatch.
- Aviso del CSIRT o de medios de comunicación.

## Señales e indicadores
- Cuenta atrás de publicación, muestra de documentos, nombre de la institución en el listado.

## ⚙️ Automatizado por Shuffle
1. Capturar la publicación (texto, fecha, muestras) sin descargar los datos filtrados.
2. Crear incidente crítico y avisar a dirección.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Verifica si la publicación es real y si los datos son vuestros (pueden ser de un proveedor).
- [ ] Busca el incidente origen (ransomware, intrusión, fuga) con retrobúsqueda de 90 días en el motor de IoC.

### 2. Contención
- [ ] Activa el runbook **Ransomware** o **Intrusión avanzada** según el caso.
- [ ] Prepara comunicación con dirección, legal y comunicación.

### 3. Erradicación
- [ ] Cierra la vía de entrada identificada.

### 4. Recuperación
- [ ] Evalúa con legal las obligaciones de notificación a afectados y autoridades.

### 5. Cierre y lecciones aprendidas
- [ ] No negocies por iniciativa propia; cualquier contacto con el grupo lo decide la dirección con asesoría.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Capturas fechadas de la publicación, hashes de las muestras (sin conservar datos personales innecesarios).

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Herramientas recomendadas
[Crawler-Scanner](#/tools?q=Crawler-Scanner) · [Ransomware.live](#/tools?q=Ransomware.live) · [RansomWatch](#/tools?q=RansomWatch)
