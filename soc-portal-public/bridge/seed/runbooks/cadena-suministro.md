---
title: "Compromiso de la cadena de suministro"
description: "Software, actualización, librería o proveedor de confianza comprometido que introduce código malicioso"
level: Avanzado
category: Desarrollo
severity: Critical
mitre: T1195.002, T1195.001, T1199
owasp: A03:2025, A08:2025
---
# Runbook — Compromiso de la cadena de suministro

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Desarrollo  
> **MITRE ATT&CK:** [T1195.002](#/mitre?t=T1195.002) · [T1195.001](#/mitre?t=T1195.001) · [T1199](#/mitre?t=T1199) · **OWASP:** A03:2025, A08:2025

## Cuándo usarlo
- Aviso de un proveedor o del CSIRT sobre una versión comprometida.
- Conexiones de software legítimo a infraestructura maliciosa.

## Señales e indicadores
- Binarios firmados por el proveedor con comportamiento nuevo.
- Dependencias con nombres parecidos (typosquatting) en proyectos internos.

## ⚙️ Automatizado por Shuffle
1. Buscar la versión afectada en el inventario de software de Wazuh (syscollector).
2. Cargar los IoC del aviso en el motor de IoC y hacer retrobúsqueda de 90 días.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Inventario: dónde está instalada la versión afectada y con qué privilegios.

### 2. Contención
- [ ] Desconecta o bloquea el software afectado; corta los accesos del proveedor (VPN, cuentas).

### 3. Erradicación
- [ ] Actualiza a la versión limpia indicada por el proveedor; reconstruye sistemas si hubo ejecución de la carga maliciosa.

### 4. Recuperación
- [ ] Lista de proveedores críticos con contactos y obligaciones de notificación.

### 5. Cierre y lecciones aprendidas
- [ ] Revisa el control OWASP A03:2025 en los proyectos internos (SBOM, firmas, dependencias).
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Hashes de las versiones, logs de conexiones, comunicaciones del proveedor.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
data.win.eventdata.image:*<software>*
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[osquery](#/tools?q=osquery) · [YARA](#/tools?q=YARA) · [Velociraptor](#/tools?q=Velociraptor)
