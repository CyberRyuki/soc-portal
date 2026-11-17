---
title: "Compromiso de nube y Microsoft 365"
description: "Abuso de cuentas cloud, aplicaciones OAuth maliciosas, robo de tokens o cambios de configuración del tenant"
level: Avanzado
category: Nube
severity: Critical
mitre: T1078.004, T1528, T1098.003, T1550.001, T1114.002
owasp: A07:2025, A01:2025
---
# Runbook — Compromiso de nube y Microsoft 365

> **Nivel:** Avanzado · **Severidad típica:** Crítica · **Categoría:** Nube  
> **MITRE ATT&CK:** [T1078.004](#/mitre?t=T1078.004) · [T1528](#/mitre?t=T1528) · [T1098.003](#/mitre?t=T1098.003) · [T1550.001](#/mitre?t=T1550.001) · [T1114.002](#/mitre?t=T1114.002) · **OWASP:** A07:2025, A01:2025

## Cuándo usarlo
- Consentimiento a una aplicación OAuth con permisos de correo/archivos.
- Inicios de sesión imposibles (dos países en minutos) o con tokens robados (sin MFA).

## Señales e indicadores
- Nuevos administradores globales, credenciales añadidas a aplicaciones, reglas de acceso condicional cambiadas.

## ⚙️ Automatizado por Shuffle
1. Listar consentimientos OAuth y roles asignados en las últimas 72 h.
2. Revocar sesiones de la cuenta con aprobación.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Determina si es una cuenta o el tenant completo (roles de administración afectados).

### 2. Contención
- [ ] Revoca tokens y sesiones, elimina aplicaciones OAuth maliciosas, desactiva cuentas.
- [ ] Restringe el consentimiento de usuarios a aplicaciones.

### 3. Erradicación
- [ ] Revisa reglas de buzón, reenvíos, delegaciones y credenciales de service principals.

### 4. Recuperación
- [ ] Acceso condicional con MFA resistente a phishing y bloqueo de autenticación heredada.

### 5. Cierre y lecciones aprendidas
- [ ] Exporta el registro unificado de auditoría del periodo antes de que caduque.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- Unified Audit Log, Sign-in logs, lista de aplicaciones y consentimientos.

## Escalamiento
Activa el equipo de respuesta completo (responsable de seguridad, infraestructura, dirección y legal). Valora avisar al CSIRT nacional y conservar evidencias con cadena de custodia.

## Consultas útiles en Wazuh (Discover)
```
data.office365.Operation:"Consent to application."
data.office365.Operation:"Add member to role."
```
Sustituye los valores entre `< >`. Los nombres de campo pueden variar según el decodificador.

## Herramientas recomendadas
[jq](#/tools?q=jq) · [Hayabusa](#/tools?q=Hayabusa)
