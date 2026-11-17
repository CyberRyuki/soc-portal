---
title: "Secretos expuestos en repositorios de código"
description: "Contraseñas, tokens o claves de API publicados en GitHub/GitLab u otros repositorios"
level: Intermedio
category: Desarrollo
severity: High
mitre: T1552.001, T1078.004
owasp: A02:2025, A03:2025
---
# Runbook — Secretos expuestos en repositorios de código

> **Nivel:** Intermedio · **Severidad típica:** Alta · **Categoría:** Desarrollo  
> **MITRE ATT&CK:** [T1552.001](#/mitre?t=T1552.001) · [T1078.004](#/mitre?t=T1078.004) · **OWASP:** A02:2025, A03:2025

## Cuándo usarlo
- Aviso de GitHub secret scanning, Gitleaks o TruffleHog.
- Un tercero informa de una clave institucional publicada.

## Señales e indicadores
- Archivos `.env`, `config.json`, claves privadas en el historial de commits.

## ⚙️ Automatizado por Shuffle
1. Identificar el tipo de secreto y el sistema al que da acceso.
2. Comprobar en logs si se usó desde IPs ajenas.

> La contención siempre requiere aprobación humana durante el piloto.

## 👤 Pasos del analista
### 1. Triaje (primeros 15 minutos)
- [ ] Asume que el secreto está comprometido aunque se borre el commit (queda en el historial y en copias).

### 2. Contención
- [ ] Revoca y rota el secreto inmediatamente.
- [ ] Haz el repositorio privado si no debía ser público.

### 3. Erradicación
- [ ] Limpia el historial (git filter-repo) y añade Gitleaks como pre-commit/CI.

### 4. Recuperación
- [ ] Usa un gestor de secretos (Vault, variables de CI).

### 5. Cierre y lecciones aprendidas
- [ ] Revisa el uso del secreto durante el tiempo expuesto.
- [ ] Completa en el incidente la causa raíz y las lecciones aprendidas.

## Evidencias a conservar
- URL del commit, fecha de exposición, logs de uso del secreto.

## Escalamiento
Analista nivel 2 con apoyo de infraestructura. Avisa al responsable de seguridad al confirmar el incidente.

## Herramientas recomendadas
[Gitleaks](#/tools?q=Gitleaks) · [TruffleHog](#/tools?q=TruffleHog)
