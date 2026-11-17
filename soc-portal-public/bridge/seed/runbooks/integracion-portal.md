---
title: "Integración con el portal (para Shuffle)"
description: Cómo crea Shuffle los incidentes en el portal SOC
level: Referencia
category: Plataforma
severity: Low
mitre: 
owasp: 
---
# Integración de Shuffle con el portal

Todos los workflows crean el incidente con **una sola petición HTTP**. Usa la app **Http** de Shuffle:

| Campo | Valor |
|---|---|
| Acción | **POST** |
| URL | `http://10.10.10.101:8088/portal/api/incidents` |
| Headers | `X-API-Key: <BRIDGE_TOKEN del .env>` · `Content-Type: application/json` |
| Body | Ver el ejemplo de abajo |

```json
{
  "title": "Fuerza bruta SSH desde $exec.all_fields.data.srcip contra $exec.all_fields.agent.name",
  "severity": "High",
  "runbook": "fuerza-bruta",
  "detected_by": "Wazuh regla $exec.all_fields.rule.id · Shuffle",
  "assets": "$exec.all_fields.agent.name",
  "iocs": "$exec.all_fields.data.srcip",
  "summary": "$exec.all_fields.rule.description\n\n$exec.all_fields.full_log"
}
```

La respuesta incluye el código del incidente (`{"code": "INC-2026-007"}`). Úsalo en el aviso: `http://10.10.10.101:8088/portal/#/incidents/$http.body.code`.

**Valores de `runbook`:** `misp-ioc-match`, `critical-alert`, `phishing`, `fuerza-bruta`, `cuenta-comprometida`, `malware-endpoint`, `agente-desconectado`, `vulnerabilidad-critica`, `escaneo-red`.

**Severidades:** `Critical`, `High`, `Medium`, `Low`.

> Los incidentes creados por Shuffle aparecen firmados como **shuffle** en la cronología.
