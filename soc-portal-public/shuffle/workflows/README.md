# Workflows de Shuffle

Se construyen en la interfaz (http://HOST_IP:3001 → *Workflows*) para que queden
ligados a tu instancia y a tus credenciales. Después expórtalos (⋮ → *Export*) y
guarda el JSON en esta carpeta como respaldo versionado.

## 1. SOC-Wazuh-Alert-Triage (solo lectura)

| # | Nodo | Configuración |
|---|---|---|
| 1 | **Webhook** (trigger) | Nombre `wazuh`. Pulsa *Start* y copia el ID `webhook_…` → parámetro `--shuffle-hook` de `wazuh/install-integrations.sh`. |
| 2 | **Shuffle Tools → Repeat back to me** | `$exec` — verifica que llega la alerta (prueba). |
| 3 | **Shuffle Tools → Parse IOC** | Input: `$exec.all_fields.full_log` y `$exec.all_fields.data` |
| 4 | **MISP → Search attributes** (app MISP) | Auth: URL `https://HOST_IP:8443`, API key de solo lectura. Value: `$parse_ioc.#.data` |
| 5 | **Condición** | `$misp_search.response.Attribute` *larger than* 0 |
| 6 | **Email / Teams / Telegram** | Mensaje con: `$exec.rule.description`, `$exec.agent.name`, IoC, evento MISP |

Campos útiles de la alerta Wazuh en Shuffle: `$exec.severity`, `$exec.title`,
`$exec.text`, `$exec.all_fields.rule.id`, `$exec.all_fields.agent.name`,
`$exec.all_fields.data.srcip`.

## 2. SOC-Contencion-IP (requiere aprobación)

| # | Nodo | Configuración |
|---|---|---|
| 1 | **User input** (trigger) | Pide IP + justificación; enviar a responsable de seguridad |
| 2 | **Wazuh → Run command / Active response** | `firewall-drop` sobre el agente indicado, con timeout |
| 3 | **HTTP** | Registrar la acción (o comentar en el incidente) |

> No conectar este workflow al webhook automático durante el piloto.

## Probar

```bash
# Envía una alerta sintética directamente al webhook de Shuffle
curl -s -X POST "http://HOST_IP:3001/api/v1/hooks/WEBHOOK_ID" \
  -H 'Content-Type: application/json' \
  -d '{"rule":{"id":"5712","level":10,"description":"Prueba SSH brute force"},
       "agent":{"id":"001","name":"srv-prueba"},"data":{"srcip":"185.220.101.1"}}'
```
