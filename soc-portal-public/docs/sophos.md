# Integración con Sophos Central

El portal se conecta a la **API pública de Sophos Central**. Con ella:

| Función | Dónde |
|---|---|
| **Recibir** alertas (cada `SOPHOS_POLL_MIN` min) y cruzarlas con el motor de IoC | Sophos → Alertas |
| Incidente automático para alertas ≥ `SOPHOS_AUTO_INCIDENT` (sin duplicados) | Incidentes |
| Inventario y salud de equipos (salud, aislamiento, antimanipulación, último contacto) | Sophos → Equipos |
| **Aislar / quitar aislamiento**, **escanear**, acciones sobre la alerta (revisada, limpiar, autorizar PUA…) | Alertas y Equipos (menú ⋯) |
| **Enviar IoC a Sophos**: SHA-256 → *Elementos bloqueados*; dominio/URL/IP → *Sitios web locales* | Sophos → Bloqueos, y «Bloquear en Sophos» en el análisis de un IoC |
| Cola de aprobación e historial de todas las acciones | Sophos → Acciones |

Sophos Central **no envía webhooks**: «recibir» significa que el portal consulta su API periódicamente.

## 1. Crear la credencial de API

1. Sophos Central → **Configuración global → Credenciales de API → Añadir credencial**.
2. Rol: **Service Principal Super Admin** (necesario para aislar y bloquear). Si solo se quiere ver, **Service Principal ReadOnly**
   y pon `SOPHOS_READ_ONLY=true`: el portal muestra alertas, equipos y bloqueos, pero no ofrece acciones.
3. Copia **Client ID** y **Client Secret** (el secreto no se vuelve a mostrar).
4. En el `.env`:
   ```bash
   SOPHOS_CLIENT_ID=...
   SOPHOS_CLIENT_SECRET=...
   SOPHOS_AUTO_INCIDENT=high      # high | medium | low | vacío
   SOPHOS_FOUR_EYES=false         # true = la contención la aprueba otra persona
   SOPHOS_WEB_TAG=SOC-ACME-BLOQUEO
   ```
5. `docker compose --env-file .env -f bridge/docker-compose.yml up -d --force-recreate soc-bridge`

El servidor necesita salida HTTPS a `id.sophos.com`, `api.central.sophos.com` y al host de su región
(`api-<región>.central.sophos.com`). Con credencial de **partner u organización** añade `SOPHOS_TENANT_ID`.

## 2. Bloqueo de dominios/URL/IP (una sola vez en Sophos)

Sophos no tiene «lista negra de IP/dominios» directa en endpoint: el portal añade cada valor como **sitio web
local** con la etiqueta `SOPHOS_WEB_TAG`. Para que se bloquee:

1. **Endpoint Protection → Políticas → Control web** (la política que aplique a todos los equipos).
2. En **Etiquetas de sitios web**, pon la etiqueta `SOC-ACME-BLOQUEO` en **Bloquear**.
3. Guarda. Desde entonces todo lo que el portal envíe con esa etiqueta queda bloqueado.

Los SHA-256 no necesitan política: *Elementos bloqueados* se aplica a todo el tenant.

## 3. Regla del piloto: aprobación humana

- Desde el **portal**, la persona que pulsa **Confirmar** es quien aprueba; el **motivo** es obligatorio.
- Con `SOPHOS_FOUR_EYES=true`, la **contención** (aislar, quitar aislamiento, bloquear) queda pendiente hasta que
  **otra** persona la aprueba en *Sophos → Acciones*.
- Desde **Shuffle**, toda acción queda **pendiente**; Shuffle nunca puede aprobar (la aprobación exige sesión en el portal).
- Cada acción queda en la **auditoría de accesos** (evento «Acción en Sophos Central») y, si se indica un incidente,
  como nota en su cronología.

## 4. Pedir acciones desde Shuffle

```http
POST http://HOST_IP:8088/portal/api/sophos/actions
X-API-Key: <BRIDGE_TOKEN>
Content-Type: application/json

{"kind": "isolate", "target": {"ids": ["<id del equipo en Sophos>"]},
 "reason": "Regla 100622: IoC de MISP en el equipo", "incident": "INC-2026-012"}
```

`kind`: `isolate`, `unisolate`, `scan`, `alert_action` (`{"alert_id", "action"}`), `block_hash` y `block_web`
(`{"values": [...]}`, máx. 100). La respuesta trae `"status": "pending"`; un analista la aprueba en el portal.

## 5. Problemas frecuentes

| Mensaje | Causa |
|---|---|
| «Sophos rechazó el client ID / secret» | Credencial mal copiada o borrada en Sophos Central |
| «la credencial de API no tiene permiso» (403) | Rol Read-Only: crea una con Super Admin para acciones |
| «no conecta con Sophos Central» | El servidor no tiene salida a `*.sophos.com` (firewall/proxy) |
| «La credencial es de partner…» | Falta `SOPHOS_TENANT_ID` |
| El sitio se añade pero no se bloquea | Falta la etiqueta en la política de Control web (§2) |
