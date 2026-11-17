# SOC Portal

Portal de un **Centro de Operaciones de Seguridad (SOC)** que integra Wazuh, MISP, Shuffle (SOAR), Wiki.js,
Sophos Central y Microsoft 365 Defender en una sola consola: amenazas, incidentes con aprobación humana, inteligencia
de IoC, vulnerabilidades (incl. informes Pentera), monitoreo y desfiguración de portales web, exposición a Internet
y Shadow IT, auditoría con cadena de hash y asistente de IA local.

> Los nombres, dominios (`acme.example`) e IP de este repositorio son **ficticios**. Ajusta `.env` a tu entorno
> (`cp .env.example .env`) y no subas nunca el `.env` ni la carpeta `data/`.

## Arquitectura — Wiki.js + Wazuh + MISP + Shuffle

Arquitectura con **dos servidores**: el portal SOC nuevo (todo en Docker) y tu
**servidor Wazuh existente**, que no se reinstala: solo se le añaden integraciones.

| Servidor | Componente | Función | Puerto |
|---|---|---|---|
| **Portal SOC** (`HOST_IP`) | Wiki.js 2.x | Portal: procedimientos, incidentes, panel de estado | 3000 |
| | MISP | Inteligencia de amenazas e IoC | 8080 / 8443 |
| | **Shuffle v2.3.0** | SOAR open source (AGPL-3.0): workflows | 3001 / 3443 |
| | soc-bridge | API de solo lectura que alimenta la Wiki | 127.0.0.1:8088 |
| **Wazuh** (`WAZUH_HOST`) | Manager, indexer, dashboard | SIEM/XDR (ya existente) | 443, 55000, 9200 |

```
        SERVIDOR WAZUH (existente)                      SERVIDOR PORTAL SOC (Docker)
 ┌──────────────────────────────┐   webhook :3001   ┌──────────────────────────┐
 │ Manager ── shuffle (nativa) ─┼──────────────────►│ Shuffle ──► MISP         │
 │        └─ custom-misp.py ────┼──── HTTPS :8443 ─►│ MISP                     │
 │             ▲ regla 100622   │                   │                          │
 │ API :55000 / Indexer :9200 ◄─┼─── solo lectura ──┤ soc-bridge ──► Wiki.js   │
 └──────────────────────────────┘                   │        (/soc/estado)     │
                                                    └──────────────────────────┘
```

> **Recomendación:** Shuffle necesita acceso a `docker.sock` (equivale a root en el host).
> Si es posible, instálalo en una **VM dedicada**: el proyecto funciona igual, solo cambia
> `SHUFFLE_URL` en `.env` y la IP en el webhook de Wazuh.

### Novedades v20 — alteraciones web y Exposición / Shadow IT

- **Portales**: además del texto, se detectan redirecciones, formularios de contraseña nuevos, cabeceras de seguridad
  retiradas, cambios de certificado, cambios de IP (fuera de rango = posible secuestro DNS) y scripts modificados.
- **Comparación visual**: nuevo contenedor `soc-screens` (Chromium aislado) que captura cada portal y lo compara con la
  versión aprobada (pestañas *Diferencias / Ahora / Aprobada* en el detalle). Requiere `SCREENS_TOKEN` en `.env`.
- **Exposición** (menú Inteligencia): descubrimiento pasivo y escaneo activo autorizado de los dominios y rangos de ACME,
  hallazgos, Shadow IT y servicios expuestos. Ver [docs/exposicion.md](docs/exposicion.md).

## 1. Requisitos
**Portal SOC:** Linux x86_64 (Ubuntu 22.04/24.04 o RHEL 9), Docker Engine 24+ con
`docker compose` v2.24+, `git`, **16 GB RAM / 4 vCPU / 100 GB**. Acceso a
`github.com`, `ghcr.io` y `docker.io`.
**Wazuh:** versión 4.x (paquetes nativos o Docker), acceso root, `curl`.

### Reglas de firewall
| Origen | Destino | Puerto | Motivo |
|---|---|---|---|
| Wazuh manager | Portal SOC | 3001/tcp | Webhook de alertas a Shuffle |
| Wazuh manager | Portal SOC | 8443/tcp | Consultas a MISP (`custom-misp.py`) |
| Portal SOC | Wazuh manager | 55000/tcp | API Wazuh (bridge y app Wazuh de Shuffle) |
| Portal SOC | Wazuh indexer | 9200/tcp | Consultas de alertas (bridge) |
| Analistas | Ambos | 443, 3000, 3001, 8443 | Interfaces web |

## 2. Estructura
```
.env.example                    variables (copiar a .env)
deploy.sh                       despliegue del portal SOC
wikijs/ misp/                   docker compose de cada servicio
shuffle/
  setup-shuffle.sh              instala Shuffle oficial (v2.3.0) + ajustes
  docker-compose.override.yml   cierra 5001/9200, fija imágenes, memoria OpenSearch
  workflows/README.md           cómo construir los workflows
bridge/                         soc-bridge (FastAPI)
wazuh/                          ► se COPIA al servidor Wazuh
  install-integrations.sh       integración nativa shuffle + custom-misp (nativo o Docker)
  integrations/custom-misp.py   enriquecimiento con MISP
  rules/misp_rules.xml          reglas 100620-100622
  crear_usuario_api_lectura.py  usuario API readonly para el bridge
wiki-content/                   páginas del portal (Markdown)
scripts/                        prerequisitos, check_wazuh, carga e inventario de la Wiki
alternativas/opensoar/          OpenSOAR (probado), por si se cambia de SOAR
docs/seguridad.md               endurecimiento y backups
```

## 3. Instalar Docker (si no está)
Ubuntu:
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
 | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
docker compose version     # debe ser v2.24 o superior
```
RHEL/Rocky/Alma: https://docs.docker.com/engine/install/rhel/

## 4. Despliegue del portal SOC
```bash
cp .env.example .env && nano .env      # HOST_IP, WAZUH_HOST, contraseñas
openssl rand -hex 32                   # -> SHUFFLE_ENCRYPTION_MODIFIER (no cambiarlo nunca después)
chmod +x deploy.sh scripts/*.sh shuffle/*.sh wazuh/*.sh
sudo ./deploy.sh todo                  # Wiki.js + MISP + Shuffle
```
MISP tarda 3–5 minutos en inicializar; Shuffle descarga sus imágenes y arranca OpenSearch (≈5 min).

### Portal web (v14) — http://HOST_IP:8088/portal/
Desde la v14 el portal son dos contenedores: **soc-web** (nginx + interfaz React, puerto 8088) y **soc-bridge**
(API, solo en la red interna). Detalles de desarrollo, pruebas, seguridad y variables: [`web/README.md`](web/README.md).

### Portales: cobertura WAF y desfiguración
- **Importar Excel** (Portales → Importar Excel): lee el «Dashboard Cobertura WAF» (hojas Pasan / NO pasan por WAF) o un CSV
  con columna Portal/Dominio/URL. Guarda plan, IP pública, backend, servidor, VS FortiWeb y estado WAF de cada portal.
- **Desfiguración**: compara título, texto visible y scripts externos con la **versión aprobada**. Detecta firmas de
  atacante («hacked by», «hackeado por»…), spam SEO de casinos, páginas vaciadas o reemplazadas, cambios de título y
  código/redirecciones hacia dominios nuevos. Los cambios por debajo del umbral (40 %) no alertan.
- Incidente **Crítico** si hay desfiguración y **Alto** si hay sospecha (por defecto solo en portales sin WAF o en bypass).
  «Aceptar como versión buena» da por legítimo un cambio.

### Auditoría y Pentera
- **Auditoría** (solo admin): quién cambió qué, cuándo y desde dónde, con cadena de hashes anti-manipulación y exportación CSV.
  Respalda `bridge/data/audit.db`.
- **Pentera**: Vulnerabilidades → Pentera → subir el PDF (o JSON/CSV) → revisar → importar. Originales en `bridge/data/reports/`.

### Sugerencias de incidente
Con `AUTO_INCIDENTS=false` (por defecto) ninguna detección crea incidentes por sí sola: portales, Sophos, Microsoft 365,
IoC y Shuffle dejan **sugerencias** en Incidentes, agrupadas si se repiten. Un analista las convierte en incidente o las descarta.

### Microsoft 365 (opcional)
Defender, inicios de sesión y riesgo, reglas de correo, auditoría, Secure Score y acciones sobre cuentas con aprobación
humana: [`docs/m365.md`](docs/m365.md).

### Sophos Central (opcional)
Alertas, equipos y respuesta (aislar, escanear, bloquear IoC) con aprobación humana: [`docs/sophos.md`](docs/sophos.md).

### 4.1 Wiki.js — http://HOST_IP:3000
1. Asistente inicial (administrador, URL del sitio).
2. *Administración → Locale*: instalar y activar **Español** (`es`).
3. *Administración → API Access*: **Enable API** → *New API Key*. Copiar a `WIKI_API_KEY`.

### 4.2 MISP — https://HOST_IP:8443
1. Entrar con `MISP_ADMIN_EMAIL` / `MISP_ADMIN_PASSWORD` y cambiar la contraseña.
2. *Administration → Add User*: `soc-service@…`, rol **Read Only**.
3. *Administration → List Auth Keys → Add* para ese usuario. Copiar a `MISP_API_KEY`.
4. *Sync Actions → Feeds*: habilitar fuentes aprobadas y *Fetch and store all feed data*.

### 4.3 Shuffle — http://HOST_IP:3001
1. Primer acceso: crear la cuenta **administrador**. Activar MFA en *Settings*.
2. *Settings → API key*: copiar a `SHUFFLE_API_KEY` (para el panel de la Wiki).
3. *Apps*: buscar y activar **MISP** y **Wazuh**.
   - MISP → *Authenticate*: URL `https://HOST_IP:8443`, API key de solo lectura, *ssl_verify* `false` (hasta tener certificados internos).
   - Wazuh → URL `https://WAZUH_HOST:55000`, usuario API de solo lectura.
4. Crear el workflow `SOC-Wazuh-Alert-Triage` (`shuffle/workflows/README.md`), pulsar
   *Start* en el nodo Webhook y copiar su **ID** (`webhook_…`).

### 4.4 Credenciales de solo lectura en el Wazuh remoto
**API (55000):**
```bash
python3 wazuh/crear_usuario_api_lectura.py --api https://WAZUH_HOST:55000 --admin wazuh-wui --usuario soc-bridge
```
**Indexer (9200):** Wazuh Dashboard → *☰ → Indexer management → Security*:
1. *Roles → Create role* `soc_bridge_read`: index pattern `wazuh-alerts-*`, permisos `read`, `search`; cluster permission `cluster_composite_ops_ro`.
2. *Internal users → Create* `soc-bridge`.
3. *Roles → soc_bridge_read → Mapped users → Map* `soc-bridge`.

Pon ambos usuarios en `.env` y comprueba: `sudo ./deploy.sh check-wazuh`

## 5. Integraciones en el servidor Wazuh
```bash
scp -r wazuh/ usuario@WAZUH_HOST:/tmp/soc-wazuh
ssh usuario@WAZUH_HOST
cd /tmp/soc-wazuh
# 1) Prueba sin cambios (conectividad y clave MISP)
sudo ./install-integrations.sh --soc-host HOST_IP --shuffle-hook webhook_XXXX --misp-key CLAVE_MISP --dry-run
# 2) Instalación
sudo ./install-integrations.sh --soc-host HOST_IP --shuffle-hook webhook_XXXX --misp-key CLAVE_MISP
```
- **Wazuh nativo:** añade la integración nativa `shuffle` (alertas nivel ≥ 10) y `custom-misp.py` a
  `/var/ossec/etc/ossec.conf` (copia `ossec.conf.bak-FECHA`), valida y reinicia; si falla, restaura.
- **Wazuh en Docker:** copia los archivos al contenedor y muestra el bloque XML para tu
  `wazuh_manager.conf`. Para que sobrevivan a una recreación, móntalos como volumen:
  ```yaml
      - ./soc/custom-misp.py:/var/ossec/integrations/custom-misp.py
      - ./soc/misp_rules.xml:/var/ossec/etc/rules/misp_rules.xml
  ```
- **Clúster:** ejecútalo en cada nodo que procese alertas.
- Si Shuffle está en otra VM, usa su IP en `--soc-host` o `--shuffle-port`.

## 6. Portal SOC en la Wiki
```bash
pip3 install requests
set -a; source .env; set +a
export WIKI_URL=http://$HOST_IP:3000
python3 scripts/sync_wiki.py --prune-legacy --theme           # crea /soc, runbooks, plantillas…
python3 scripts/inventario_wiki.py     # inventario_wiki.csv + página /soc/inventario
sudo ./deploy.sh bridge                # panel /soc/estado cada 5 min
```
Añade `/soc` en *Administración → Navegación*.

## 7. Ver todo lo que hay en la Wiki
- *Administración → Páginas*: listado completo; *Browse* muestra el árbol de carpetas.
- `scripts/inventario_wiki.py`: exporta todas las páginas a CSV y publica `/soc/inventario`.
- `/t`: todas las etiquetas y sus páginas.

## 8. Verificación
| Prueba | Dónde | Resultado esperado |
|---|---|---|
| Contenedores | Portal: `cd shuffle/shuffle-core && docker compose ps` | backend, frontend, orborus, opensearch *Up* |
| Acceso a Wazuh | Portal: `sudo ./deploy.sh check-wazuh` | Token OK + agentes + conteo de alertas |
| Webhook | `curl` de `shuffle/workflows/README.md` | Ejecución en *Executions* |
| Wazuh → Shuffle | Fallos SSH repetidos en un agente (regla 5712, nivel 10) | Ejecución con la alerta real |
| Wazuh → MISP | Atributo `ip-src` de prueba en MISP (`to_ids`) + alerta con esa IP | Regla **100622** |
| Panel | Wiki `/soc/estado` | Servicios 🟢 y workflows listados |

## 9. Operación de Shuffle
```bash
cd shuffle/shuffle-core
docker compose logs -f backend orborus     # registros
docker compose restart                     # reinicio
```
**Actualizar:** exportar workflows → cambiar `SHUFFLE_REF`/`SHUFFLE_IMAGE_TAG` en `.env` →
borrar `shuffle/shuffle-core` (los datos siguen en `shuffle-core/shuffle-database`, ¡haz copia antes!)
→ `sudo ./deploy.sh shuffle`. Probar primero en laboratorio.

## 10. Problemas frecuentes
- **OpenSearch se reinicia:** poca RAM (baja `SHUFFLE_OPENSEARCH_HEAP`), permisos de `shuffle-database` (1000:1000) o `vm.max_map_count`.
- **Workflows no se ejecutan:** `docker compose logs orborus`; Orborus necesita `docker.sock` y descargar imágenes de `ghcr.io`.
- **Apps sin red hacia MISP/Wazuh:** las apps corren en contenedores propios; usa IPs/DNS reales (`HOST_IP`, `WAZUH_HOST`), no nombres de contenedor.
- **Alertas no llegan:** firewall 3001 desde Wazuh; webhook sin *Start*; `grep integratord /var/ossec/logs/ossec.log`.
- **Indexer 403:** el rol `soc_bridge_read` no está mapeado al usuario.

Seguridad y backups: `docs/seguridad.md`.
