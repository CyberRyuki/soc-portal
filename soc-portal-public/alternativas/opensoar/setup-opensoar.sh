#!/usr/bin/env bash
# =====================================================================
#  Instala OpenSOAR en el servidor del portal SOC (Docker Compose).
#  1. Descarga opensoar-core fijado a OPENSOAR_REF y construye las imágenes
#  2. Levanta base de datos, API, worker y UI
#  3. Crea el administrador, el usuario de solo lectura para soc-bridge
#     y la API key que usará Wazuh para enviar alertas
#  Uso: sudo ./opensoar/setup-opensoar.sh   (desde la raíz del proyecto)
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ../.env; set +a
DC="docker compose --env-file ../.env"
API="http://127.0.0.1:8000/api/v1"

echo "== 1. Código fuente (ref ${OPENSOAR_REF})"
if [ ! -d opensoar-core/.git ]; then
  git clone https://github.com/opensoar-hq/opensoar-core.git opensoar-core
fi
git -C opensoar-core fetch -q origin
git -C opensoar-core checkout -q "${OPENSOAR_REF}"

echo "== 2. Construyendo y levantando (la primera vez tarda varios minutos)"
$DC up -d --build

echo -n "   Esperando a la API"
for i in $(seq 1 60); do
  curl -sf "${API}/health" >/dev/null && { echo " OK"; break; }
  echo -n "."; sleep 5
  [ "$i" = 60 ] && { echo; echo "La API no responde: $DC logs migrate api"; exit 1; }
done

echo "== 3. Administrador"
$DC exec -T api opensoar-bootstrap-admin \
  --username "${OPENSOAR_ADMIN_USER}" --password "${OPENSOAR_ADMIN_PASSWORD}" \
  --display-name "Administrador SOC" || echo "   (ya existía)"

TOKEN=$(curl -sf -X POST "${API}/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${OPENSOAR_ADMIN_USER}\",\"password\":\"${OPENSOAR_ADMIN_PASSWORD}\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

echo "== 4. Usuario de solo lectura para soc-bridge (rol viewer)"
curl -s -o /dev/null -w '   HTTP %{http_code} (201 creado / 409 ya existe)\n' -X POST "${API}/auth/analysts" \
  -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"username\":\"${OPENSOAR_BRIDGE_USER}\",\"display_name\":\"soc-bridge\",\"password\":\"${OPENSOAR_BRIDGE_PASSWORD}\",\"role\":\"viewer\"}"

echo "== 5. API key para Wazuh"
KEY=$(curl -sf -X POST "${API}/api-keys" -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' -d '{"name":"wazuh-manager"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["key"])')

echo "== 6. Playbooks detectados"
curl -s "${API}/playbooks" -H "Authorization: Bearer ${TOKEN}" \
  | python3 -c 'import sys,json;[print("   -",p["name"],"| trigger:",p.get("trigger_type"),"| activo:",p.get("enabled")) for p in json.load(sys.stdin)]'

cat <<EOF

OpenSOAR listo
  UI:       http://${HOST_IP}:3002   (usuario ${OPENSOAR_ADMIN_USER})
  API/docs: http://${HOST_IP}:8000/docs

  API key para Wazuh (se muestra UNA sola vez, guárdala en un gestor de secretos):
    ${KEY}

  Úsala en el servidor Wazuh:
    sudo ./install-integrations.sh --soc-host ${HOST_IP} --opensoar-key '${KEY}' --misp-key '<MISP_API_KEY>'

  Nota: al existir una API key, el webhook deja de aceptar peticiones sin X-API-Key.
EOF
