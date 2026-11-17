#!/usr/bin/env bash
# Ejecutar en el servidor PORTAL SOC: comprueba el acceso al servidor Wazuh remoto
# con las credenciales de .env (API 55000 e indexer 9200).
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
K=""; [ "${WAZUH_VERIFY_TLS:-false}" = "true" ] || K="-k"

echo "== API Wazuh  ${WAZUH_API_URL}  (opcional: si falla, los agentes se leen del indexer)"
TOKEN=$(curl -s $K -m 60 -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" -X POST \
        "${WAZUH_API_URL}/security/user/authenticate?raw=true")
if [ -n "$TOKEN" ] && [ "${TOKEN:0:1}" != "{" ]; then
  echo "   Autenticación OK"
  curl -s $K -m 60 -H "Authorization: Bearer $TOKEN" "${WAZUH_API_URL}/agents/summary/status?pretty=true" | head -20
else
  echo "   FALLO: $TOKEN  (¿puerto 55000 abierto hacia ${HOST_IP}? ¿usuario/contraseña?)"
fi

echo "== Agentes (indexer, wazuh-monitoring-*)"
curl -s $K -m 60 -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}" -H 'Content-Type: application/json' \
  "${WAZUH_INDEXER_URL}/wazuh-monitoring-*/_search?size=0" \
  -d '{"aggs":{"st":{"terms":{"field":"status"}}},"query":{"range":{"timestamp":{"gte":"now-20m"}}}}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('   ', {b['key']:b['doc_count'] for b in d['aggregations']['st']['buckets']} if 'aggregations' in d else d)" \
  || echo "   FALLO (¿permiso sobre wazuh-monitoring-*?)"

echo "== Indexer    ${WAZUH_INDEXER_URL}"
curl -s $K -m 60 -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}" \
  "${WAZUH_INDEXER_URL}/wazuh-alerts-*/_count?pretty" \
  || echo "   FALLO (¿puerto 9200 abierto? ¿permisos sobre wazuh-alerts-*?)"
