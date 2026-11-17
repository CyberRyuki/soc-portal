#!/usr/bin/env bash
# =====================================================================
#  Instala Shuffle (SOAR) con Docker usando el repositorio OFICIAL,
#  fijado a SHUFFLE_REF, más los ajustes de docker-compose.override.yml.
#  Uso (desde la raíz del proyecto):  sudo ./shuffle/setup-shuffle.sh
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ../.env; set +a
DIR=shuffle-core

echo "== 1. Código oficial de Shuffle (${SHUFFLE_REF})"
if [ ! -d "$DIR/.git" ]; then
  git clone --depth 1 -b "${SHUFFLE_REF}" https://github.com/Shuffle/Shuffle.git "$DIR"
fi
cp docker-compose.override.yml "$DIR/"

echo "== 2. Configuración (.env oficial + valores del portal)"
cd "$DIR"
[ -f .env.original ] || cp .env .env.original
cp .env.original .env
setv() {  # setv CLAVE valor  -> reemplaza o añade en .env
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}
setv SHUFFLE_OPENSEARCH_PASSWORD "\"${SHUFFLE_OPENSEARCH_PASSWORD}\""
setv OPENSEARCH_INITIAL_ADMIN_PASSWORD "\"${SHUFFLE_OPENSEARCH_PASSWORD}\""
setv SHUFFLE_ENCRYPTION_MODIFIER "${SHUFFLE_ENCRYPTION_MODIFIER}"
setv SSO_REDIRECT_URL "http://${HOST_IP}:3001"
setv TZ "America/Santo_Domingo"
setv DB_LOCATION "./shuffle-database"
setv SHUFFLE_IMAGE_TAG "${SHUFFLE_IMAGE_TAG}"
setv SHUFFLE_OPENSEARCH_HEAP "${SHUFFLE_OPENSEARCH_HEAP}"
chmod 600 .env

echo "== 3. Base de datos y parámetros del sistema"
mkdir -p shuffle-database shuffle-apps shuffle-files
chown -R 1000:1000 shuffle-database
sysctl -qw vm.max_map_count=262144
grep -q '^vm.max_map_count' /etc/sysctl.conf || echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
swapoff -a || true   # recomendado por Shuffle para OpenSearch

echo "== 4. Imágenes (tag ${SHUFFLE_IMAGE_TAG})"
if ! docker pull -q "ghcr.io/shuffle/shuffle-backend:${SHUFFLE_IMAGE_TAG}" >/dev/null 2>&1; then
  echo "   El tag ${SHUFFLE_IMAGE_TAG} no existe en ghcr.io: se usa 'latest'"
  setv SHUFFLE_IMAGE_TAG latest; export SHUFFLE_IMAGE_TAG=latest
fi
if ! docker compose pull -q; then
  echo "   Alguna imagen no tiene el tag ${SHUFFLE_IMAGE_TAG}: se usa 'latest'"
  setv SHUFFLE_IMAGE_TAG latest; export SHUFFLE_IMAGE_TAG=latest; docker compose pull -q
fi

echo "== 5. Arranque"
docker compose up -d
echo -n "   Esperando al frontend"
for i in $(seq 1 60); do
  curl -sf -o /dev/null "http://127.0.0.1:3001/" && { echo " OK"; break; }
  echo -n "."; sleep 5
done
docker compose ps

cat <<EOF

Shuffle ${SHUFFLE_REF} en marcha
  UI: http://${HOST_IP}:3001  -> crea la cuenta de administrador en el primer acceso
Siguientes pasos: README §4.3 (API key, apps MISP/Wazuh, workflow y webhook)
Nota: Shuffle no es accesible por el puerto 5001 ni OpenSearch por 9200 (solo internos).
EOF
