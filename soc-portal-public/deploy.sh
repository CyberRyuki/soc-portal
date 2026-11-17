#!/usr/bin/env bash
# Despliegue del servidor PORTAL SOC. Wazuh está en otro servidor (ver wazuh/).
# Uso: sudo ./deploy.sh [todo|wiki|misp|shuffle|bridge|check-wazuh]
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { echo "Falta .env (copia .env.example y edítalo)"; exit 1; }
grep -q 'CAMBIAR_' .env && echo "AVISO: .env aún contiene valores CAMBIAR_*"

up() { docker compose --env-file .env -f "$1/docker-compose.yml" up -d ${2:-}; }

misp_certs() {  # certificado autofirmado para misp-nginx (lo lee el usuario uid 101)
  set -a; source .env; set +a
  if [ ! -s misp/ssl/cert.pem ]; then
    mkdir -p misp/ssl
    openssl req -x509 -newkey rsa:4096 -nodes -days 825 -subj "/CN=${HOST_IP}" \
      -addext "subjectAltName=IP:${HOST_IP},DNS:localhost" \
      -keyout misp/ssl/key.pem -out misp/ssl/cert.pem 2>/dev/null
  fi
  chgrp 101 misp/ssl/*.pem && chmod 640 misp/ssl/*.pem
}

case "${1:-todo}" in
  wiki)    up wikijs ;;
  misp)    misp_certs; up misp ;;
  shuffle) bash shuffle/setup-shuffle.sh ;;
  bridge)  up bridge --build ;;
  check-wazuh) bash scripts/check_wazuh.sh; exit 0 ;;
  todo)
    bash scripts/prerequisitos.sh
    up wikijs; misp_certs; up misp
    bash shuffle/setup-shuffle.sh
    echo
    echo "Siguiente: README §4 (claves API) y §5 (integración en el servidor Wazuh)."
    ;;
  *) echo "Opción no válida"; exit 1 ;;
esac
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
