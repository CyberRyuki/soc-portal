#!/usr/bin/env bash
# Prepara el host (Ubuntu/Debian/RHEL) para el stack. Ejecutar con sudo.
set -euo pipefail


command -v docker >/dev/null || { echo "Instala Docker Engine + plugin compose: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null

docker network inspect soc-net >/dev/null 2>&1 || docker network create soc-net
echo "RAM total: $(free -g | awk '/Mem/{print $2}') GB (recomendado >= 16 GB: Shuffle+OpenSearch, MISP, Wiki.js)"
echo "OK: prerequisitos listos"
