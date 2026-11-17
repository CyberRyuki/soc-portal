#!/usr/bin/env bash
# Instala la app MISP en Shuffle (viene en python-apps/unsupported) con las correcciones
# necesarias para Shuffle 2.3: SDK nuevo (shuffle_sdk) y typo en api.yaml.
# Uso: sudo ./shuffle/install-misp-app.sh   (desde la raíz del proyecto)
set -euo pipefail
cd "$(dirname "$0")/shuffle-core"
[ -d /tmp/python-apps ] || git clone --depth 1 https://github.com/Shuffle/python-apps.git /tmp/python-apps
rm -rf shuffle-apps/misp && cp -r /tmp/python-apps/unsupported/misp shuffle-apps/
A=shuffle-apps/misp/1.0.0
sed -i 's/from walkoff_app_sdk.app_base import AppBase/from shuffle_sdk import AppBase/' $A/src/app.py
sed -i 's/multiline true:/multiline: true/' $A/api.yaml
printf 'shuffle-sdk==0.0.40\n' > $A/requirements.txt
chown -R 1000:1000 shuffle-apps
docker build --no-cache -t frikky/shuffle:misp_1.0.0 $A
KEY=$(grep ^SHUFFLE_API_KEY ../../.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:3001/api/v1/apps/run_hotload; echo
docker service update -d --force misp_1-0-0 2>/dev/null || true
echo "App MISP lista. Autenticación en Shuffle: url=https://HOST_IP:8443 (sin / final), apikey=MISP_API_KEY"
