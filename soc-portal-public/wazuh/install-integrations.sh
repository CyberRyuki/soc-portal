#!/usr/bin/env bash
# =====================================================================
#  Ejecutar EN EL SERVIDOR WAZUH (como root). Copia esta carpeta wazuh/ allí.
#
#  sudo ./install-integrations.sh \
#       --soc-host 10.0.0.10 \
#       --shuffle-hook webhook_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
#       --misp-key  CLAVE_MISP_SOLO_LECTURA \
#       [--level 10] [--misp-port 8443] [--shuffle-port 3001] [--dry-run]
#
#  - Wazuh nativo (paquete):  instala todo y edita /var/ossec/etc/ossec.conf
#    (con copia de seguridad y validación; si falla, restaura).
#  - Wazuh en Docker:         copia script y reglas al contenedor y muestra el
#    bloque XML que debes pegar en tu wazuh_manager.conf montado.
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"

LEVEL=10; MISP_PORT=8443; SH_PORT=3001; DRY=0
SOC=""; HOOK=""; KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --soc-host) SOC="$2"; shift 2;;
    --shuffle-hook) HOOK="$2"; shift 2;;
    --misp-key) KEY="$2"; shift 2;;
    --level) LEVEL="$2"; shift 2;;
    --misp-port) MISP_PORT="$2"; shift 2;;
    --shuffle-port) SH_PORT="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) echo "Parámetro desconocido: $1"; exit 1;;
  esac
done
[ -n "$SOC" ] && [ -n "$HOOK" ] && [ -n "$KEY" ] || { sed -n '5,10p' "$0"; exit 1; }

MISP_URL="https://${SOC}:${MISP_PORT}"
HOOK_URL="http://${SOC}:${SH_PORT}/api/v1/hooks/${HOOK}"

BLOCK=$(cat <<EOF
  <!-- Portal SOC: alertas a Shuffle (integración nativa de Wazuh) -->
  <integration>
    <name>shuffle</name>
    <hook_url>${HOOK_URL}</hook_url>
    <level>${LEVEL}</level>
    <alert_format>json</alert_format>
  </integration>

  <!-- Portal SOC: enriquecimiento con MISP -->
  <integration>
    <name>custom-misp.py</name>
    <hook_url>${MISP_URL}</hook_url>
    <api_key>${KEY}</api_key>
    <group>syscheck,sysmon_event1,sysmon_event3,sysmon_event_22,web,authentication_failed,firewall</group>
    <alert_format>json</alert_format>
  </integration>
EOF
)

echo "== 1. Conectividad desde Wazuh hacia el portal SOC"
c_misp=$(curl -sk -o /dev/null -m 8 -w '%{http_code}' "${MISP_URL}/users/login" || true)
c_os=$(curl -s  -o /dev/null -m 8 -w '%{http_code}' "http://${SOC}:${SH_PORT}/" || true)
echo "   MISP    ${MISP_URL}            -> HTTP ${c_misp:-000}"
echo "   Shuffle http://${SOC}:${SH_PORT}             -> HTTP ${c_os:-000}"
c_key=$(curl -sk -o /dev/null -m 8 -w '%{http_code}' -H "Authorization: ${KEY}" \
        -H 'Accept: application/json' "${MISP_URL}/servers/getVersion" || true)
echo "   Clave MISP                         -> HTTP ${c_key:-000} (200 = válida)"
if [ "${c_misp:-000}" = "000" ] || [ "${c_os:-000}" = "000" ]; then
  echo "   AVISO: sin conexión. Abre en el firewall Wazuh -> ${SOC}:${MISP_PORT},${SH_PORT}/tcp"
fi
[ "$DRY" = 1 ] && { echo; echo "$BLOCK"; echo "(dry-run: no se cambió nada)"; exit 0; }

# ---------------------------------------------------------------- Docker
if [ ! -x /var/ossec/bin/wazuh-control ]; then
  C=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -m1 'wazuh.manager' || true)
  [ -n "$C" ] || { echo "No encuentro Wazuh nativo ni contenedor wazuh.manager"; exit 1; }
  echo "== Modo Docker (contenedor $C)"
  for f in custom-misp.py; do
    docker cp "integrations/$f" "$C:/var/ossec/integrations/$f"
    docker exec "$C" chown root:wazuh "/var/ossec/integrations/$f"
    docker exec "$C" chmod 750 "/var/ossec/integrations/$f"
  done
  docker cp rules/misp_rules.xml "$C":/var/ossec/etc/rules/misp_rules.xml
  docker exec "$C" chown wazuh:wazuh /var/ossec/etc/rules/misp_rules.xml
  docker exec "$C" chmod 660 /var/ossec/etc/rules/misp_rules.xml
  echo
  echo "Pega este bloque dentro de <ossec_config> en tu wazuh_manager.conf montado"
  echo "(ej. single-node/config/wazuh_cluster/wazuh_manager.conf), y luego:"
  echo "   docker compose up -d --force-recreate wazuh.manager"
  echo "   (los scripts y la regla se pierden al recrear: móntalos como volumen, ver README §5)"
  echo; echo "$BLOCK"
  exit 0
fi

# ---------------------------------------------------------------- Nativo
OSSEC=/var/ossec/etc/ossec.conf
BK="${OSSEC}.bak-$(date +%Y%m%d-%H%M%S)"
echo "== 2. Instalando script y reglas (Wazuh nativo)"
install -o root  -g wazuh -m 750 integrations/custom-misp.py /var/ossec/integrations/custom-misp.py
install -o wazuh -g wazuh -m 660 rules/misp_rules.xml        /var/ossec/etc/rules/misp_rules.xml

echo "== 3. Editando ${OSSEC} (copia: ${BK})"
cp -p "$OSSEC" "$BK"
if grep -q 'custom-misp.py\|/api/v1/hooks/' "$OSSEC"; then
  echo "   Ya existen integraciones del portal SOC en ossec.conf: no se modifica"
  echo "   (para cambiarlas, edita ${OSSEC} o restaura un .bak y vuelve a ejecutar)"
else
  BLOCK="$BLOCK" /var/ossec/framework/python/bin/python3 - "$OSSEC" <<'PY'
import os, sys
p = sys.argv[1]
s = open(p).read()
i = s.rfind("</ossec_config>")
if i < 0:
    sys.exit("No se encontró </ossec_config>")
open(p, "w").write(s[:i] + os.environ["BLOCK"] + "\n" + s[i:])
PY
  echo "   Bloque añadido"
fi

echo "== 4. Validando configuración"
if ! /var/ossec/bin/wazuh-analysisd -t; then
  echo "   ERROR de validación: restaurando ${BK}"; cp -p "$BK" "$OSSEC"; exit 1
fi

echo "== 5. Reiniciando wazuh-manager"
systemctl restart wazuh-manager
sleep 8
if ! systemctl is-active --quiet wazuh-manager; then
  echo "   wazuh-manager no arrancó: restaurando ${BK}"
  cp -p "$BK" "$OSSEC"; systemctl restart wazuh-manager; exit 1
fi
echo "   wazuh-manager activo"
echo
echo "Listo. Revisa: tail -f /var/ossec/logs/integrations.log /var/ossec/logs/ossec.log"
