#!/bin/bash
# =====================================================================
#  Descarga las listas de IoC del portal SOC y las instala como listas
#  CDB de Wazuh (detección en tiempo real con wazuh/rules/ioc_portal_rules.xml).
#  Ejecutar EN EL SERVIDOR DE WAZUH, como root.
#
#  Uso:   PORTAL=http://10.10.10.101:8088 TOKEN=<BRIDGE_TOKEN> ./actualizar_listas_ioc.sh
#  Cron (cada día a las 3:10, fuera de horario):
#    10 3 * * * root PORTAL=http://10.10.10.101:8088 TOKEN=xxxx /var/ossec/etc/actualizar_listas_ioc.sh >> /var/log/ioc-listas.log 2>&1
#
#  Wazuh compila las listas al arrancar: si alguna cambió, se reinicia wazuh-manager (unos 30 s).
# =====================================================================
set -uo pipefail
PORTAL="${PORTAL:-http://10.10.10.101:8088}"
TOKEN="${TOKEN:?Define TOKEN con el valor de BRIDGE_TOKEN del portal}"
MINW="${MIN_WEIGHT:-75}"            # solo fuentes con confianza >= 75
DIR=/var/ossec/etc/lists
cambios=0

for k in ip domain hash; do
  dst="$DIR/soc-ioc-$k"
  tmp=$(mktemp)
  if curl -sf --max-time 900 -H "X-API-Key: $TOKEN" "$PORTAL/feeds/wazuh/$k.cdb?min_weight=$MINW" -o "$tmp"; then
    n=$(wc -l < "$tmp")
    if [ "$n" -eq 0 ]; then
      if [ -s "$dst" ]; then echo "$(date '+%F %T') $k: el portal devolvió una lista vacía; se conserva la anterior"; rm -f "$tmp"; continue; fi
      echo "0.0.0.1:vacia" > "$tmp"    # una lista CDB no puede estar vacía
    fi
    if ! cmp -s "$tmp" "$dst"; then
      install -o wazuh -g wazuh -m 660 "$tmp" "$dst" && cambios=1
      echo "$(date '+%F %T') $k: $n entradas (actualizada)"
    else
      echo "$(date '+%F %T') $k: sin cambios ($n entradas)"
    fi
  else
    echo "$(date '+%F %T') $k: no se pudo descargar de $PORTAL (¿token o red?)"
  fi
  rm -f "$tmp"
done

for k in ip domain hash; do
  grep -q "etc/lists/soc-ioc-$k" /var/ossec/etc/ossec.conf || \
    echo "AVISO: falta <list>etc/lists/soc-ioc-$k</list> dentro de <ruleset> en ossec.conf"
done

if [ "$cambios" = 1 ]; then
  if /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    systemctl restart wazuh-manager && echo "$(date '+%F %T') wazuh-manager reiniciado con las listas nuevas"
  else
    echo "$(date '+%F %T') ERROR: la configuración no valida (wazuh-analysisd -t); NO se reinicia"
  fi
fi
