#!/usr/bin/env bash
# Wazuh Active Response — alimentar el Threat Feed Service automáticamente.
#
# Desplegar en: /var/ossec/active-response/bin/threatfeed-block.sh
# Permisos:     chmod 750 /var/ossec/active-response/bin/threatfeed-block.sh
#               chown root:wazuh /var/ossec/active-response/bin/threatfeed-block.sh
#
# Configurar en ossec.conf del Manager:
#
#   <command>
#     <name>threatfeed-block</name>
#     <executable>threatfeed-block.sh</executable>
#     <timeout_allowed>yes</timeout_allowed>
#   </command>
#
#   <active-response>
#     <command>threatfeed-block</command>
#     <location>server</location>
#     <rules_id>40101,40102,5763</rules_id>  <!-- ajustar a tus rule IDs -->
#     <timeout>3600</timeout>                <!-- segundos; 0 = permanente -->
#   </active-response>
#
# El script lee el JSON de Wazuh desde stdin (formato AR versión 2, Wazuh 4.2+).

set -euo pipefail

THREATFEED_HOST="${THREATFEED_HOST:-http://localhost:8000}"
API_KEY="${THREATFEED_API_KEY:?Establece THREATFEED_API_KEY en el entorno del Manager}"

LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT_NAME="threatfeed-block"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') $SCRIPT_NAME: $*" >> "$LOG_FILE"
}

# Leer el JSON completo de stdin
INPUT=$(cat)

ACTION=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")
SRCIP=$(echo "$INPUT"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parameters',{}).get('alert',{}).get('data',{}).get('srcip',''))" 2>/dev/null || echo "")

if [[ -z "$SRCIP" ]]; then
    log "No srcip en el evento, saliendo."
    exit 0
fi

# Validar que es una IP (no un dominio u otro valor)
if ! python3 -c "import ipaddress; ipaddress.ip_address('$SRCIP')" 2>/dev/null; then
    log "Valor no válido como IP: $SRCIP"
    exit 0
fi

case "$ACTION" in
    add)
        # Temporal 1 hora — el sistema de reputación lo promoverá a permanente
        # si reincide THRESHOLD_PROMOTION veces
        HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "$THREATFEED_HOST/api/feed" \
            -H "X-API-Key: $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"element\":\"$SRCIP\",\"data_type\":\"ip\",\"entry_type\":\"temporary\",\"duration_seconds\":3600}")

        if [[ "$HTTP_STATUS" == "200" ]]; then
            log "ADD OK: $SRCIP bloqueado temporalmente (1h)"
        else
            log "ADD ERROR: $SRCIP — HTTP $HTTP_STATUS"
        fi
        ;;

    delete)
        HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -X DELETE "$THREATFEED_HOST/api/feed" \
            -H "X-API-Key: $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"element\":\"$SRCIP\"}")

        if [[ "$HTTP_STATUS" == "200" ]]; then
            log "DELETE OK: $SRCIP eliminado de la feed"
        elif [[ "$HTTP_STATUS" == "404" ]]; then
            log "DELETE SKIP: $SRCIP no estaba en la feed"
        else
            log "DELETE ERROR: $SRCIP — HTTP $HTTP_STATUS"
        fi
        ;;

    *)
        log "Acción desconocida: $ACTION"
        ;;
esac

exit 0
