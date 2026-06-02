#!/usr/bin/env bash
# =============================================================================
# threatfeed-add-ip.sh — Wazuh Active Response (server-side)
#
# Envía la IP bloqueada por un AR al Threat Feed Service.
# Se ejecuta en el MANAGER (location: server), no en el agente.
#
# Despliegue:
#   cp threatfeed-add-ip.sh /var/ossec/active-response/bin/
#   chmod 750 /var/ossec/active-response/bin/threatfeed-add-ip.sh
#   chown root:wazuh /var/ossec/active-response/bin/threatfeed-add-ip.sh
#
# Configuracion (crear este fichero en el manager):
#   /var/ossec/etc/threatfeed.conf
#   chmod 640  /var/ossec/etc/threatfeed.conf
#   chown root:wazuh /var/ossec/etc/threatfeed.conf
#
#   Contenido de threatfeed.conf:
#     THREATFEED_HOST="http://10.0.0.100:8000"
#     THREATFEED_API_KEY="tu-clave-aqui"
#
# Logica de duracion (igual que los AR existentes):
#   Nivel  < 14  → temporary 3600s  (1 hora)
#   Nivel >= 14  → temporary 86400s (24 horas)
#   Nivel >= 14 + reincidencia >= THRESHOLD → promovido a permanent por el servicio
# =============================================================================

set -euo pipefail

CONF_FILE="/var/ossec/etc/threatfeed.conf"
LOG_FILE="/var/ossec/logs/active-responses.log"
SCRIPT="threatfeed-add-ip"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') $SCRIPT: $*" >> "$LOG_FILE"
}

# ── Leer configuracion ────────────────────────────────────────────────────────
if [[ ! -f "$CONF_FILE" ]]; then
    log "ERROR: $CONF_FILE no encontrado. Crear el fichero con THREATFEED_HOST y THREATFEED_API_KEY."
    exit 1
fi
# shellcheck source=/dev/null
source "$CONF_FILE"

if [[ -z "${THREATFEED_HOST:-}" || -z "${THREATFEED_API_KEY:-}" ]]; then
    log "ERROR: THREATFEED_HOST o THREATFEED_API_KEY no definidos en $CONF_FILE"
    exit 1
fi

# ── Leer JSON del alert desde stdin ──────────────────────────────────────────
INPUT=$(cat)

ACTION=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('command', 'add'))
" 2>/dev/null || echo "add")

# Solo procesar el bloqueo, no la eliminacion (el TTL lo gestiona el Threat Feed)
if [[ "$ACTION" != "add" ]]; then
    log "Accion '$ACTION' ignorada (el Threat Feed gestiona TTL de forma nativa)"
    exit 0
fi

# ── Extraer IP y nivel de alerta ──────────────────────────────────────────────
SRCIP=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
alert = d.get('parameters', {}).get('alert', {})
data  = alert.get('data', {})
# Intentar varios campos en orden de prioridad
for field in ('srcip', 'src_ip', 'win.eventdata.sourceIp', 'agent.ip'):
    val = data
    for key in field.split('.'):
        val = val.get(key, {}) if isinstance(val, dict) else {}
    if isinstance(val, str) and val:
        print(val)
        sys.exit(0)
print('')
" 2>/dev/null || echo "")

LEVEL=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('parameters', {}).get('alert', {}).get('rule', {}).get('level', 10))
" 2>/dev/null || echo "10")

RULE_ID=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('parameters', {}).get('alert', {}).get('rule', {}).get('id', 'unknown'))
" 2>/dev/null || echo "unknown")

RULE_DESC=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('parameters', {}).get('alert', {}).get('rule', {}).get('description', '')[:200])
" 2>/dev/null || echo "")

if [[ -z "$SRCIP" ]]; then
    log "No se encontro srcip en el alert (regla $RULE_ID). Saliendo."
    exit 0
fi

# Validar que es una IP valida
if ! python3 -c "import ipaddress; ipaddress.ip_address('$SRCIP')" 2>/dev/null; then
    log "Valor '$SRCIP' no es una IP valida. Saliendo."
    exit 0
fi

# ── Calcular duracion segun nivel (igual que AR existentes) ──────────────────
if (( LEVEL >= 14 )); then
    DURATION=86400
    DURATION_LABEL="24h"
else
    DURATION=3600
    DURATION_LABEL="1h"
fi

COMMENT="Wazuh AR | Regla $RULE_ID (nivel $LEVEL) | $RULE_DESC"

# ── Enviar al Threat Feed Service ─────────────────────────────────────────────
PAYLOAD=$(python3 -c "
import json
print(json.dumps({
    'element':          '$SRCIP',
    'data_type':        'ip',
    'entry_type':       'temporary',
    'duration_seconds': $DURATION,
    'source':           'wazuh-ar',
    'comment':          '${COMMENT//\'/\\\'}'
}))
")

HTTP_STATUS=$(curl -s -o /tmp/threatfeed_response_$$.json -w "%{http_code}" \
    --max-time 10 \
    -X POST "$THREATFEED_HOST/api/feed" \
    -H "X-API-Key: $THREATFEED_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>/dev/null)

if [[ "$HTTP_STATUS" == "200" ]]; then
    OCCURRENCES=$(python3 -c "
import json
with open('/tmp/threatfeed_response_$$.json') as f:
    d = json.load(f)
print(d.get('occurrences_count', '?'))
    " 2>/dev/null || echo "?")
    PROMOTED=$(python3 -c "
import json
with open('/tmp/threatfeed_response_$$.json') as f:
    d = json.load(f)
print('PROMOVIDA A PERMANENTE' if d.get('promoted_to_permanent') else '')
    " 2>/dev/null || echo "")
    log "OK: $SRCIP → temporary $DURATION_LABEL | ocurrencias=$OCCURRENCES | regla=$RULE_ID $PROMOTED"
else
    log "ERROR HTTP $HTTP_STATUS: $SRCIP | regla=$RULE_ID"
fi

rm -f "/tmp/threatfeed_response_$$.json"
exit 0
