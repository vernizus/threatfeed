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
# Configuracion — /var/ossec/etc/threatfeed.conf:
#   THREATFEED_HOST="http://10.0.0.100:8000"
#   THREATFEED_API_KEY="tu-clave-aqui"
#   THREATFEED_DEDUP_WINDOW="300"   # segundos entre reportes del mismo elemento
#                                   # Evita que una rafaga de alertas del mismo
#                                   # ataque suba el contador varias veces y
#                                   # promueva la IP a permanent de golpe.
#                                   # Default: 300s (5 min). 0 = dedup desactivado.
#
# Logica de duracion (igual que los AR existentes):
#   Nivel  < 14  → temporary 3600s  (1 hora)
#   Nivel >= 14  → temporary 86400s (24 horas)
#   Reincidencias >= THRESHOLD_PROMOTION → promovido a permanent por el servicio
# =============================================================================

set -euo pipefail

CONF_FILE="/var/ossec/etc/threatfeed.conf"
LOG_FILE="/var/ossec/logs/active-responses.log"
DEDUP_DIR="/tmp/threatfeed_dedup"
SCRIPT="threatfeed-add-ip"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') $SCRIPT: $*" >> "$LOG_FILE"
}

# ── Leer configuracion ────────────────────────────────────────────────────────
if [[ ! -f "$CONF_FILE" ]]; then
    log "ERROR: $CONF_FILE no encontrado."
    exit 1
fi
# shellcheck source=/dev/null
source "$CONF_FILE"

if [[ -z "${THREATFEED_HOST:-}" || -z "${THREATFEED_API_KEY:-}" ]]; then
    log "ERROR: THREATFEED_HOST o THREATFEED_API_KEY no definidos en $CONF_FILE"
    exit 1
fi

DEDUP_WINDOW="${THREATFEED_DEDUP_WINDOW:-300}"

# ── Leer JSON del alert desde stdin ──────────────────────────────────────────
INPUT=$(cat)

ACTION=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('command', 'add'))
" 2>/dev/null || echo "add")

# Solo procesar el bloqueo — el TTL lo gestiona el Threat Feed de forma nativa
if [[ "$ACTION" != "add" ]]; then
    exit 0
fi

# ── Extraer IP y metadatos del alert ─────────────────────────────────────────
SRCIP=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('parameters', {}).get('alert', {}).get('data', {})
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

if ! python3 -c "import ipaddress; ipaddress.ip_address('$SRCIP')" 2>/dev/null; then
    log "Valor '$SRCIP' no es una IP valida. Saliendo."
    exit 0
fi

# ── Deduplicacion por ventana de tiempo ───────────────────────────────────────
# Problema: un ataque de fuerza bruta genera decenas de alertas en segundos.
# Sin dedup, cada alerta incrementaria el contador y la IP podria quedar
# permanente en una sola rafaga. La ventana garantiza que el contador solo
# sube UNA VEZ por incidente, no una vez por alerta individual.
if (( DEDUP_WINDOW > 0 )); then
    mkdir -p "$DEDUP_DIR"
    find "$DEDUP_DIR" -mmin +1440 -delete 2>/dev/null || true  # limpiar entradas >24h

    DEDUP_KEY=$(printf '%s' "$SRCIP" | md5sum | cut -d' ' -f1)
    DEDUP_FILE="$DEDUP_DIR/ip_$DEDUP_KEY"

    if [[ -f "$DEDUP_FILE" ]]; then
        LAST_SENT=$(cat "$DEDUP_FILE" 2>/dev/null || echo 0)
        NOW=$(date +%s)
        ELAPSED=$(( NOW - LAST_SENT ))
        if (( ELAPSED < DEDUP_WINDOW )); then
            log "DEDUP: $SRCIP ignorada (reportada hace ${ELAPSED}s, ventana=${DEDUP_WINDOW}s | regla=$RULE_ID)"
            exit 0
        fi
    fi
fi

# ── Calcular duracion segun nivel ────────────────────────────────────────────
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

RESP_FILE="/tmp/threatfeed_response_$$.json"
HTTP_STATUS=$(curl -s -o "$RESP_FILE" -w "%{http_code}" \
    --max-time 10 \
    -X POST "$THREATFEED_HOST/api/feed" \
    -H "X-API-Key: $THREATFEED_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>/dev/null)

if [[ "$HTTP_STATUS" == "200" ]]; then
    OCCURRENCES=$(python3 -c "
import json
with open('$RESP_FILE') as f: d = json.load(f)
print(d.get('occurrences_count', '?'))
    " 2>/dev/null || echo "?")
    PROMOTED=$(python3 -c "
import json
with open('$RESP_FILE') as f: d = json.load(f)
print('| PROMOVIDA A PERMANENTE' if d.get('promoted_to_permanent') else '')
    " 2>/dev/null || echo "")

    log "OK: $SRCIP → temporary $DURATION_LABEL | ocurrencias=$OCCURRENCES | regla=$RULE_ID $PROMOTED"

    # Actualizar timestamp de dedup solo tras exito
    if (( DEDUP_WINDOW > 0 )); then
        date +%s > "$DEDUP_FILE"
    fi
else
    log "ERROR HTTP $HTTP_STATUS: $SRCIP | regla=$RULE_ID"
fi

rm -f "$RESP_FILE"
exit 0
