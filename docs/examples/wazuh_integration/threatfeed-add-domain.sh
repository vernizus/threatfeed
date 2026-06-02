#!/usr/bin/env bash
# =============================================================================
# threatfeed-add-domain.sh — Wazuh Active Response (server-side)
#
# Envía el dominio bloqueado por un AR al Threat Feed Service.
# Se ejecuta en el MANAGER (location: server), no en el agente.
#
# Despliegue:
#   cp threatfeed-add-domain.sh /var/ossec/active-response/bin/
#   chmod 750 /var/ossec/active-response/bin/threatfeed-add-domain.sh
#   chown root:wazuh /var/ossec/active-response/bin/threatfeed-add-domain.sh
#
# Requiere /var/ossec/etc/threatfeed.conf (igual que threatfeed-add-ip.sh)
# THREATFEED_DEDUP_WINDOW aplica igual — evita que una rafaga de consultas DNS
# al mismo dominio suba el contador multiples veces en el mismo incidente.
#
# Campos donde se busca el dominio (en orden de prioridad):
#   data.win.eventdata.queryName  → Sysmon Event ID 22 (DNS query)
#   data.dns.question.name        → Suricata dns
#   data.query                    → decoders genericos
#   data.hostname                 → varios decoders
#   data.url / data.http.url      → extrae host de la URL
# =============================================================================

set -euo pipefail

CONF_FILE="/var/ossec/etc/threatfeed.conf"
LOG_FILE="/var/ossec/logs/active-responses.log"
DEDUP_DIR="/tmp/threatfeed_dedup"
SCRIPT="threatfeed-add-domain"

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

if [[ "$ACTION" != "add" ]]; then
    exit 0
fi

# ── Extraer dominio del alert ─────────────────────────────────────────────────
DOMAIN=$(echo "$INPUT" | python3 -c "
import sys, json, re, urllib.parse

DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def is_valid_domain(s):
    return bool(s and DOMAIN_RE.match(s.strip()))

def extract_host_from_url(url):
    try:
        return urllib.parse.urlparse(url).hostname or ''
    except Exception:
        return ''

d     = json.load(sys.stdin)
alert = d.get('parameters', {}).get('alert', {})
data  = alert.get('data', {})

candidates = [
    data.get('win', {}).get('eventdata', {}).get('queryName', ''),
    data.get('dns', {}).get('question', {}).get('name', ''),
    data.get('query', ''),
    data.get('hostname', ''),
    extract_host_from_url(data.get('url', '')),
    extract_host_from_url(data.get('http', {}).get('url', '')),
]

for c in candidates:
    c = str(c).strip().rstrip('.')
    if is_valid_domain(c):
        print(c)
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

if [[ -z "$DOMAIN" ]]; then
    log "No se encontro dominio en el alert (regla $RULE_ID)."
    exit 0
fi

# ── Deduplicacion por ventana de tiempo ───────────────────────────────────────
if (( DEDUP_WINDOW > 0 )); then
    mkdir -p "$DEDUP_DIR"
    find "$DEDUP_DIR" -mmin +1440 -delete 2>/dev/null || true

    DEDUP_KEY=$(printf '%s' "$DOMAIN" | md5sum | cut -d' ' -f1)
    DEDUP_FILE="$DEDUP_DIR/dom_$DEDUP_KEY"

    if [[ -f "$DEDUP_FILE" ]]; then
        LAST_SENT=$(cat "$DEDUP_FILE" 2>/dev/null || echo 0)
        NOW=$(date +%s)
        ELAPSED=$(( NOW - LAST_SENT ))
        if (( ELAPSED < DEDUP_WINDOW )); then
            log "DEDUP: $DOMAIN ignorado (reportado hace ${ELAPSED}s, ventana=${DEDUP_WINDOW}s | regla=$RULE_ID)"
            exit 0
        fi
    fi
fi

# ── Enviar al Threat Feed Service ─────────────────────────────────────────────
COMMENT="Wazuh AR | Regla $RULE_ID (nivel $LEVEL) | $RULE_DESC"

PAYLOAD=$(python3 -c "
import json
print(json.dumps({
    'element':   '$DOMAIN',
    'data_type': 'domain',
    'entry_type':'permanent',
    'source':    'wazuh-ar',
    'comment':   '${COMMENT//\'/\\\'}'
}))
")

RESP_FILE="/tmp/threatfeed_dom_response_$$.json"
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

    log "OK: $DOMAIN → permanent | ocurrencias=$OCCURRENCES | regla=$RULE_ID"

    if (( DEDUP_WINDOW > 0 )); then
        date +%s > "$DEDUP_FILE"
    fi
else
    log "ERROR HTTP $HTTP_STATUS: $DOMAIN | regla=$RULE_ID"
fi

rm -f "$RESP_FILE"
exit 0
