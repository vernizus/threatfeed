#!/usr/bin/env bash
# =============================================================================
# sync_ips_atacantes.sh
#
# Descarga la lista activa del Threat Feed y actualiza la CDB ips_atacantes.
# Escribe directamente en /var/ossec/etc/lists/ y recarga Wazuh.
# Sin credenciales, sin API, sin token.
#
# También se autocomprueba en el primer arranque:
#   - Crea el fichero ips_atacantes si no existe
#   - Añade <list>etc/lists/ips_atacantes</list> al <ruleset> de ossec.conf
#     si no estaba declarado
#
# Configuracion — /var/ossec/etc/threatfeed.conf:
#   THREATFEED_HOST="http://<nombre-servicio-docker>:8000"   # ej. http://threatfeed:8000
#
# Cron en el host (3am):
#   0 3 * * * root docker exec wazuh-manager \
#       /var/ossec/active-response/bin/sync_ips_atacantes.sh
# =============================================================================

set -euo pipefail

CONF_FILE="/var/ossec/etc/threatfeed.conf"
LIST_FILE="/var/ossec/etc/lists/ips_atacantes"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOG_FILE="/var/ossec/logs/threatfeed_sync.log"
TMP="/tmp/ips_atacantes_$$.txt"
MIN_IPS=1
LIST_ENTRY="etc/lists/ips_atacantes"

log() { echo "$(date '+%Y/%m/%d %H:%M:%S') sync_ips_atacantes: $*" >> "$LOG_FILE"; }
trap 'rm -f "$TMP" "$TMP.raw"' EXIT

# ── 1. Crear fichero de lista si no existe ────────────────────────────────
if [[ ! -f "$LIST_FILE" ]]; then
    touch "$LIST_FILE"
    chmod 640 "$LIST_FILE"
    chown root:wazuh "$LIST_FILE" 2>/dev/null || true
    log "INFO: $LIST_FILE creado (no existia)"
fi

# ── 2. Verificar que esta declarado en ossec.conf <ruleset> ───────────────
if [[ -f "$OSSEC_CONF" ]]; then
    if ! grep -q "<list>${LIST_ENTRY}</list>" "$OSSEC_CONF"; then
        # Insertar antes de </ruleset>
        sed -i "s|</ruleset>|    <list>${LIST_ENTRY}</list>\n</ruleset>|" "$OSSEC_CONF"
        log "INFO: <list>${LIST_ENTRY}</list> añadido a $OSSEC_CONF"
    fi
else
    log "AVISO: $OSSEC_CONF no encontrado — verificar manualmente"
fi

# ── 3. Config ─────────────────────────────────────────────────────────────
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"
: "${THREATFEED_HOST:?ERROR: THREATFEED_HOST no definido en $CONF_FILE}"

# ── 4. Descargar feed activo ──────────────────────────────────────────────
HTTP=$(curl -s -o "$TMP.raw" -w "%{http_code}" --max-time 15 \
    "$THREATFEED_HOST/feed/ip/active")

[[ "$HTTP" != "200" ]] && { log "ERROR: GET /feed/ip/active HTTP $HTTP"; exit 1; }

# ── 5. Convertir a CDB: ip:threatfeed ────────────────────────────────────
grep -Ev '^\s*(#|$)' "$TMP.raw" \
    | grep -E '^[0-9a-fA-F:.][0-9a-fA-F:./]*$' \
    | awk '{print $1":threatfeed"}' \
    > "$TMP" || true

COUNT=$(wc -l < "$TMP" | tr -d ' ')

(( COUNT < MIN_IPS )) && {
    log "AVISO: feed vacio ($COUNT IPs). Lista no actualizada."
    exit 0
}

# ── 6. Escribir lista y recargar Wazuh ───────────────────────────────────
cp "$TMP" "$LIST_FILE"
chmod 640 "$LIST_FILE"
chown root:wazuh "$LIST_FILE" 2>/dev/null || true

/var/ossec/bin/wazuh-control reload >> "$LOG_FILE" 2>&1

log "OK: $COUNT IPs → $LIST_FILE | Wazuh recargado"
exit 0
