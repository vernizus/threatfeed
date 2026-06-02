#!/usr/bin/env bash
# Importación masiva de IPs y dominios desde ficheros de texto plano.
# Uso: ./bulk-import.sh <fichero_ips.txt> <fichero_dominios.txt>
#
# Formato del fichero: una IP/CIDR o dominio por línea. Se ignoran líneas vacías y comentarios (#).
# Ejemplo:
#   1.2.3.4
#   10.0.0.0/8
#   # esto es un comentario
#   185.220.101.45

set -euo pipefail

HOST="${THREATFEED_HOST:-http://localhost:8000}"
API_KEY="${API_KEY:?Establece la variable API_KEY}"
BATCH_SIZE=100  # elementos por petición bulk (máximo 500)
ENTRY_TYPE="${ENTRY_TYPE:-permanent}"
DURATION="${DURATION_SECONDS:-3600}"  # solo relevante si ENTRY_TYPE=temporary

IP_FILE="${1:-}"
DOMAIN_FILE="${2:-}"

if [[ -z "$IP_FILE" && -z "$DOMAIN_FILE" ]]; then
    echo "Uso: $0 [fichero_ips.txt] [fichero_dominios.txt]"
    exit 1
fi

build_item_ip() {
    local element="$1"
    local data_type="ip"
    # Detectar si es CIDR
    if [[ "$element" == */* ]]; then
        data_type="cidr"
    fi
    if [[ "$ENTRY_TYPE" == "temporary" ]]; then
        printf '{"element":"%s","data_type":"%s","entry_type":"temporary","duration_seconds":%s}' \
            "$element" "$data_type" "$DURATION"
    else
        printf '{"element":"%s","data_type":"%s","entry_type":"permanent"}' \
            "$element" "$data_type"
    fi
}

build_item_domain() {
    local element="$1"
    if [[ "$ENTRY_TYPE" == "temporary" ]]; then
        printf '{"element":"%s","data_type":"domain","entry_type":"temporary","duration_seconds":%s}' \
            "$element" "$DURATION"
    else
        printf '{"element":"%s","data_type":"domain","entry_type":"permanent"}' "$element"
    fi
}

send_bulk() {
    local items_json="$1"
    local response
    response=$(curl -sf -X POST "$HOST/api/feed/bulk" \
        -H "X-API-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"items\":[$items_json]}")
    local processed failed
    processed=$(echo "$response" | grep -o '"processed":[0-9]*' | cut -d: -f2)
    failed=$(echo "$response" | grep -o '"failed":[0-9]*' | cut -d: -f2)
    echo "  → procesados: $processed | fallidos: $failed"
}

import_file() {
    local file="$1"
    local type="$2"  # "ip" o "domain"
    local items=()
    local count=0
    local total=0

    echo "Importando $file como $type..."

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line// /}"  # strip spaces
        [[ -z "$line" || "$line" == \#* ]] && continue

        if [[ "$type" == "ip" ]]; then
            items+=("$(build_item_ip "$line")")
        else
            items+=("$(build_item_domain "$line")")
        fi
        ((count++)) || true
        ((total++)) || true

        if (( count >= BATCH_SIZE )); then
            local batch
            batch=$(IFS=,; echo "${items[*]}")
            send_bulk "$batch"
            items=()
            count=0
        fi
    done < "$file"

    # Enviar el último lote parcial
    if (( ${#items[@]} > 0 )); then
        local batch
        batch=$(IFS=,; echo "${items[*]}")
        send_bulk "$batch"
    fi

    echo "Total leído de $file: $total elementos"
}

[[ -n "$IP_FILE"     ]] && import_file "$IP_FILE"     "ip"
[[ -n "$DOMAIN_FILE" ]] && import_file "$DOMAIN_FILE" "domain"

echo "Importación completada."
