# API Reference

Base URL: `http://<host>:8000`  
Auth: cabecera `X-API-Key: <API_KEY>` en endpoints protegidos.  
Swagger interactivo: `http://<host>:8000/docs` (solo con `DEBUG=true`).

---

## Resumen de endpoints

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| GET | `/feed/ip/active` | No* | IPs/CIDRs activos — firewall consumable |
| GET | `/feed/ip/permanent` | No* | Solo IPs/CIDRs permanentes |
| GET | `/feed/ip/temporary` | No* | Solo IPs/CIDRs temporales no expirados |
| GET | `/feed/domain/active` | No* | Dominios activos — firewall consumable |
| GET | `/feed/domain/permanent` | No* | Solo dominios permanentes |
| GET | `/feed/domain/temporary` | No* | Solo dominios temporales no expirados |
| GET | `/api/feed/lookup` | No / Sí | Consulta de un elemento (ver modos) |
| GET | `/feed/history` | Sí | Historial de reincidencias |
| GET | `/api/stats` | Sí | Estadísticas del servicio |
| POST | `/api/feed` | Sí | Añadir/actualizar un elemento |
| POST | `/api/feed/bulk` | Sí | Importar hasta 500 elementos |
| POST | `/api/feed/import` | Sí | Descargar feed remoto desde URL |
| DELETE | `/api/feed` | Sí | Eliminar un elemento |
| GET | `/health` | No | Estado del servicio |

\* `?detail=true` requiere `X-API-Key`.

---

## Feeds de texto plano

Devuelven `text/plain`, un elemento por línea.  
Compatibles con cualquier firewall que soporte External Block Lists HTTP:
FortiGate, Cisco FTD/ASA, MikroTik, pfSense, OPNsense, Squid, nginx y cualquier firewall con soporte de listas HTTP.

### `GET /feed/ip/active`

IPs/CIDRs activos: permanentes + temporales no expirados.

```
1.2.3.4
10.0.0.0/8
185.220.101.45
```

### `GET /feed/ip/permanent`

Solo IPs/CIDRs con `entry_type = permanent`.

### `GET /feed/ip/temporary`

Solo IPs/CIDRs temporales cuya expiración no ha llegado.

### `GET /feed/domain/active`

Dominios activos: permanentes + temporales no expirados.

```
c2.badactor.net
malware.example.com
```

### `GET /feed/domain/permanent`
### `GET /feed/domain/temporary`

---

### Modo detail (`?detail=true`)

Todos los endpoints de feed aceptan `?detail=true`. Requiere `X-API-Key`.  
Devuelve `application/json` con `source` y `comment` por entrada.  
El plain text sin parámetro no cambia — los firewalls no se ven afectados.

```bash
curl "http://localhost:8000/feed/ip/active?detail=true" \
  -H "X-API-Key: $API_KEY"
```

```json
[
  {
    "element": "1.2.3.4",
    "data_type": "ip",
    "entry_type": "permanent",
    "source": "wazuh-ar",
    "comment": "Incidente #42 — brute force SSH",
    "expires_at": null
  },
  {
    "element": "5.6.7.8",
    "data_type": "ip",
    "entry_type": "temporary",
    "source": "feodo",
    "comment": "Feodo Tracker C2 blocklist",
    "expires_at": "2026-06-03T10:00:00Z"
  }
]
```

---

## `GET /api/feed/lookup`

Consulta el estado de un elemento. Dos modos según autenticación.

### Sin API key — modo público

Devuelve solo si el elemento está actualmente bloqueado. Una sola query, sin exponer intel interna.

```bash
curl "http://localhost:8000/api/feed/lookup?element=1.2.3.4"
```

```json
{"element": "1.2.3.4", "blocked": true}
```

### Con API key — modo completo

Devuelve estado completo del feed + historial de reincidencias.

```bash
curl "http://localhost:8000/api/feed/lookup?element=1.2.3.4" \
  -H "X-API-Key: $API_KEY"
```

```json
{
  "element": "1.2.3.4",
  "found": true,
  "feed": {
    "data_type": "ip",
    "entry_type": "permanent",
    "source": "wazuh-ar",
    "comment": "Incidente #42 — brute force SSH",
    "expires_at": null,
    "created_at": "2026-06-02T09:00:00Z",
    "active": true
  },
  "history": {
    "occurrences_count": 7,
    "last_seen": "2026-06-02T14:30:00Z"
  }
}
```

Elemento no registrado:

```json
{"element": "8.8.8.8", "found": false, "feed": null, "history": null}
```

---

## `GET /feed/history`

Historial completo de reincidencias, ordenado por ocurrencias descendente.

```bash
curl http://localhost:8000/feed/history \
  -H "X-API-Key: $API_KEY"
```

```json
{
  "total": 42,
  "items": [
    {"element": "1.2.3.4", "data_type": "ip", "occurrences_count": 12, "last_seen": "2026-06-02T09:15:30Z"},
    {"element": "evil.com", "data_type": "domain", "occurrences_count": 7,  "last_seen": "2026-06-02T08:00:00Z"}
  ]
}
```

---

## `GET /api/stats`

Estadísticas del servicio y configuración activa.

```bash
curl http://localhost:8000/api/stats \
  -H "X-API-Key: $API_KEY"
```

```json
{
  "feed": {
    "ip":     {"permanent": 42, "temporary_active": 7,  "temporary_expired": 3},
    "cidr":   {"permanent": 5,  "temporary_active": 0,  "temporary_expired": 1},
    "domain": {"permanent": 15, "temporary_active": 2,  "temporary_expired": 0}
  },
  "history": {
    "total_unique_elements": 74,
    "total_occurrences": 312
  },
  "config": {
    "threshold_promotion": 5,
    "promotion_enabled": true
  }
}
```

---

## `POST /api/feed`

Añade o actualiza un elemento. Ejecuta historial y promoción automática.

| Campo | Tipo | Valores | Notas |
|-------|------|---------|-------|
| `element` | string | IP, CIDR o dominio | Validado según `data_type`. Máx. 253 chars |
| `data_type` | string | `"ip"` \| `"cidr"` \| `"domain"` | |
| `entry_type` | string | `"permanent"` \| `"temporary"` | |
| `duration_seconds` | int | 1 – 31 536 000 | Requerido si `temporary` |
| `source` | string | cualquier texto | Default: `"manual"`. Máx. 64 chars |
| `comment` | string \| null | texto libre | Opcional. Máx. 512 chars |

```bash
curl -X POST http://localhost:8000/api/feed \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "element": "1.2.3.4",
    "data_type": "ip",
    "entry_type": "temporary",
    "duration_seconds": 3600,
    "source": "wazuh-ar",
    "comment": "Incidente #42 — brute force SSH"
  }'
```

```json
{
  "element": "1.2.3.4",
  "data_type": "ip",
  "entry_type": "temporary",
  "source": "wazuh-ar",
  "comment": "Incidente #42 — brute force SSH",
  "occurrences_count": 3,
  "promoted_to_permanent": false,
  "message": null
}
```

Al alcanzar el umbral:

```json
{
  "entry_type": "permanent",
  "occurrences_count": 5,
  "promoted_to_permanent": true,
  "message": "Auto-promoted to permanent (threshold=5 occurrences reached)."
}
```

> Los entries `permanent` nunca se degradan a `temporary`. Si se re-envían, se actualizan `source` y `comment`.

---

## `POST /api/feed/bulk`

Importa hasta 500 elementos por petición. Los fallos individuales no abortan el lote.

```bash
curl -X POST http://localhost:8000/api/feed/bulk \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {"element": "1.1.1.1", "data_type": "ip", "entry_type": "permanent", "source": "manual"},
      {"element": "2.2.2.2", "data_type": "ip", "entry_type": "temporary", "duration_seconds": 7200, "source": "n8n"},
      {"element": "bad.example.com", "data_type": "domain", "entry_type": "permanent", "comment": "Phishing confirmado"}
    ]
  }'
```

```json
{
  "processed": 3,
  "failed": 0,
  "results": [
    {"element": "1.1.1.1", "data_type": "ip", "entry_type": "permanent", "source": "manual", "occurrences_count": 1, "promoted_to_permanent": false, "error": null},
    ...
  ]
}
```

---

## `POST /api/feed/import`

Descarga una URL de threat feed en texto plano y la importa masivamente.  
`INSERT OR IGNORE` — los elementos ya existentes no se modifican.  
No incrementa contadores de historial (imports masivos no deben inflar reputación).

| Campo | Tipo | Notas |
|-------|------|-------|
| `url` | string | URL del feed. Máx. 2048 chars |
| `data_type` | string | `"ip"` \| `"domain"` |
| `entry_type` | string | Default: `"permanent"` |
| `duration_seconds` | int | Requerido si `temporary` |
| `source` | string | Etiqueta de origen. Requerido |
| `comment` | string \| null | Nota para todas las entradas importadas |

```bash
# Feodo Tracker — C2 botnet IPs (abuse.ch)
curl -X POST http://localhost:8000/api/feed/import \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "data_type": "ip",
    "entry_type": "permanent",
    "source": "feodo",
    "comment": "Feodo Tracker C2 blocklist"
  }'
```

```json
{
  "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
  "source": "feodo",
  "inserted": 287,
  "skipped_duplicate": 12,
  "skipped_invalid": 3,
  "total_parsed": 302
}
```

### Feeds públicos compatibles

| Nombre | URL | `data_type` |
|--------|-----|-------------|
| Feodo Tracker (C2 IPs) | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | `ip` |
| Feodo Tracker recommended | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` | `ip` |
| Emerging Threats compromised | `https://rules.emergingthreats.net/blockrules/compromised-ips.txt` | `ip` |
| Binary Defense Artillery | `https://www.binarydefense.com/banlist.txt` | `ip` |
| Blocklist.de all | `https://lists.blocklist.de/lists/all.txt` | `ip` |
| CI Army | `https://cinsscore.com/list/ci-badguys.txt` | `ip` |

---

## `DELETE /api/feed`

Elimina un elemento de la feed activa. El historial **se conserva**.

```bash
curl -X DELETE http://localhost:8000/api/feed \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"element": "1.2.3.4"}'
```

```json
{"deleted": "1.2.3.4"}
```

---

## `GET /health`

```bash
curl http://localhost:8000/health
# {"status": "ok"}
```
