# API Reference

Base URL: `http://<host>:8000`  
Auth: cabecera `X-API-Key: <API_KEY>` en endpoints protegidos.  
Swagger interactivo: `http://<host>:8000/docs`

---

## Endpoints públicos — Feeds de texto plano

Devuelven `text/plain`, un elemento por línea. Sin autenticación.  
Diseñados para consumo directo por firewalls (FortiGate, pfSense, Squid, etc.).

### `GET /feed/ip/active`

Todos los IPs/CIDRs activos en este momento: permanentes + temporales no expirados.  
**Endpoint recomendado para FortiGate External Connector de tipo IPv4.**

```bash
curl http://localhost:8000/feed/ip/active
# 1.2.3.4
# 10.0.0.0/8
# 185.220.101.45
```

### `GET /feed/ip/permanent`

Solo IPs/CIDRs marcados como permanentes.

### `GET /feed/ip/temporary`

Solo IPs/CIDRs temporales cuya expiración no ha llegado aún.

### `GET /feed/domain/active`

Todos los dominios activos. **Endpoint recomendado para FortiGate External Connector de tipo Domain.**

```bash
curl http://localhost:8000/feed/domain/active
# malware.example.com
# c2.badactor.net
```

### `GET /feed/domain/permanent`
### `GET /feed/domain/temporary`

---

## Endpoints protegidos — Gestión

Requieren cabecera `X-API-Key`.

---

### `POST /api/feed`

Añade o actualiza un elemento. Ejecuta la lógica de historial y promoción automática.

**Body:**
```json
{
  "element": "1.2.3.4",
  "data_type": "ip",
  "entry_type": "temporary",
  "duration_seconds": 3600
}
```

| Campo | Tipo | Valores | Notas |
|-------|------|---------|-------|
| `element` | string | IP, CIDR o dominio | Validado según `data_type` |
| `data_type` | string | `"ip"` \| `"cidr"` \| `"domain"` | |
| `entry_type` | string | `"permanent"` \| `"temporary"` | |
| `duration_seconds` | int | > 0 | Requerido si `entry_type = "temporary"` |

**Respuesta:**
```json
{
  "element": "1.2.3.4",
  "data_type": "ip",
  "entry_type": "temporary",
  "occurrences_count": 3,
  "promoted_to_permanent": false,
  "message": null
}
```

Si se alcanza el umbral de promoción:
```json
{
  "element": "1.2.3.4",
  "data_type": "ip",
  "entry_type": "permanent",
  "occurrences_count": 5,
  "promoted_to_permanent": true,
  "message": "Auto-promoted to permanent (threshold=5 occurrences reached)."
}
```

**Ejemplos curl:**

```bash
# IP temporal — 1 hora
curl -X POST http://localhost:8000/api/feed \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"element":"1.2.3.4","data_type":"ip","entry_type":"temporary","duration_seconds":3600}'

# CIDR permanente
curl -X POST http://localhost:8000/api/feed \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"element":"185.220.0.0/16","data_type":"cidr","entry_type":"permanent"}'

# Dominio temporal — 24 horas
curl -X POST http://localhost:8000/api/feed \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"element":"evil.example.com","data_type":"domain","entry_type":"temporary","duration_seconds":86400}'
```

---

### `POST /api/feed/bulk`

Importa hasta 500 elementos en una sola petición. Procesa todos aunque alguno falle.

**Body:**
```json
{
  "items": [
    {"element": "1.1.1.1", "data_type": "ip", "entry_type": "permanent"},
    {"element": "2.2.2.2", "data_type": "ip", "entry_type": "temporary", "duration_seconds": 7200},
    {"element": "bad.example.com", "data_type": "domain", "entry_type": "permanent"}
  ]
}
```

**Respuesta:**
```json
{
  "processed": 3,
  "failed": 0,
  "results": [
    {"element": "1.1.1.1", "data_type": "ip", "entry_type": "permanent", "occurrences_count": 1, "promoted_to_permanent": false, "error": null},
    ...
  ]
}
```

---

### `DELETE /api/feed`

Elimina un elemento de la feed activa. El historial **se conserva**.

```bash
curl -X DELETE http://localhost:8000/api/feed \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"element": "1.2.3.4"}'
```

**Respuesta:**
```json
{"deleted": "1.2.3.4"}
```

---

### `GET /feed/history`

Listado completo de reincidencias, ordenado por número de ocurrencias descendente.

```bash
curl http://localhost:8000/feed/history \
  -H "X-API-Key: $API_KEY"
```

**Respuesta:**
```json
{
  "total": 42,
  "items": [
    {"element": "1.2.3.4", "data_type": "ip", "occurrences_count": 12, "last_seen": "2026-06-02T09:15:30Z"},
    {"element": "evil.com", "data_type": "domain", "occurrences_count": 7, "last_seen": "2026-06-02T08:00:00Z"}
  ]
}
```

---

### `GET /api/stats`

Estadísticas del servicio.

```bash
curl http://localhost:8000/api/stats \
  -H "X-API-Key: $API_KEY"
```

**Respuesta:**
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

### `GET /health`

```bash
curl http://localhost:8000/health
# {"status": "ok", "promotion_enabled": true, "threshold": 5}
```
