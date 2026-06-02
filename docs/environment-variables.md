# Variables de Entorno

Todas las variables se configuran en `docker-compose.yml` o en un fichero `.env` en la raíz del proyecto.

## Referencia completa

### `API_KEY` *(requerida)*

Clave secreta para los endpoints protegidos. Se pasa en la cabecera HTTP `X-API-Key`.

```
API_KEY=clave-secreta-larga-y-aleatoria
```

Los endpoints públicos (feeds de texto plano, `/health`) no requieren esta clave — están diseñados para ser consumidos directamente por firewalls.

---

### `THRESHOLD_PROMOTION`

**Default:** `5`

Número de ocurrencias que debe alcanzar un elemento en `threat_history` para ser promovido automáticamente a `permanent`.

```
THRESHOLD_PROMOTION=3   # Más agresivo: bloqueo permanente tras 3 incidencias
THRESHOLD_PROMOTION=10  # Más conservador: requiere 10 incidencias
THRESHOLD_PROMOTION=1   # Todo se promueve inmediatamente en el primer POST
```

El umbral se evalúa en cada `POST /api/feed` y `POST /api/feed/bulk`. Un elemento que ya es `permanent` no se ve afectado (no puede degradarse).

---

### `PROMOTION_ENABLED`

**Default:** `true`

Activa o desactiva la promoción automática a `permanent` cuando se alcanza el umbral.

```
PROMOTION_ENABLED=true   # El sistema promueve automáticamente (comportamiento por defecto)
PROMOTION_ENABLED=false  # Se sigue contando el historial, pero nunca se promueve automáticamente
```

Útil para entornos donde se quiere tracking de reincidencias sin promoción automática, por ejemplo cuando la promoción se gestiona externamente (N8N, script de revisión manual, etc.).

---

### `DB_PATH`

**Default:** `/data/threatfeed.db`

Ruta del fichero SQLite dentro del contenedor. El volumen Docker `threatfeed_data` monta `/data`, por lo que no es necesario cambiar este valor salvo casos especiales.

```
DB_PATH=/data/threatfeed.db
```

---

## Ejemplo de fichero `.env`

```env
API_KEY=s3cr3t-k3y-ch4nge-m3-in-pr0duction
THRESHOLD_PROMOTION=5
PROMOTION_ENABLED=true
```

Lanzar con:

```bash
docker compose --env-file .env up -d
```

---

## Comportamiento combinado

| `PROMOTION_ENABLED` | `THRESHOLD_PROMOTION` | Resultado al llegar al umbral |
|---|---|---|
| `true` | `5` | El elemento se convierte en `permanent` automáticamente |
| `false` | `5` | El contador llega a 5 pero no ocurre nada automático |
| `true` | `1` | Todo elemento se hace `permanent` en el primer POST |
| `true` | `999` | En la práctica, nunca se promueve (umbral inalcanzable) |
