# Guía de Despliegue

## Requisitos previos

- Docker Engine 24+ y Docker Compose v2
- Puerto 8000 disponible en el host (o cambiar en `docker-compose.yml`)
- Acceso a internet para el pull de la imagen base `python:3.12-slim`

---

## Despliegue básico (desarrollo / red interna)

```bash
# 1. Ir al directorio de build
cd build/

# 2. Crear el fichero de entorno a partir de la plantilla
cp .env.example .env

# 3. Generar una API key segura y pegarla en .env
openssl rand -hex 32

# 4. Editar .env y rellenar API_KEY
#    El resto de variables tienen defaults razonables

# 5. Construir la imagen y levantar
docker compose up -d --build

# 6. Verificar
curl http://localhost:8000/health
```

En los logs del arranque verás la semilla aplicada:

```
[seed] IPs/CIDRs: 38 inserted, 0 already present
[seed] domains:   35 inserted, 0 already present
```

---

## Despliegue en producción (con nginx + TLS)

### Estructura recomendada

```
build/
├── .env
├── docker-compose.yml
└── nginx/
    ├── threatfeed.conf
    └── certs/
        ├── threatfeed.crt
        └── threatfeed.key
```

### 1. Generar certificado (autofirmado para pruebas, CA propia para producción)

```bash
# Autofirmado — solo para pruebas internas
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout build/nginx/certs/threatfeed.key \
  -out    build/nginx/certs/threatfeed.crt \
  -subj "/CN=threatfeed.interno"
```

### 2. Configuración nginx

Crear `build/nginx/threatfeed.conf`:

```nginx
server {
    listen 443 ssl;
    server_name threatfeed.interno;

    ssl_certificate     /etc/nginx/certs/threatfeed.crt;
    ssl_certificate_key /etc/nginx/certs/threatfeed.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Feeds públicos — solo desde firewalls y sistemas autorizados
    location /feed/ {
        allow 192.168.1.1;    # IP del firewall
        allow 10.0.0.0/24;    # Red de gestión SOC
        deny  all;
        proxy_pass http://threatfeed:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # API de gestión — solo desde jump host / Wazuh Manager
    location /api/ {
        allow 10.0.0.5;       # Wazuh Manager
        allow 10.0.0.10;      # Jump host SOC
        deny  all;
        proxy_pass http://threatfeed:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /health {
        allow 10.0.0.0/24;
        deny  all;
        proxy_pass http://threatfeed:8000;
    }
}

# Redirigir HTTP → HTTPS
server {
    listen 80;
    server_name threatfeed.interno;
    return 301 https://$host$request_uri;
}
```

### 3. Añadir nginx al compose

Descomentar el bloque nginx en `docker-compose.yml` y ajustar volúmenes:

```yaml
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/threatfeed.conf:/etc/nginx/conf.d/default.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - threatfeed
    restart: unless-stopped
```

Con nginx delante, el servicio FastAPI **no** debe exponer el puerto 8000 al exterior. Cambiar en `docker-compose.yml`:

```yaml
# En lugar de:
ports:
  - "8000:8000"

# Usar (solo accesible desde la red Docker interna):
expose:
  - "8000"
```

### 4. Levantar el stack completo

```bash
docker compose up -d --build
```

---

## Actualizar el servicio

```bash
# Reconstruir imagen (incluye nuevas seeds si las modificaste)
docker compose up -d --build

# Solo reiniciar sin reconstruir
docker compose restart threatfeed

# Ver logs en tiempo real
docker compose logs -f threatfeed
```

---

## Actualizar las listas de seed

Las listas `build/seeds/ips.txt` y `build/seeds/domains.txt` van dentro de la imagen. Para añadir nuevas entradas:

```bash
# 1. Editar el fichero de seed
echo "1.2.3.4" >> build/seeds/ips.txt

# 2. Reconstruir y reiniciar (solo reconstruye capas afectadas — rápido)
docker compose up -d --build

# 3. Verificar que se insertó
curl -H "X-API-Key: $API_KEY" http://localhost:8000/api/stats
```

> Las entradas ya existentes se saltan (`INSERT OR IGNORE`). Solo se insertan las nuevas.

---

## Configurar el firewall

Con el servicio en marcha, apuntar el firewall a los endpoints de feed:

| Feed | URI | Refresh |
|------|-----|---------|
| IPs/CIDRs | `https://threatfeed.interno/feed/ip/active` | 5 min |
| Dominios | `https://threatfeed.interno/feed/domain/active` | 5 min |

Ver [firewall-integration.md](firewall-integration.md) para la configuración específica de cada firewall (FortiGate, Cisco, MikroTik, pfSense, Squid, nginx).

---

## Operaciones habituales

```bash
# Estado del contenedor
docker compose ps

# Inspeccionar la BD directamente
docker exec -it $(docker compose ps -q threatfeed) \
  sqlite3 /data/threatfeed.db "SELECT COUNT(*) FROM threat_feed;"

# Backup de la BD
docker cp $(docker compose ps -q threatfeed):/data/threatfeed.db ./backup-$(date +%F).db

# Parar el servicio
docker compose down

# Parar y eliminar volumen (DESTRUCTIVO — borra todos los datos)
docker compose down -v
```

---

## Troubleshooting

### El contenedor no arranca

```bash
docker compose logs threatfeed
```

Causas comunes:
- `API_KEY` no definida en `.env` → el compose falla con el mensaje de error configurado
- Puerto 8000 ocupado → cambiar `ports` en `docker-compose.yml`

### El firewall no recibe la lista

1. Verificar que el endpoint responde desde la IP del firewall:
   ```bash
   curl -v https://threatfeed.interno/feed/ip/active
   ```
2. Revisar que nginx permite la IP del firewall en el bloque `/feed/`
3. En FortiGate: `diagnose threat-feed update ThreatFeed-IPs`

### `[seed]` no aparece en los logs

- Verificar `SEED_ENABLED=true` en `.env`
- Verificar que los ficheros existen dentro del contenedor:
  ```bash
  docker exec $(docker compose ps -q threatfeed) ls /app/seeds/
  ```
