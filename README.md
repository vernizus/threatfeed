# Threat Feed Service

Microservicio de listas de bloqueo dinámicas (IPs, CIDRs, Dominios) con sistema de reputación histórico y salida en texto plano compatible con FortiGate y cualquier firewall que soporte External Block Lists HTTP.

## Características

- Bloqueos **permanentes** y **temporales** (expiración en segundos)
- **Historial de reincidencias** — contador por elemento a lo largo del tiempo
- **Promoción automática** — los temporales se vuelven permanentes al superar un umbral configurable
- **Importación masiva** — hasta 500 elementos por petición
- Compatible con **FortiGate External Connectors** (IPv4 y Domain threat feeds)
- Rate limiting, comparación de API key en tiempo constante, Swagger deshabilitado en producción

## Estructura

```
iplistfw/
├── app/                    # Código fuente (FastAPI)
│   ├── main.py
│   ├── database.py
│   └── models.py
├── build/                  # Docker y dependencias
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
├── docs/                   # Documentación detallada
│   ├── README.md           — índice de docs
│   ├── api-reference.md    — todos los endpoints con ejemplos curl
│   ├── environment-variables.md
│   ├── fortinet-integration.md
│   └── examples/
│       ├── bulk-import.sh
│       └── wazuh-ar-integration.sh
└── .dockerignore
```

## Arranque rápido

```bash
cd build/

# Crear fichero de entorno
echo "API_KEY=tu-clave-secreta" > .env

# Levantar
docker compose --env-file .env up -d

# Verificar
curl http://localhost:8000/health
```

## Endpoints principales

| Ruta | Auth | Descripción |
|------|------|-------------|
| `GET /feed/ip/active` | No | IPs/CIDRs activos — **URL para FortiGate** |
| `GET /feed/domain/active` | No | Dominios activos — **URL para FortiGate** |
| `POST /api/feed` | Sí | Añadir elemento |
| `POST /api/feed/bulk` | Sí | Importar hasta 500 |
| `GET /feed/history` | Sí | Histórico de reincidencias |
| `GET /api/stats` | Sí | Estadísticas del servicio |

Auth: cabecera `X-API-Key: <API_KEY>`.  
Swagger UI disponible en `/docs` solo si `DEBUG=true`.

## Variables de entorno clave

| Variable | Default | Descripción |
|----------|---------|-------------|
| `API_KEY` | — | **Requerida.** Clave para endpoints protegidos |
| `THRESHOLD_PROMOTION` | `5` | Ocurrencias para promover a permanente |
| `PROMOTION_ENABLED` | `true` | Activar/desactivar la promoción automática |
| `DEBUG` | `false` | Habilita Swagger UI en `/docs` |

Ver `docs/environment-variables.md` para referencia completa.

## Documentación

- [API Reference](docs/api-reference.md)
- [Variables de entorno](docs/environment-variables.md)
- [Integración FortiGate](docs/fortinet-integration.md)
