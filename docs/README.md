# Threat Feed Service — Documentación

Microservicio REST que gestiona listas de bloqueo (IPs, CIDRs, Dominios) con sistema de reputación histórico, promoción automática a permanente, y salida en texto plano compatible con firewalls.

## Casos de uso

- **FortiGate External Block List**: los endpoints `/feed/*/active` devuelven texto plano listo para consumir desde External Connectors de FortiOS.
- **Cualquier firewall con threat feed HTTP**: Palo Alto, pfSense/OPNsense, Squid, nginx geo-block, etc.
- **Automatización SOC**: alimentar el servicio desde alertas de Wazuh, SIEM events, o MISP para bloqueo automático.

## Estructura de archivos

```
iplistfw/
├── app/
│   ├── main.py         # FastAPI — rutas y lógica HTTP
│   ├── database.py     # SQLite — operaciones y control de concurrencia
│   └── models.py       # Pydantic — validación de entrada/salida
├── docs/
│   ├── README.md       # Este archivo
│   ├── api-reference.md
│   ├── environment-variables.md
│   ├── fortinet-integration.md
│   └── examples/
│       ├── bulk-import.sh
│       └── wazuh-ar-integration.sh
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Arranque rápido

```bash
# 1. Crear fichero de entorno
echo "API_KEY=mi-clave-secreta-aqui" > .env

# 2. Levantar el servicio
docker compose up -d

# 3. Verificar
curl http://localhost:8000/health
```

## Conceptos clave

### entry_type

| Tipo | Comportamiento |
|------|---------------|
| `permanent` | No expira nunca. Permanece hasta DELETE explícito. |
| `temporary` | Expira pasados `duration_seconds` segundos. Si alcanza el umbral, se promueve a permanent automáticamente. |

### Sistema de reputación

Cada vez que se hace un `POST /api/feed` con un elemento (sea permanente o temporal), el sistema:
1. Añade o actualiza el elemento en la lista activa.
2. Incrementa el contador en `threat_history`.
3. Si `occurrences_count >= THRESHOLD_PROMOTION` **y** `PROMOTION_ENABLED=true`, convierte el elemento a `permanent` automáticamente.

Un elemento eliminado de la feed (`DELETE`) conserva su historial — si se vuelve a añadir, retoma el contador anterior.

## Endpoints resumen

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| GET | `/feed/ip/active` | No | IPs/CIDRs activos (permanent + temp no expirados) |
| GET | `/feed/ip/permanent` | No | Solo IPs/CIDRs permanentes |
| GET | `/feed/ip/temporary` | No | Solo IPs/CIDRs temporales no expirados |
| GET | `/feed/domain/active` | No | Dominios activos |
| GET | `/feed/domain/permanent` | No | Solo dominios permanentes |
| GET | `/feed/domain/temporary` | No | Solo dominios temporales no expirados |
| GET | `/feed/history` | Sí | Histórico de reincidencias |
| GET | `/api/stats` | Sí | Estadísticas del servicio |
| POST | `/api/feed` | Sí | Añadir/actualizar un elemento |
| POST | `/api/feed/bulk` | Sí | Importar hasta 500 elementos |
| DELETE | `/api/feed` | Sí | Eliminar un elemento de la feed |
| GET | `/health` | No | Estado del servicio |

La documentación interactiva (Swagger UI) está disponible en `http://localhost:8000/docs` (requiere `DEBUG=true`).

## Índice de documentación

- [deploy.md](deploy.md) — Despliegue básico, producción con nginx+TLS, operaciones y troubleshooting
- [api-reference.md](api-reference.md) — Todos los endpoints con ejemplos curl
- [environment-variables.md](environment-variables.md) — Referencia completa de variables de entorno
- [fortinet-integration.md](fortinet-integration.md) — Integración con FortiGate External Connectors
