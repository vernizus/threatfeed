# Threat Feed Service

Microservicio REST de listas de bloqueo dinámicas (IPs, CIDRs, Dominios) con sistema de reputación histórico, promoción automática y salida en texto plano compatible con cualquier firewall que soporte External Block Lists HTTP.

> **Integra con Wazuh, firewall, Cisco, MikroTik, pfSense, Squid y cualquier firewall con soporte de listas de bloqueo HTTP.**

## Características

- Bloqueos **permanentes** y **temporales** (expiración en segundos)
- **Historial de reincidencias** — contador por elemento, trazabilidad de origen (`source`) y notas operacionales (`comment`)
- **Promoción automática** — los temporales escalan a permanentes al superar un umbral configurable
- **Importación masiva** — hasta 500 elementos por petición o descarga directa desde URLs de threat feeds públicos (Feodo Tracker, Emerging Threats…)
- **Lookup** — consulta puntual con o sin API key (modo público: solo `blocked: true/false`)
- **Modo detail** — los feeds devuelven JSON con `source` y `comment` para herramientas SOC (`?detail=true`)
- **Seed inicial** — listas preconfiguradas de IPs y dominios maliciosos conocidos (Tor exits, Feodo C2, phishing…)
- Rate limiting, comparación de API key en tiempo constante, Swagger deshabilitado en producción

## Integraciones

### Wazuh Active Response

Cuando Wazuh dispara un Active Response de bloqueo, los scripts incluidos notifican automáticamente al Threat Feed Service en paralelo — sin modificar los ARs existentes de los agentes.

```
Wazuh detecta ataque
    ├── AR agente: netsh / block-ip-inbound / block-domain  (bloqueo local)
    └── AR manager: threatfeed-add-ip.sh / threatfeed-add-domain.sh
            ↓
        Threat Feed Service (IP temporal / dominio permanente)
            ↓
        firewall recoge el bloqueo en el siguiente refresh (5 min)
```

- `ar_block` → IP entra como **temporary** (1h nivel <14, 24h nivel ≥14)
- `ar_block_domain` → dominio entra como **permanent**
- Cada reincidencia incrementa el contador → al llegar a `THRESHOLD_PROMOTION`, la IP se promueve a **permanent** automáticamente

Ver [`docs/examples/wazuh_integration/`](docs/examples/wazuh_integration/) para scripts y snippet `ossec.conf` listos para desplegar.

### firewall External Block List

```
Security Fabric > External Connectors > Threat Feed
  IPv4:   http://<host>:8000/feed/ip/active
  Domain: http://<host>:8000/feed/domain/active
  Refresh: 5 min
```

Ver [`docs/fortinet-integration.md`](docs/fortinet-integration.md) para configuración completa CLI/GUI.

### Otros firewalls

Los endpoints de feed devuelven texto plano, un elemento por línea — el formato estándar que consume cualquier firewall con soporte de listas externas:

| Firewall | Dónde configurar |
|----------|-----------------|
| **firewall** | Security Fabric > External Connectors |
| **Cisco FTD/ASA** | Security Intelligence > Network / URL feeds |
| **MikroTik** | IP > Firewall > Address List (script de descarga) |
| **pfSense/OPNsense** | Firewall > Aliases > URL Table |
| **Squid** | `acl blocklist dstdomain "/etc/squid/blocklist.txt"` |
| **nginx** | `geo` o `map` block con la lista descargada |

## Estructura

```
threatfeed/
├── app/                          # Código fuente (FastAPI)
│   ├── main.py
│   ├── database.py
│   └── models.py
├── build/                        # Docker y dependencias
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt
│   ├── .env.example
│   └── seeds/
│       ├── ips.txt               — IPs/CIDRs maliciosos conocidos
│       └── domains.txt           — dominios maliciosos conocidos
└── docs/
    ├── deploy.md
    ├── api-reference.md
    ├── environment-variables.md
    ├── fortinet-integration.md
    └── examples/
        ├── curl-examples.txt
        ├── bulk-import.sh
        └── wazuh_integration/
            ├── threatfeed-add-ip.sh       — AR script para IPs
            ├── threatfeed-add-domain.sh   — AR script para dominios
            └── threatfeed_ar_snippet.xml  — bloque ossec.conf
```

## Arranque rápido

```bash
cd build/
cp .env.example .env
# Editar .env — generar API_KEY con: openssl rand -hex 32
docker compose up -d
curl http://localhost:8000/health
```

## Endpoints principales

| Ruta | Auth | Descripción |
|------|------|-------------|
| `GET /feed/ip/active` | No | IPs/CIDRs activos — texto plano para firewalls |
| `GET /feed/domain/active` | No | Dominios activos — texto plano para firewalls |
| `GET /feed/ip/active?detail=true` | Sí | JSON con source y comment |
| `GET /api/feed/lookup?element=X` | No / Sí | `blocked: bool` público · detalle completo con key |
| `POST /api/feed` | Sí | Añadir elemento con source y comment |
| `POST /api/feed/bulk` | Sí | Importar hasta 500 elementos |
| `POST /api/feed/import` | Sí | Descargar feed desde URL (Feodo, ET…) |
| `GET /feed/history` | Sí | Historial de reincidencias |
| `GET /api/stats` | Sí | Estadísticas y configuración activa |

Auth: cabecera `X-API-Key: <API_KEY>`. Swagger en `/docs` solo con `DEBUG=true`.

## Variables de entorno clave

| Variable | Default | Descripción |
|----------|---------|-------------|
| `API_KEY` | — | **Requerida.** Clave para endpoints protegidos |
| `THRESHOLD_PROMOTION` | `5` | Ocurrencias para promover a permanente |
| `PROMOTION_ENABLED` | `true` | Activar/desactivar la promoción automática |
| `SEED_ENABLED` | `true` | Sembrar listas iniciales al arrancar |
| `DEBUG` | `false` | Habilita Swagger UI en `/docs` |

Ver [`docs/environment-variables.md`](docs/environment-variables.md) para referencia completa.

## Documentación

- [Despliegue](docs/deploy.md)
- [API Reference](docs/api-reference.md)
- [Variables de entorno](docs/environment-variables.md)
- [Integración Firewalls](docs/firewall-integration.md)
- [Integración Wazuh](docs/wazuh-integration.md)
- [Integración Wazuh AR — scripts](docs/examples/wazuh_integration/)
