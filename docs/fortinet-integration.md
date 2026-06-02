# Integración con FortiGate (External Block List)

FortiGate soporta **External Connectors** de tipo Threat Feed que consumen ficheros de texto plano mediante HTTP/HTTPS, uno por línea. Los endpoints `/feed/*/active` de este servicio son directamente compatibles con ese formato.

## Prerrequisitos

- FortiOS 6.4 o superior (External Connectors disponibles desde 6.2).
- El servicio Threat Feed accesible desde el FortiGate (mismo segmento, DMZ, o HTTPS a través de un reverse proxy).
- Para producción: exponer el servicio detrás de nginx/Traefik con TLS. Los feeds son públicos por diseño, pero restringir el acceso por IP al FortiGate es recomendable.

---

## Paso 1 — Crear los External Connectors

En FortiGate: **Security Fabric > External Connectors > Create New > Threat Feed**

### Conector de IPs

| Campo | Valor |
|-------|-------|
| Name | `ThreatFeed-IPs` |
| Type | `IP Address` |
| URI | `http://<host>:8000/feed/ip/active` |
| HTTP basic auth | No (los feeds son públicos) |
| Refresh rate | `5 minutes` (recomendado) |
| Status | Enable |

### Conector de Dominios

| Campo | Valor |
|-------|-------|
| Name | `ThreatFeed-Domains` |
| Type | `Domain Name` |
| URI | `http://<host>:8000/feed/domain/active` |
| Refresh rate | `5 minutes` |
| Status | Enable |

### CLI equivalente

```
config system external-resource
    edit "ThreatFeed-IPs"
        set type address
        set resource "http://<host>:8000/feed/ip/active"
        set refresh-rate 5
        set status enable
    next
    edit "ThreatFeed-Domains"
        set type domain
        set resource "http://<host>:8000/feed/domain/active"
        set refresh-rate 5
        set status enable
    next
end
```

---

## Paso 2 — Crear los Address Objects

FortiGate genera automáticamente un objeto de dirección dinámico a partir del connector. Verificar en **Policy & Objects > Addresses** que aparecen:

- `ThreatFeed-IPs` (tipo: External Resource)
- `ThreatFeed-Domains` (tipo: External Resource)

---

## Paso 3 — Crear la Firewall Policy de bloqueo

**Policy & Objects > Firewall Policy > Create New**

Política de denegación que referencia los objetos dinámicos:

| Campo | Valor |
|-------|-------|
| Name | `Block-ThreatFeed` |
| Incoming Interface | `<interfaz LAN/WAN según caso de uso>` |
| Outgoing Interface | `any` |
| Source / Destination | `ThreatFeed-IPs` y/o `ThreatFeed-Domains` |
| Action | `DENY` |
| Log Violation Traffic | Enable |

> **Posición en la tabla de políticas:** Esta política debe ir **por encima** de las políticas de allow general. FortiGate evalúa las políticas en orden descendente de la lista.

### CLI equivalente

```
config firewall policy
    edit 0
        set name "Block-ThreatFeed-IPs"
        set srcintf "port1"
        set dstintf "any"
        set dstaddr "ThreatFeed-IPs"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
    edit 0
        set name "Block-ThreatFeed-Domains"
        set srcintf "port1"
        set dstintf "any"
        set dstaddr "ThreatFeed-Domains"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

---

## Paso 4 — Verificar la sincronización

```bash
# En FortiGate CLI
diagnose threat-feed category list
# Debe mostrar ThreatFeed-IPs y ThreatFeed-Domains con el número de entradas

diagnose threat-feed category ip ThreatFeed-IPs
# Lista las IPs cargadas actualmente

# Forzar refresco inmediato
diagnose threat-feed update ThreatFeed-IPs
```

---

## Notas de formato

El servicio devuelve:
- **IPs**: una dirección IPv4 o IPv6 por línea (`1.2.3.4`, `2001:db8::1`)
- **CIDRs**: notación CIDR estándar por línea (`10.0.0.0/8`, `185.220.0.0/16`)
- **Dominios**: FQDN por línea (`evil.example.com`, `c2.badactor.net`)
- Líneas vacías al final si la lista está vacía (FortiGate las ignora correctamente)

FortiGate acepta CIDRs en el feed de tipo `IP Address` sin necesidad de configuración adicional.

---

## Recomendaciones de producción

### HTTPS con reverse proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name threatfeed.internal.ejemplo.com;

    ssl_certificate     /etc/ssl/certs/threatfeed.crt;
    ssl_certificate_key /etc/ssl/private/threatfeed.key;

    # Restringir acceso solo al FortiGate
    allow <IP-FortiGate>;
    deny all;

    location /feed/ {
        proxy_pass http://localhost:8000;
    }
}
```

Cambiar las URIs en los External Connectors a `https://threatfeed.internal.ejemplo.com/feed/ip/active`.

### Refresh rate recomendado

| Escenario | Refresh rate |
|-----------|-------------|
| Respuesta a incidentes activos | 1-2 minutos |
| Operación normal | 5 minutos |
| Feed con pocos cambios | 15-30 minutos |

FortiGate tiene un mínimo de 1 minuto. Para actualizaciones más rápidas, usar la API de FortiGate para forzar refresco programático.

### Integración con Wazuh Active Response

Ver `docs/examples/wazuh-ar-integration.sh` para un script de Active Response que alimenta este servicio automáticamente cuando Wazuh detecta una IP maliciosa.
