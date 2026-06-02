# Integración con Firewalls — External Block List

Los endpoints `/feed/*/active` devuelven texto plano, un elemento por línea — el formato estándar que consume cualquier firewall con soporte de listas de bloqueo HTTP externas.

```
1.2.3.4
10.0.0.0/8
185.220.101.45
```

---

## FortiGate — External Connector

FortiOS 6.2+ soporta **External Connectors** que descargan listas de IPs y dominios vía HTTP/HTTPS de forma periódica.

### Crear los conectores

**Security Fabric > External Connectors > Create New > Threat Feed**

| Campo | IPs/CIDRs | Dominios |
|-------|-----------|---------|
| Name | `ThreatFeed-IPs` | `ThreatFeed-Domains` |
| Type | `IP Address` | `Domain Name` |
| URI | `http://<host>:8000/feed/ip/active` | `http://<host>:8000/feed/domain/active` |
| Refresh rate | 5 min | 5 min |

**CLI equivalente:**
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

### Crear la firewall policy de bloqueo

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

> La política de bloqueo debe ir **por encima** de las políticas de allow general.

### Verificar sincronización

```bash
diagnose threat-feed category list
diagnose threat-feed update ThreatFeed-IPs
```

---

## Cisco FTD / FMC — Security Intelligence

**Policies > Access Control > (política) > Security Intelligence**

1. **Network Intelligence** (IPs) → Add Feed:
   - URL: `http://<host>:8000/feed/ip/active`
   - Action: Block
   - Update interval: 30 min

2. **URL Intelligence** (dominios) → Add Feed:
   - URL: `http://<host>:8000/feed/domain/active`
   - Action: Block

---

## MikroTik — Address List

MikroTik no tiene feed HTTP nativo pero su scripting permite descargarlo y aplicarlo automáticamente. El resultado es una Address List dinámica que se puede referenciar en cualquier regla de firewall.

### Script de descarga e importación

```routeros
/system script add name="ThreatFeedUpdate" source={
  :local urlIPs     "http://<host>:8000/feed/ip/active"
  :local urlDomains "http://<host>:8000/feed/domain/active"
  :local listIPs     "ThreatFeed-IPs"
  :local listDomains "ThreatFeed-Domains"

  # ── Actualizar IPs ──────────────────────────────────────────────────────────
  :local dataIPs [/tool fetch url=$urlIPs as-value output=user]
  /ip firewall address-list remove [find list=$listIPs]
  :foreach line in=[:toarray ($dataIPs->"data")] do={
    :if ($line != "") do={
      :do {
        /ip firewall address-list add list=$listIPs address=$line \
          comment="ThreatFeed auto" timeout=0
      } on-error={ }
    }
  }

  # ── Actualizar Dominios (DNS static) ────────────────────────────────────────
  :local dataDom [/tool fetch url=$urlDomains as-value output=user]
  /ip dns static remove [find comment="ThreatFeed-domain"]
  :foreach line in=[:toarray ($dataDom->"data")] do={
    :if ($line != "") do={
      :do {
        /ip dns static add name=$line address=0.0.0.0 \
          comment="ThreatFeed-domain" ttl=00:30:00
      } on-error={ }
    }
  }

  :log info "ThreatFeed: listas actualizadas"
}
```

### Scheduler — actualización automática cada 30 minutos

```routeros
/system scheduler add \
  name="ThreatFeed-Update" \
  interval=00:30:00 \
  on-event="/system script run ThreatFeedUpdate" \
  comment="Actualiza listas ThreatFeed"
```

### Reglas de firewall

```routeros
# Bloquear tráfico de entrada desde IPs maliciosas
/ip firewall filter add \
  chain=input \
  src-address-list=ThreatFeed-IPs \
  action=drop \
  comment="ThreatFeed — block inbound" \
  place-before=0

# Bloquear tráfico de salida hacia IPs maliciosas
/ip firewall filter add \
  chain=forward \
  dst-address-list=ThreatFeed-IPs \
  action=drop \
  comment="ThreatFeed — block forward" \
  place-before=0
```

> Los dominios se bloquean via DNS static resolviendo a `0.0.0.0`. Requiere que el MikroTik actúe como DNS de los clientes (`/ip dns set allow-remote-requests=yes`).

### Ejecución manual inmediata

```routeros
/system script run ThreatFeedUpdate
```

### Verificar listas cargadas

```routeros
/ip firewall address-list print where list=ThreatFeed-IPs
/ip dns static print where comment~"ThreatFeed-domain"
```

---

## pfSense / OPNsense — URL Table Alias

**Firewall > Aliases > Add**

| Campo | Valor |
|-------|-------|
| Type | `URL Table (IPs)` |
| Name | `ThreatFeed_IPs` |
| URL | `http://<host>:8000/feed/ip/active` |
| Update frequency | `Daily` |

Repetir para dominios con type `URL Table (Hosts)`. Crear regla en **Firewall > Rules** con el alias como destino y acción **Block**.

---

## Squid — Proxy

```bash
# Cron para actualizar las listas
curl -sf http://<host>:8000/feed/ip/active     > /etc/squid/blocklist-ips.txt
curl -sf http://<host>:8000/feed/domain/active > /etc/squid/blocklist-domains.txt
squid -k reconfigure
```

```squid
acl blocklist_domains dstdomain "/etc/squid/blocklist-domains.txt"
acl blocklist_ips     dst       "/etc/squid/blocklist-ips.txt"
http_access deny blocklist_domains
http_access deny blocklist_ips
```

---

## nginx — geo block

```bash
# Generar mapa desde la feed
curl -sf http://<host>:8000/feed/ip/active | awk '{print $1" 1;"}' > /etc/nginx/blocklist.conf
```

```nginx
geo $blocked {
    default 0;
    include /etc/nginx/blocklist.conf;
}
server {
    if ($blocked) { return 403; }
}
```

---

## Recomendaciones generales

- Exponer el servicio detrás de **nginx con TLS** — ver [deploy.md](deploy.md)
- Restringir acceso a los feeds **solo a las IPs de los firewalls** mediante allowlist en nginx
- Un solo servicio puede alimentar múltiples firewalls simultáneamente
- Refresh recomendado: **5 minutos** para respuesta rápida, **30 minutos** para operación normal
