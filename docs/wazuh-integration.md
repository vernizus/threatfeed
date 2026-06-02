# Integración con Wazuh Active Response

Cuando Wazuh dispara un Active Response de bloqueo, los scripts incluidos notifican automáticamente al Threat Feed Service en paralelo, sin modificar los ARs existentes de los agentes.

## Arquitectura

```
Wazuh detecta ataque
    ├── AR agente: netsh / block-ip-inbound / block-domain  (bloqueo local en Windows)
    └── AR manager: threatfeed-add-ip.sh / threatfeed-add-domain.sh
            ↓
        Threat Feed Service
            ├── IP temporal (1h nivel <14, 24h nivel ≥14) — source: "wazuh-ar"
            └── Dominio permanente — source: "wazuh-ar"
            ↓
        Cada reincidencia incrementa el contador en threat_history
            ↓
        Al llegar a THRESHOLD_PROMOTION → promovido a permanent automáticamente
            ↓
        Firewall recoge el bloqueo en el siguiente refresh
```

Los scripts se ejecutan en el **manager** (`location: server`) — no hay nada que desplegar en los agentes.

---

## Ficheros incluidos

En `docs/examples/wazuh_integration/`:

| Fichero | Descripción |
|---------|-------------|
| `threatfeed-add-ip.sh` | AR para IPs — dispara con grupo `ar_block` |
| `threatfeed-add-domain.sh` | AR para dominios — dispara con grupo `ar_block_domain` |
| `threatfeed_ar_snippet.xml` | Bloque `ossec.conf` listo para pegar en el manager |

---

## Instalación en el Manager

### 1. Copiar los scripts

```bash
cp threatfeed-add-ip.sh     /var/ossec/active-response/bin/
cp threatfeed-add-domain.sh /var/ossec/active-response/bin/

chmod 750 /var/ossec/active-response/bin/threatfeed-add-ip.sh
chmod 750 /var/ossec/active-response/bin/threatfeed-add-domain.sh
chown root:wazuh /var/ossec/active-response/bin/threatfeed-add-ip.sh
chown root:wazuh /var/ossec/active-response/bin/threatfeed-add-domain.sh
```

### 2. Crear el fichero de configuración

```bash
cat > /var/ossec/etc/threatfeed.conf << 'EOF'
THREATFEED_HOST="http://10.0.0.X:8000"
THREATFEED_API_KEY="tu-clave-aqui"

# Ventana de deduplicacion en segundos (default: 300 = 5 minutos).
# Si el mismo elemento se reporta dentro de esta ventana, se ignora.
# Evita que una rafaga de alertas del mismo ataque suba el contador
# varias veces y promueva la IP a permanent en un solo incidente.
# Poner a 0 para desactivar la deduplicacion.
THREATFEED_DEDUP_WINDOW="300"
EOF

chmod 640 /var/ossec/etc/threatfeed.conf
chown root:wazuh /var/ossec/etc/threatfeed.conf
```

### 3. Añadir el snippet al ossec.conf

Copiar el contenido de `threatfeed_ar_snippet.xml` dentro de un bloque `<ossec_config>` del `/var/ossec/etc/ossec.conf` del manager, o incluirlo como fichero separado si el manager usa `<include>`.

```bash
# Verificar sintaxis antes de reiniciar
/var/ossec/bin/wazuh-control configtest
```

### 4. Reiniciar el manager

```bash
systemctl restart wazuh-manager

# Verificar que los nuevos comandos están cargados
grep -A3 "threatfeed" /var/ossec/logs/ossec.log | tail -20
```

---

## Verificación

Forzar un AR de prueba desde la API del manager y revisar el log:

```bash
# Simular un AR manual (ajustar agent_id y srcip)
curl -sk -X PUT "https://localhost:55000/active-response?agents_list=001" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"threatfeed-add-ip", "alert":{"rule":{"id":"109001","level":15},"data":{"srcip":"1.2.3.4"}}}'

# Ver log de Active Response
tail -f /var/ossec/logs/active-responses.log | grep threatfeed
```

Salida esperada:
```
2026/06/02 10:00:00 threatfeed-add-ip: OK: 1.2.3.4 → temporary 24h | ocurrencias=1 | regla=109001
```

Verificar que llegó al Threat Feed:
```bash
curl "http://10.0.0.X:8000/api/feed/lookup?element=1.2.3.4" \
  -H "X-API-Key: tu-clave"
```

---

## Lógica de duración

Igual que los ARs existentes de agente:

| Nivel de alerta | entry_type | duration |
|----------------|------------|---------|
| < 14 | `temporary` | 3 600 s (1 hora) |
| ≥ 14 | `temporary` | 86 400 s (24 horas) |
| ar_block_domain | `permanent` | sin expiración |

Cuando el mismo elemento alcanza `THRESHOLD_PROMOTION` ocurrencias, el Threat Feed lo promueve automáticamente a `permanent` y el firewall lo bloquea indefinidamente.

---

## Campos que extrae cada script

### threatfeed-add-ip.sh — búsqueda de srcip

Prueba estos campos del alert en orden:

1. `data.srcip`
2. `data.src_ip`
3. `data.win.eventdata.sourceIp`
4. `data.agent.ip`

### threatfeed-add-domain.sh — búsqueda de dominio

1. `data.win.eventdata.queryName` ← Sysmon Event ID 22 (DNS)
2. `data.dns.question.name` ← Suricata DNS
3. `data.query`
4. `data.hostname`
5. `data.url` / `data.http.url` ← extrae el host de la URL

Si ningún campo contiene un dominio válido, el script loguea el campo que faltó y sale sin error.

---

## Troubleshooting

### El script no se ejecuta

```bash
ls -lha /var/ossec/active-response/bin/threatfeed-add-*.sh
# Debe ser: -rwxr-x--- root wazuh
```

### HTTP 401 en el log

La `THREATFEED_API_KEY` en `/var/ossec/etc/threatfeed.conf` no coincide con la del servicio.

### "No se encontro srcip"

La regla que disparó el AR no tiene `srcip` en el alert. Revisar el JSON del alert en `/var/ossec/logs/alerts/alerts.json` para identificar el campo correcto y añadirlo al script.

### El servicio no es accesible desde el manager

```bash
curl -sf http://10.0.0.X:8000/health
```

Revisar firewall entre el manager y el host del Threat Feed.
