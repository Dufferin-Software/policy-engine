# IPFIX Flow Export

IPFIX flow export sends per-flow traffic statistics as RFC 7011 UDP datagrams
to an external collector. This enables visibility into which flows are passing
through the engine, with packet/byte counters and timing, suitable for feeding
into tools like ntopng, Elastic, Grafana, or a custom collector.

Both XDP (ingress) and TC (egress) flows are tracked independently in separate
BPF LRU hash maps.

## Build requirement

IPFIX support is an optional compile-time feature. Build with:

```bash
cargo build --release --features ipfix
```

Without `--features ipfix` the flow cache maps and tail call program are
present in the BPF object but the userspace polling task, GraphQL query/mutation,
and web UI panel are all compiled out. The BPF tail call slot is never populated
so the fail-open path fires and packets continue as normal.

### Debian packaging

Use the `pkg.policy-engine.ipfix` build profile to select the IPFIX-enabled
package. It may be combined with `pkg.policy-engine.suricata`:

```bash
# IPFIX only → produces policy-engine-ipfix_*.deb
DEB_BUILD_PROFILES=pkg.policy-engine.ipfix dpkg-buildpackage -us -uc

# Suricata + IPFIX → produces policy-engine-ips-ipfix_*.deb
DEB_BUILD_PROFILES="pkg.policy-engine.suricata pkg.policy-engine.ipfix" dpkg-buildpackage -us -uc
```

See the [Debian packaging](#debian-packaging) section of `README.md` for the
full matrix of packages and profiles.

## How it works

1. For each packet that completes policy evaluation, `xdp_policy_main` (or
   `xdp_sni_inspect` / `tc_policy_egress`) stores the flow key, packet length,
   matched rule ID, action, and final verdict in the per-CPU scratch map
   (`pkt_scratch` / `tc_pkt_scratch`) and tail-calls
   `xdp_flow_cache_update` / `tc_flow_cache_update` (dispatcher slot 2 / 1).

2. The tail-called program updates an LRU hash map entry for the 5-tuple flow
   key: increments packet/byte counters atomically, updates `last_seen_ns`, or
   inserts a new entry with `first_seen_ns`.

3. A userspace tokio task runs every 10 seconds. It scans both maps for entries
   that have been idle for more than `idle_timeout_s` seconds **or** have been
   active for more than `active_timeout_s` seconds, encodes them as RFC 7011
   IPFIX UDP datagrams, sends them to the configured collector, and deletes the
   exported entries.

4. Two IPFIX templates are used:
   - Template 256: IPv4 flows (src/dst addr, src/dst port, protocol, direction,
     first/last switched, packet count, byte count) — 46 bytes per record.
   - Template 257: IPv6 flows — 70 bytes per record.

   Templates are re-sent every 100 data records or every 60 seconds, whichever
   comes first. Records are batched into ≤1400-byte UDP payloads.

### Tail-call chain (XDP)

```
xdp_policy_main
    └─► xdp_flow_cache_update   (slot 2 — ipfix feature only)
            └─► xdp_fib_dispatch (slot 1 — if FIB forward mode enabled)
```

If the `ipfix` feature is not compiled in, slot 2 is never registered and the
`bpf_tail_call` fails silently — the fail-open `return verdict` immediately
after the call fires instead.

## Configuring a collector via GraphQL

Enable flow export and point it at your collector:

```graphql
mutation {
  configureFlowExport(input: {
    enabled: true
    collectorHost: "192.168.1.100"
    collectorPort: 4739
    idleTimeoutS: 15
    activeTimeoutS: 60
  }) {
    success
    message
  }
}
```

Disable without losing the collector settings:

```graphql
mutation {
  configureFlowExport(input: { enabled: false }) {
    success
    message
  }
}
```

Query current status:

```graphql
query {
  flowExportStatus {
    enabled
    collectorHost
    collectorPort
    idleTimeoutS
    activeTimeoutS
    activeFlowCount
    flowsExportedTotal
  }
}
```

### Input fields

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | Boolean | — | Required. Enable or disable export. |
| `collectorHost` | String | `"127.0.0.1"` | Collector hostname or IP address. |
| `collectorPort` | Int | `4739` | Collector UDP port (IANA assigned for IPFIX). |
| `idleTimeoutS` | Int | `15` | Export a flow after this many seconds of inactivity. |
| `activeTimeoutS` | Int | `60` | Export a long-running flow after this many seconds regardless of activity. |

Omitted optional fields retain their current value.

## Configuring via the web UI

When the server is built with `--features ipfix`, an **IPFIX Flow Export** panel
appears on the Overview page of the web UI. The panel shows:

- Enable/disable toggle
- Collector host:port
- Idle and active timeouts
- Current active flow count (XDP + TC maps combined)
- Total flows exported since the server started

Click **Edit settings →** to update the collector address or timeouts.

## Open-source collectors for testing

Any RFC 7011-compliant IPFIX collector works. Some options:

| Collector | Notes |
|---|---|
| [nfdump / nfcapd](https://github.com/phaag/nfdump) | Mature collector+tools suite; `nfcapd -T all -l /tmp/flows -p 4739` |
| [GoFlow2](https://github.com/netsampler/goflow2) | Go-based, Kafka/stdout output; `goflow2 -transport.file.path /dev/stdout` |
| [pmacct](http://www.pmacct.net/) | Flexible collector with many output backends |
| [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/) | Flow visualisation; listens on UDP 4739 by default |
| [Wireshark](https://www.wireshark.org/) | Capture UDP 4739 and decode with the IPFIX/NetFlow dissector — useful for protocol-level debugging |

Quick test with nfdump:

```bash
# Listen for flows on port 4739, write captures to /tmp/flows/
nfcapd -T all -l /tmp/flows -p 4739 -D

# Enable export pointing at localhost
curl -s -X POST http://127.0.0.1:8080/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"mutation { configureFlowExport(input: {enabled:true, collectorHost:\"127.0.0.1\", collectorPort:4739}) { success message } }"}'

# Send some traffic through the engine, then after ~15s:
nfdump -R /tmp/flows -o long
```

## Visualising flows with the Elastic Stack

The Elastic Stack (Elasticsearch + Logstash + Grafana or Kibana) is a
straightforward way to store and visualise flows. Logstash has a built-in
NetFlow/IPFIX codec that handles RFC 7011 template negotiation automatically,
including the custom template IDs 256 (IPv4) and 257 (IPv6) used by this
engine.

### Stack overview

```
policy-engine → UDP 4739 → Logstash (netflow codec) → Elasticsearch → Grafana / Kibana
```

### 1. Install Elasticsearch and Logstash

Add the Elastic APT repository if not already present:

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | sudo gpg --dearmor -o /usr/share/keyrings/elastic.gpg

echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] \
  https://artifacts.elastic.co/packages/8.x/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update && sudo apt install -y elasticsearch logstash
```

#### Disable security (local installs)

Elasticsearch 8+ enables TLS and authentication by default. For a local
installation disable it in `/etc/elasticsearch/elasticsearch.yml`:

```yaml
xpack.security.enabled: false
xpack.security.http.ssl.enabled: false
```

The installer also stores SSL keystore passwords in the Elasticsearch keystore
that will cause a startup failure if security is disabled while they remain.
Remove them:

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-keystore remove \
  xpack.security.transport.ssl.keystore.secure_password
sudo /usr/share/elasticsearch/bin/elasticsearch-keystore remove \
  xpack.security.transport.ssl.truststore.secure_password
```

#### Cap the JVM heap

Elasticsearch auto-allocates half of system RAM by default. Override this via
a systemd drop-in:

```bash
sudo systemctl edit elasticsearch
```

Add:
```ini
[Service]
Environment=ES_JAVA_OPTS="-Xms512m -Xmx512m"
```

#### Fix data and log directory permissions

The Debian package does not always set ownership correctly:

```bash
sudo chown -R elasticsearch:elasticsearch \
  /usr/share/elasticsearch/data \
  /usr/share/elasticsearch/logs
```

#### Start and verify

```bash
sudo systemctl enable --now elasticsearch
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
```

Expected output includes `"status": "green"` or `"yellow"` (yellow is normal
for a single-node cluster with no replicas).

### 2. Configure Logstash

Create `/etc/logstash/conf.d/ipfix.conf`:

```
input {
  udp {
    port  => 4739
    codec => netflow {
      versions => [10]
    }
  }
}

filter {
  # Tag the direction field for readability in dashboards
  if [netflow][flow_direction] == 0 {
    mutate { add_field => { "direction" => "ingress" } }
  } else if [netflow][flow_direction] == 1 {
    mutate { add_field => { "direction" => "egress" } }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "flows-%{+YYYY.MM.dd}"
  }
}
```

Enable and start Logstash:

```bash
sudo systemctl enable --now logstash
```

Check that Logstash is listening on UDP 4739:

```bash
sudo ss -ulnp | grep 4739
```

### 3. Enable flow export from the policy engine

Point the engine at Logstash:

```graphql
mutation {
  configureFlowExport(input: {
    enabled: true
    collectorHost: "127.0.0.1"
    collectorPort: 4739
    idleTimeoutS: 15
    activeTimeoutS: 60
  }) {
    success
    message
  }
}
```

After 15–60 seconds (depending on traffic and the idle timeout), flows will
start appearing in Elasticsearch. Verify with:

```bash
curl -s "http://localhost:9200/flows-*/_count" | python3 -m json.tool
```

### 4. Key field names in Elasticsearch

The Logstash netflow codec decodes the IPFIX information elements into the
following fields under the `netflow` object:

| IPFIX IE | Elasticsearch field | Description |
|---|---|---|
| IE 8 / 27 | `netflow.ipv4_src_addr` / `netflow.ipv6_src_addr` | Source address |
| IE 12 / 28 | `netflow.ipv4_dst_addr` / `netflow.ipv6_dst_addr` | Destination address |
| IE 7 | `netflow.l4_src_port` | Source port |
| IE 11 | `netflow.l4_dst_port` | Destination port |
| IE 4 | `netflow.protocol` | IP protocol number |
| IE 61 | `netflow.flow_direction` | 0 = ingress, 1 = egress |
| IE 152 | `netflow.flow_start` | Flow start (UTC milliseconds) |
| IE 153 | `netflow.flow_end` | Flow end (UTC milliseconds) |
| IE 2 | `netflow.in_pkts` | Packet count |
| IE 1 | `netflow.in_bytes` | Byte count |

### 5. Grafana datasource

The Elasticsearch datasource is built into Grafana — no plugin required.

Add it via `/etc/grafana/provisioning/datasources/flows.yaml`:

```yaml
apiVersion: 1
datasources:
  - name: Flows
    type: elasticsearch
    access: proxy
    url: http://localhost:9200
    jsonData:
      index: "flows-*"
      timeField: "@timestamp"
      esVersion: "8.0.0"
    editable: false
```

Restart Grafana to pick up the datasource:

```bash
sudo systemctl restart grafana-server
```

#### Import the pre-built dashboard

A ready-to-use dashboard is provided at
`grafana/engine-flows.json`. Import it via the Grafana UI:

1. **Dashboards → Import → Upload JSON file** → select `engine-flows.json`
2. When prompted, map the **Flows** datasource input to the `Flows`
   Elasticsearch datasource configured above.
3. Click **Import**.

The dashboard includes:

| Panel | Description |
|---|---|
| Total flows / bytes / packets | Stat panels for the selected time range |
| Protocol breakdown | Pie chart — TCP / UDP / ICMP / ICMPv6 / other |
| Ingress vs egress bytes | Pie chart by direction |
| Flows per minute | Time series |
| Bytes per minute by direction | Ingress and egress series overlaid |
| Top source IPs by bytes | Table, top 20 |
| Top destination IPs by bytes | Table, top 20 |
| Recent flows | Raw flow table: time, src/dst IP, src/dst port, protocol, direction, bytes, packets |

### 6. Kibana alternative

If Kibana is preferred over Grafana, it auto-discovers the `flows-*` index
pattern and the **Network Traffic** dashboard template populates immediately
from NetFlow/IPFIX data with no further configuration.

```bash
sudo apt install -y kibana
sudo systemctl enable --now kibana
# Kibana available at http://localhost:5601
```

### Troubleshooting

**No documents in Elasticsearch after enabling export**

- Check Logstash is running and owns port 4739: `sudo ss -ulnp | grep 4739`
- Check Logstash logs for decode errors: `sudo journalctl -u logstash -n 50`
- Verify packets are arriving: `sudo tshark -i lo -f "udp port 4739" -c 5`
- Remember flows are only exported after the idle timeout elapses (default 15s
  of inactivity) — generate some traffic then wait.

**Template not yet received**

Logstash buffers data records received before their template and decodes them
once the template arrives. The engine re-sends templates every 60 seconds, so
in the worst case there is a 60-second delay before the first batch of flows
appears.

## Persistence

The flow export configuration (enabled state, collector address, timeouts) is
persisted to `/var/run/policy-engine/flow_export_config.json` on every change
and reloaded on daemon startup. The BPF flow cache maps are pinned at
`/sys/fs/bpf/policy_engine/flow_cache` and `tc_flow_cache` and survive
policy-engine restarts as long as the BPF program version has not changed.

## Clock note

Flow timestamps (`first_seen_ns`, `last_seen_ns`) are recorded with
`bpf_ktime_get_ns()` (CLOCK_MONOTONIC). The userspace exporter converts these
to wall-clock milliseconds using the current monotonic/wall-clock offset at
export time. The resulting IPFIX `flowStartMilliseconds` and
`flowEndMilliseconds` fields are in UTC.
