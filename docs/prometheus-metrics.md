# Prometheus Metrics & Grafana Dashboards

There are two ways to scrape metrics depending on how you have deployed the
policy engine:

- **Standalone** — Prometheus scrapes each engine node directly.  Simple to
  set up but requires manually adding every node to the scrape config.
- **Fleet (via controller)** — Prometheus scrapes only the controller, which
  aggregates metrics from all nodes and injects a `node_id` label on every
  series.  New nodes appear automatically; no changes to Prometheus config are
  needed when nodes are added or removed.  The controller also exposes its own
  `fleet_*` metrics covering node state, rule counts, certificate expiry, and
  online/offline status.

Both modes can run simultaneously if you want per-node direct scrapes alongside
the fleet view.

---

## Installing Prometheus & Grafana

### Debian / Ubuntu

```bash
# Prometheus
sudo apt install prometheus

# Grafana (from Grafana APT repo — https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/)
sudo apt install -y apt-transport-https software-properties-common wget
sudo mkdir -p /etc/apt/keyrings
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update
sudo apt install grafana
```

Start and enable both services:

```bash
sudo systemctl enable --now prometheus
sudo systemctl enable --now grafana-server
```

Grafana is available at `http://<host>:3000`.  Default credentials are
`admin` / `admin`; you will be prompted to change the password on first login.

---

## Prometheus configuration

Edit `/etc/prometheus/prometheus.yml`.  Add one or both of the scrape jobs
below depending on your deployment mode, then reload Prometheus:

```bash
sudo systemctl reload prometheus
```

### Standalone — scrape each engine node directly

```yaml
scrape_configs:
  - job_name: policy_engine
    static_configs:
      - targets:
        - node1.example.com:8080
        - node2.example.com:8080
    # If Bearer token auth is enabled on the engine:
    # authorization:
    #   type: Bearer
    #   credentials: <your-token>
```

Each node is identified in Grafana by the `instance` label
(`node1.example.com:8080`, etc.).

### Fleet — scrape the controller

> **Tip:** the controller web UI can generate this snippet for you. On the
> **Fleet** page, click the **Prometheus** button (beside **Fleet Rule**). It
> pre-fills the scrape target with the address you used to reach the UI (and
> sets `scheme: https` when appropriate), then offers the ready-to-paste config
> with a copy button.

```yaml
scrape_configs:
  - job_name: policy_controller
    static_configs:
      - targets:
        - controller.example.com:8443
```

The controller's `/metrics` endpoint returns:

- All engine metrics from every connected node, with `node_id` and `hostname`
  labels injected on every series.
- `fleet_*` controller-native metrics (see [Controller metrics](#controller-metrics) below).

No changes to the Prometheus config are needed when nodes join or leave the
fleet.

### Verifying scrapes

Open `http://<prometheus-host>:9090/targets`.  Each job should show state
**UP**.  If a target shows **DOWN**, check that the engine / controller is
running and reachable on the listed address and port.

---

## Grafana configuration

### Add the Prometheus data source

1. Open Grafana → **Connections → Data sources → Add data source**.
2. Choose **Prometheus**.
3. Set **URL** to `http://localhost:9090` (adjust if Prometheus is on a
   different host).
4. Set **Name** to `pe-prometheus` — the supplied dashboards reference this
   name.
5. Click **Save & test**.

### Import the dashboards

Copy the dashboard JSON files to the Grafana dashboard provisioning directory:

```bash
sudo cp grafana/engine-data-plane.json /var/lib/grafana/dashboards/
sudo cp grafana/fleet-data-plane.json /var/lib/grafana/dashboards/
sudo cp grafana/controller-events.json /var/lib/grafana/dashboards/
```

Then tell Grafana to load from that directory.  Create
`/etc/grafana/provisioning/dashboards/policy-engine.yml`:

```yaml
apiVersion: 1
providers:
  - name: policy-engine
    type: file
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
```

Restart Grafana to pick up the provisioning config:

```bash
sudo systemctl restart grafana-server
```

The dashboards then appear automatically.  After the first Prometheus scrape
interval (default 15 s) all panels will show data.

| Dashboard file | Use with | Description |
|---|---|---|
| `engine-data-plane.json` | Standalone mode | Per-node traffic, policy actions, protocol breakdown, latency, QUIC |
| `fleet-data-plane.json` | Fleet mode | Fleet overview, node status, cert expiry, per-node traffic, rule counts |
| `controller-events.json` | Fleet mode | Controller event/alert pipeline (Prometheus) + REST drill-in (requires Infinity plugin) |

See `grafana/README.md` for the full plugin/datasource matrix.

---

## Engine metrics reference

The engine exposes its endpoint at `GET /metrics` (default port `8080`).
All counters are monotonically increasing since daemon start.

### Per-interface traffic

Labels: `interface` (e.g. `eth0`), `direction` (`ingress` | `egress`)

| Metric | Type | Description |
|---|---|---|
| `policy_engine_rx_packets_total` | counter | Packets received |
| `policy_engine_rx_bytes_total` | counter | Bytes received |
| `policy_engine_tx_packets_total` | counter | Packets transmitted |
| `policy_engine_tx_bytes_total` | counter | Bytes transmitted |
| `policy_engine_policy_matches_total` | counter | Packets matched by any policy rule |
| `policy_engine_policy_drops_total` | counter | Packets dropped by policy |
| `policy_engine_policy_pass_total` | counter | Packets explicitly passed by policy |
| `policy_engine_policy_redirects_total` | counter | Packets redirected by policy |
| `policy_engine_verdict_pass_packets_total` | counter | Packets with a final pass verdict |
| `policy_engine_verdict_pass_bytes_total` | counter | Bytes with a final pass verdict |
| `policy_engine_verdict_drop_packets_total` | counter | Packets with a final drop verdict |
| `policy_engine_verdict_drop_bytes_total` | counter | Bytes with a final drop verdict |
| `policy_engine_fib_forwarded_packets_total` | counter | Packets forwarded via FIB lookup |
| `policy_engine_fib_forwarded_bytes_total` | counter | Bytes forwarded via FIB lookup |
| `policy_engine_fib_fallback_packets_total` | counter | Packets falling back from FIB to slow path |
| `policy_engine_parse_errors_total` | counter | Packets that failed BPF header parsing |
| `policy_engine_tail_calls_total` | counter | BPF tail calls executed |
| `policy_engine_bum_packets_total` | counter | Broadcast/unknown-unicast/multicast packets |
| `policy_engine_non_ip_unicast_total` | counter | Non-IP unicast packets |
| `policy_engine_fragments_total` | counter | IP fragments received |
| `policy_engine_inspect_redirects_total` | counter | Packets cloned to Suricata for IPS inspection (suricata feature only) |

### Per-ethertype counters

Labels: `interface`, `direction`, `ethertype` (decimal integer string),
`ethertype_name` (e.g. `IPv4`, `IPv6`, `ARP`)

| Metric | Type | Description |
|---|---|---|
| `policy_engine_ethertype_packets_total` | counter | Packets seen for this ethertype |

Ethertypes with zero counts are omitted.

### Per-rule counters

Labels: `rule_id` (numeric string), `direction` (`ingress` | `egress`)

| Metric | Type | Description |
|---|---|---|
| `policy_engine_rule_packets_total` | counter | Packets matched by this rule |
| `policy_engine_rule_bytes_total` | counter | Bytes matched by this rule |

Rule IDs match the values in the GraphQL `rules` query and the web UI.
Rules with zero matches are omitted.

### Per-L4-protocol counters

Labels: `protocol`, `direction` (`ingress` | `egress`)

| Metric | Type | Description |
|---|---|---|
| `policy_engine_proto_packets_total` | counter | Packets for this L4 protocol |
| `policy_engine_proto_bytes_total` | counter | Bytes for this L4 protocol |

Recognised protocol values: `icmp`, `igmp`, `tcp`, `udp`, `dccp`, `ipv6`,
`rsvp`, `gre`, `esp`, `ah`, `icmpv6`, `eigrp`, `ospf`, `pim`, `vrrp`,
`l2tp`, `sctp`, `other`.  Protocols with zero counts are omitted.

### Per-L3-protocol counters

Labels: `protocol` (`ipv4` | `ipv6` | `arp` | `mpls` | `other`),
`direction` (`ingress` | `egress`)

| Metric | Type | Description |
|---|---|---|
| `policy_engine_l3_proto_packets_total` | counter | Packets for this L3 protocol |
| `policy_engine_l3_proto_bytes_total` | counter | Bytes for this L3 protocol |

### QUIC version counters

Labels: `version` (e.g. `1`, `Q046`)

| Metric | Type | Description |
|---|---|---|
| `policy_engine_quic_packets_total` | counter | Packets for this QUIC version |
| `policy_engine_quic_bytes_total` | counter | Bytes for this QUIC version |

Ingress only; egress always produces empty output.  Versions with zero counts
are omitted.

### Packet processing time

Labels: `direction` (`ingress` | `egress`), `quantile` (`0.5` | `0.9` | `0.99`)

| Metric | Type | Description |
|---|---|---|
| `policy_engine_processing_time_ns` | summary | Processing time percentile (ns) |
| `policy_engine_processing_time_ns_count` | summary | Total packet samples in histogram |

Pre-computed percentiles derived from the 64-bucket log₂ histogram recorded by
the BPF programs.  Values are `NaN` when no samples have been recorded.

### Uptime

| Metric | Type | Description |
|---|---|---|
| `policy_engine_uptime_seconds` | gauge | Seconds since the daemon started |

---

## Controller metrics reference

The controller exposes its endpoint at `GET /metrics` (default port `8443`).
The response contains two sections:

1. **Forwarded engine metrics** — the most recent `/metrics` snapshot from
   every connected node, with `node_id` and `hostname` labels prepended to
   every series.
2. **Fleet metrics** — controller-native state described below.

In fleet mode, the `node_id` label serves the same role as `instance` in
standalone mode: use it to filter panels to a single node.

### Fleet totals

| Metric | Type | Labels | Description |
|---|---|---|---|
| `fleet_nodes_total` | gauge | `status` (`active` \| `pending` \| `decommissioned`) | Number of nodes in each enrollment state |
| `fleet_nodes_online_total` | gauge | — | Number of nodes currently connected to the controller |

### Per-node state

All per-node metrics carry `node_id` (hex fingerprint of the node's public
key) and `hostname` labels.  Only nodes with status `active` are included.

| Metric | Type | Extra labels | Description |
|---|---|---|---|
| `fleet_node_online` | gauge | `label` | `1` if the node is currently connected, `0` if offline |
| `fleet_node_rule_count` | gauge | `label` | Number of rules currently assigned to the node |
| `fleet_node_cert_expiry_seconds` | gauge | — | Unix timestamp of the node's mTLS certificate expiry |
| `fleet_node_last_seen_seconds` | gauge | — | Unix timestamp of the last heartbeat received from the node |
| `fleet_node_info` | gauge (always 1) | `label`, `agent_version`, `os_pretty_name`, `kernel_version`, `tpm_backed` | Static node information; value is always 1 |

#### Useful derived queries

Days until a node's certificate expires:

```promql
(fleet_node_cert_expiry_seconds - time()) / 86400
```

Seconds since a node was last seen:

```promql
time() - fleet_node_last_seen_seconds
```

Number of active nodes that are currently offline:

```promql
fleet_nodes_total{status="active"} - fleet_nodes_online_total
```

---

## Notes

- The engine's `/metrics` endpoint reads live BPF map data on every scrape.
  At high rule counts the per-rule iteration adds a few milliseconds.  A
  15-second scrape interval is a reasonable default.
- Engine counters are stored in BPF per-CPU maps and summed at scrape time.
  They reset to zero on daemon restart or when the `clearAllStats` /
  `clearInterfaceStats` GraphQL mutations are called.
- The controller stores only the most recent metrics snapshot per node.
  Prometheus is responsible for retention and historical queries.
- Interfaces with no programs attached produce no output lines.
- `policy_engine_inspect_redirects_total` is only present in builds compiled
  with the `suricata` feature.
- If Bearer token auth is enabled on the engine (see
  [authentication.md](authentication.md)), add the `authorization` block to
  the Prometheus scrape job for that target.  The controller's `/metrics`
  endpoint does not require authentication.
