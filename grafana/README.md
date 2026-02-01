# Grafana dashboards

Importable dashboards for the policy engine + controller. Naming is
**tier-prefixed** so the function is obvious from the filename:

| File | Title | Datasource(s) | What it shows |
|------|-------|---------------|---------------|
| `engine-data-plane.json` | Policy engine — data plane | Prometheus | Single-node BPF/policy metrics (`policy_engine_*`): rx/tx, drops, per-rule stats, processing latency, protocol breakdown. |
| `engine-flows.json` | Policy engine — IPFIX flows | Elasticsearch | IPFIX flow records exported by the engine. Only useful when the engine's IPFIX exporter is wired to an ES sink — see `docs/ipfix-flow-export.md`. |
| `fleet-data-plane.json` | Controller Fleet Overview | Prometheus | Multi-node view of the same `policy_engine_*` metrics, plus controller-side `fleet_*` (enrollment, online status, cert expiry). Filterable by `$hostname`. |
| `controller-events.json` | Controller Fleet — events & alerts | Prometheus **+** Infinity | Top section: controller's event pipeline + alert metrics (`event_*`, `alert_*`). Bottom section: REST drill-in into individual events and alert history via `/api/v1/events*` and `/api/v1/alerts/history`. |

The two data-plane dashboards intentionally cover the same metrics from
different angles: `engine-data-plane.json` is the single-host view (no
`$hostname` selection), `fleet-data-plane.json` is the fleet view (per-node,
federated through the controller).

## Required Grafana plugins

| Dashboard | Plugin | Install |
|-----------|--------|---------|
| `engine-data-plane.json`, `fleet-data-plane.json` | Prometheus (core, pre-installed) | — |
| `engine-flows.json` | Elasticsearch (core, pre-installed) | — |
| `controller-events.json` | [Infinity](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) for the REST drill-in section | `sudo grafana-cli plugins install yesoreyeram-infinity-datasource && sudo systemctl restart grafana-server` |

The Prometheus section of `controller-events.json` works without the Infinity
plugin — only the lower "Drill-in" row will show "Datasource not found" if
Infinity is missing.

## Datasource wiring

**Mark one datasource of each type as default.** The dashboards omit explicit
datasource UIDs and resolve to whichever Prometheus / Infinity / Elasticsearch
datasource is marked **default** in `Connections → Data sources`. (This is what
makes them work under provisioning — Grafana only prompts for substitution
during the interactive Import flow, not when JSON is dropped into
`/var/lib/grafana/dashboards/`.) If panels show "No data," check that the
right datasource is the default for its type.

**Prometheus.** Add as `Connections → Data sources → Prometheus`, URL = your
Prometheus server, **mark as default**. Make sure that Prometheus scrapes both:

- each policy-engine node's `/metrics` endpoint (for `policy_engine_*`), and
- the controller's `/metrics` endpoint (for `fleet_*`, `event_*`, `alert_*`).

Sample scrape stanza in `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: policy-controller
    static_configs:
      - targets: ['controller.internal:8443']  # adjust port to your config
  - job_name: policy-engine
    static_configs:
      - targets:
          - 'node1.internal:9090'
          - 'node2.internal:9090'
```

Verify with `curl -s http://<controller>:8443/metrics | grep -E '^event_|^alert_'`
— if that's empty, no event has flowed through yet and the controller-events
dashboard will show "No data" (Prometheus only creates a series after the first
sample).

**Infinity (for `controller-events.json` only).** Add as `Connections → Data
sources → Infinity`, set **Base URL** to your controller (e.g.
`http://controller.internal:8443`). The dashboard uses relative URLs
(`/api/v1/...`) so the Infinity proxy prepends the base.

**Elasticsearch (for `engine-flows.json` only).** See
`docs/ipfix-flow-export.md` — needs a working ES index that the engine's IPFIX
exporter writes into.

## Importing

`Dashboards → New → Import → Upload JSON file`, then pick datasources at the
prompt. All dashboards expose template variables (e.g. `$tenant`, `$hostname`,
`$action`, `$rule_id`) that you can change without re-importing.

Debian packaging installs `engine-data-plane.json` automatically (see
`debian/rules`); the others are operator-imported.

## Reloading dashboards installed via provisioning

If you copy files to a provisioned directory (typically
`/var/lib/grafana/dashboards`) and they don't show up:

1. Check ownership — they must be readable by the `grafana` user:
   `sudo chown grafana:grafana /var/lib/grafana/dashboards/*.json && sudo chmod 644 /var/lib/grafana/dashboards/*.json`
2. The provisioner rescans every `updateIntervalSeconds` (typically 30 s).
   Bump `mtime` to force a re-detect: `sudo touch /var/lib/grafana/dashboards/*.json`
3. Last resort: `sudo systemctl restart grafana-server` and check
   `journalctl -u grafana-server | grep -iE 'dashboard|provision'`.

## Endpoints used by `controller-events.json`

- `GET /metrics` — Prometheus exposition (event-pipeline + alert metrics).
- `GET /api/v1/events?since&until&action&rule_id&node_id&sport&dport&proto&sni_like&limit&cursor&format=table|logs`
- `GET /api/v1/events/aggregate?group_by=rule_id|action|node_id|src_ip|dst_ip|minute|hour&format=table|timeseries`
- `GET /api/v1/alerts/history?since&until&rule_id&limit&cursor&format=table|annotations|logs`

See `docs/event-pipeline.md` for the wire schema and
`docs/event-pipeline-todo.md` for what's still in flight.
