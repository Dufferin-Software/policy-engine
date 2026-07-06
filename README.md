# Policy Engine

A high-performance XDP/TC packet policy engine for Linux. Rules are expressed as 7-tuples (src/dst IP prefix, src/dst port, protocol, src/dst MAC) with LPM prefix matching. Supports optional Suricata IPS/IDS integration, IPFIX flow export, and a central fleet controller for managing many nodes at scale.

## Documentation

| Document | Description |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full system architecture reference |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Comprehensive user guide |
| [docs/TESTING_WITH_NETSIM.md](docs/TESTING_WITH_NETSIM.md) | Integration test guide (all suites) |
| [docs/tls.md](docs/tls.md) | TLS/HTTPS configuration |
| [docs/authentication.md](docs/authentication.md) | Bearer token authentication |
| [docs/prometheus-metrics.md](docs/prometheus-metrics.md) | Prometheus metrics reference |
| [docs/rule-matching.md](docs/rule-matching.md) | Rule matching reference (LPM, MAC, SNI/QUIC, timed rules) down to the BPF level |
| [docs/xdp-forward-mode.md](docs/xdp-forward-mode.md) | XDP FIB forwarding |
| [docs/ipfix-flow-export.md](docs/ipfix-flow-export.md) | IPFIX flow export |
| [docs/cpu-affinity.md](docs/cpu-affinity.md) | CPU affinity configuration |
| [docs/containers.md](docs/containers.md) | Container deployment guide |
| [docs/controller/retention.md](docs/controller/retention.md) | Controller data retention (events, IDS alerts, alert history) |

## Architecture

```
  policy-controller (optional, fleet management)
       │ gRPC mTLS — port 7777
  policy-node-agent (on each node)
       │ GraphQL localhost
  policy-engine (daemon)
       │ GraphQL over HTTP
  policy-client (CLI)

  ┌────────────────────────┐
  │   BPF Maps             │  XDP (ingress) + TC (egress)
  │   Rules / Stats        │  pinned at /sys/fs/bpf/policy_engine/
  └────────────────────────┘
       │                   │
  XDP ingress          TC egress
  (line-rate drop)     (line-rate drop)

  [policy-engine-ips only]
  XDP ACTION_INSPECT → TC clone-redirect → Suricata → flow verdict cache
```

### Binaries

| Binary | Package | Role |
|---|---|---|
| `policy-engine` | policy-engine | GraphQL daemon — manages BPF programs, exposes API |
| `policy-client` | policy-engine-client | CLI client — talks to a running daemon over GraphQL |
| `policy-controller` | policy-controller | Fleet controller — CA, enrollment, ruleset distribution |
| `policy-controller-client` | policy-controller-client | CLI for the controller operator API |
| `policy-node-agent` | policy-node-agent | Fleet agent — bridges controller to local policy-engine |

## Dependencies

**Runtime**

| Package | Notes |
|---|---|
| `libbpf1` | BPF map/program loader |
| `suricata` | IPS/IDS only (`policy-engine-ips`) |

**Build**

```
cargo rustc llvm clang libbpf-dev linux-headers-$(uname -r)
```

## Building from source

```bash
# Base (no IPS/IDS, no IPFIX)
cargo build --release --workspace

# With Suricata IPS/IDS support
cargo build --release --workspace --features suricata

# With IPFIX flow export support
cargo build --release --workspace --features ipfix

# All features
cargo build --release --workspace --features suricata,ipfix

# Tests (no root or BPF required — uses mocks)
cargo test --release --workspace
cargo test --release --workspace --features suricata
cargo test --release --workspace --features ipfix

# Lint
make lint
```

## Debian packaging

Four binary packages are produced from a single source tree, selected by
combining two independent build profiles:

| Build profiles | Package produced | Cargo features |
|---|---|---|
| _(none)_ | `policy-engine` | _(none)_ |
| `pkg.policy-engine.suricata` | `policy-engine-ips` | `suricata` |
| `pkg.policy-engine.ipfix` | `policy-engine-ipfix` | `ipfix` |
| `pkg.policy-engine.suricata pkg.policy-engine.ipfix` | `policy-engine-ips-ipfix` | `suricata,ipfix` |

All variants produce `policy-engine-client_*.deb` (the CLI client) and
`policy-engine-client-dev_*.deb` (the Rust client library) as independent side packages.

**Base — `policy-engine`**

```bash
dpkg-buildpackage -us -uc
```

**Suricata IPS/IDS — `policy-engine-ips`**

```bash
DEB_BUILD_PROFILES=pkg.policy-engine.suricata dpkg-buildpackage -us -uc
```

**IPFIX flow export — `policy-engine-ipfix`**

```bash
DEB_BUILD_PROFILES=pkg.policy-engine.ipfix dpkg-buildpackage -us -uc
```

**Suricata + IPFIX — `policy-engine-ips-ipfix`**

```bash
DEB_BUILD_PROFILES="pkg.policy-engine.suricata pkg.policy-engine.ipfix" dpkg-buildpackage -us -uc
```

**Installing**

```bash
sudo dpkg -i policy-engine*.deb
```

Only one server package may be installed at a time; all variants
`Provides: policy-engine` and `Conflicts:` with the others.

The systemd service starts automatically on install. The Suricata service is
stopped and disabled until IPS/IDS mode is explicitly enabled via
`configureInspect`. IPFIX export is disabled by default; enable it via
`configureFlowExport`.

## Fleet management quick start

Deploy a central controller that distributes rulesets to a fleet of nodes:

```bash
# On the controller VM
sudo dpkg -i policy-controller_*.deb policy-controller-client_*.deb
sudo systemctl enable --now policy-controller

# On each managed node (copy CA cert from controller first)
sudo cat /var/lib/policy-controller/ca.crt   # on controller
# Paste into /etc/policy-node-agent/controller-ca.crt on node

sudo dpkg -i policy-engine_*.deb policy-node-agent_*.deb
# Configure /etc/policy-node-agent/config.toml:
#   enrollment_url = "https://controller:7776"
#   controller_url = "https://controller:7777"
sudo systemctl enable --now policy-engine policy-node-agent

# On controller: approve incoming enrollment requests
policy-controller-client nodes list --status pending
policy-controller-client nodes approve <node_id> --label "edge-01"

# Create and push a ruleset
policy-controller-client rulesets create --name "baseline" \
  --rules-json '[{"direction":"INGRESS","src":"0.0.0.0/0","dst":"0.0.0.0/0",
    "sport":0,"dport":22,"protocol":"tcp",
    "actions":[{"action":"DROP","priority":0,"param":0}]}]'
policy-controller-client rulesets assign <node_id> <ruleset_id>
policy-controller-client nodes push-all
```

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for the complete fleet management guide.

## Quick start

```bash
# Check daemon is running
policy-client status

# Attach XDP to an interface
policy-client attach ingress --interface eth0 --mode native

# Attach TC egress
policy-client attach egress --interface eth0

# Drop all traffic from a host
policy-client rule add --direction ingress \
    --src 198.51.100.1 --action drop:0

# Allow established TCP to port 443, log everything else
policy-client rule add --direction ingress \
    --dst 10.0.0.1 --dport 443 --proto tcp --action pass:0
policy-client rule add --direction ingress --action log:1

# Show rules and stats
policy-client rule list --direction ingress
policy-client show stats --interface eth0 --direction ingress
```

The GraphQL Playground is available at `http://127.0.0.1:8080/playground` (or `https://...:8443/playground` if TLS is configured).

## Monitoring

Prometheus metrics are exposed at `GET /metrics` with no extra configuration.
A Grafana dashboard is included in the package at
`/usr/share/policy-engine/grafana/`.

See [docs/prometheus-metrics.md](docs/prometheus-metrics.md) for the full
metrics reference and Grafana setup instructions.

## TLS / HTTPS

TLS is opt-in and native (rustls — no OpenSSL).  Configure via the config file
or CLI flags:

```toml
# /etc/policy-engine/config.toml
[server]
port     = 8443
tls_cert = "/etc/policy-engine/server.crt"
tls_key  = "/etc/policy-engine/server.key"
```

```bash
# CLI override
policy-engine --tls-cert /etc/policy-engine/server.crt \
              --tls-key  /etc/policy-engine/server.key

# Client with CA cert
policy-client --server https://host:8443/graphql \
              --tls-ca-cert /etc/policy-engine/ca.crt status

# Client skip verification (dev only)
policy-client --server https://127.0.0.1:8443/graphql \
              --tls-insecure status
```

The WebSocket endpoints (`/ws/events`, `/ws/rule-events`) and Web UI are
served over the same TLS port.  The Web UI auto-selects `wss://` when loaded
over HTTPS.

See [docs/tls.md](docs/tls.md) for certificate generation and full reference.

## Authentication

By default the API is unauthenticated (suitable for `127.0.0.1` deployments).
Set `POLICY_ENGINE_API_TOKEN` to enable Bearer token auth on all endpoints
including `/metrics`.

See [docs/authentication.md](docs/authentication.md) for details.

## Audit log

Every GraphQL mutation is written to an append-only audit log at
`/var/log/policy-engine/audit.log`.

See [docs/audit-log.md](docs/audit-log.md) for format and rotation.

## Timed rules

Rules can be given a lifecycle constraint: a **TTL** (auto-remove after N
seconds) or a **weekly schedule** (active only during recurring time windows).
The scheduler processes state changes every 30 seconds.

```bash
# Drop traffic from a host for one hour
policy-client rule add --direction ingress \
    --src 198.51.100.1/32 --action drop:0 \
    --expires-after-secs 3600

# Block a subnet on weekdays 09:00–17:00 Eastern Time
policy-client rule add --direction ingress \
    --src 10.0.0.0/8 --action drop:0 \
    --schedule-window 1:09:00-5:17:00 \
    --schedule-tz "America/Toronto"

# List managed (TTL/scheduled) rules
policy-client rule managed-rules --direction ingress
```

Every state change (activated, deactivated, expired, deleted) is broadcast as
a JSON event over the WebSocket endpoint `GET /ws/rule-events`.

See [docs/rule-matching.md § Timed rules](docs/rule-matching.md#timed-rules) for the full reference.

## XDP Forward Mode

When enabled, transit packets that pass policy are forwarded at line rate via
a kernel FIB lookup inside the XDP program — L2 headers rewritten, TTL
decremented, redirected with `bpf_redirect()` without entering the kernel
network stack. Falls back to normal kernel forwarding if ARP is unresolved.

See [docs/xdp-forward-mode.md](docs/xdp-forward-mode.md) for details.

## IPFIX flow export

When built with `--features ipfix`, the engine exports per-flow statistics
as RFC 7011 IPFIX UDP datagrams to any compatible collector (ntopng, nfdump,
GoFlow2, Elastic, etc.). The collector address and timeouts are configurable
at runtime via GraphQL or the web UI.

See [docs/ipfix-flow-export.md](docs/ipfix-flow-export.md) for details.

## MAC address matching

Rules can filter on Layer 2 source and/or destination MAC addresses in addition
to the IP 5-tuple, giving full 7-tuple matching. MAC fields are optional —
omitting them matches any MAC (wildcard). The IP LPM lookup still applies; use
`0.0.0.0/0` as src/dst if the MAC is the only criterion.

```bash
# Drop inbound traffic from a specific NIC
policy-client rule add --direction ingress \
    --src 0.0.0.0/0 --action drop:0 \
    --src-mac aa:bb:cc:dd:ee:ff

# Drop inbound traffic to a specific NIC
policy-client rule add --direction ingress \
    --action drop:0 \
    --dst-mac 11:22:33:44:55:66

# Combine both — rule fires only when both MACs match
policy-client rule add --direction ingress \
    --src 10.0.0.0/8 --action drop:0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --dst-mac 11:22:33:44:55:66
```

See [docs/rule-matching.md § MAC matching](docs/rule-matching.md#mac-matching) for the full reference.

## CPU affinity

Control-plane threads and ring-buffer pollers can be pinned to dedicated cores
to avoid competing with XDP/TC dataplane processing.

See [docs/cpu-affinity.md](docs/cpu-affinity.md) for configuration.

## License

Rust and web code: [GPL-2.0-or-later](LICENSE).
BPF programs (`src/bpf/`): GPL-2.0-only.
