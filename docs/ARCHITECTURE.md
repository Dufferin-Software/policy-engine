# Policy Engine — Architecture Reference

## System Overview

The policy engine is a high-performance XDP/TC packet policy enforcement system built on Linux eBPF. It provides line-rate packet classification and enforcement directly in the kernel data path, with a GraphQL control plane and optional fleet management via a central controller.

```
┌─────────────────────────────────────────────────────────────────┐
│  policy-controller  (optional, central fleet management)        │
│  ┌──────────────────┐    ┌──────────────────────────────────┐  │
│  │ Operator API     │    │ NodeManagementService (gRPC)     │  │
│  │ GraphQL / HTTP   │    │ mTLS, port 7777                  │  │
│  │ port 8443        │    ├──────────────────────────────────┤  │
│  │ WebSocket events │    │ EnrollmentService (gRPC)         │  │
│  │ Prometheus /mtrc │    │ TLS, port 7776                   │  │
│  └──────────────────┘    └──────────────────────────────────┘  │
└─────────────────────────────────────────────┬───────────────────┘
                                              │ mTLS gRPC (agent-initiated)
┌─────────────────────────────────────────────┼───────────────────┐
│  policy-node-agent  (on each managed node)  │                   │
│  ┌────────────────────────────────────────────────────────┐    │
│  │ gRPC bidirectional stream to controller                │    │
│  │ Enrollment → mTLS management → ConfigPush/StateQuery   │    │
│  └──────────────┬─────────────────────────────────────────┘    │
└─────────────────┼──────────────────────────────────────────────┘
                  │ HTTP localhost:8080/graphql
┌─────────────────┼──────────────────────────────────────────────┐
│  policy-engine  │ (standalone or agent-managed)                │
│  ┌──────────────▼──────────┐  ┌────────────────────────────┐  │
│  │ GraphQL API (actix-web) │  │ BPF Manager (libbpf-rs)    │  │
│  │ port 8080               │  │ XDP programs (ingress)     │  │
│  │ WebSocket events        │  │ TC programs  (egress)      │  │
│  │ Prometheus /metrics     │  │ Pinned maps                │  │
│  └─────────────────────────┘  └────────────────────────────┘  │
│                                                                 │
│  Optional:  ┌─────────────────┐  ┌──────────────────────────┐ │
│  IPS/IDS    │ Suricata        │  │ IPFIX Exporter           │ │
│             │ AF-XDP, EVE     │  │ RFC 7011 flow records    │ │
│             │ IPS/IDS verdicts│  │ to external collector    │ │
│             └─────────────────┘  └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Binaries and Packages

### policy-engine (core)

The enforcement daemon. Loads XDP and TC eBPF programs, manages BPF maps, and exposes a GraphQL control plane.

- **Binary:** `policy-engine`
- **Config:** `/etc/policy-engine/config.toml`
- **State:** `/var/lib/policy-engine/state.json`
- **BPF pin:** `/sys/fs/bpf/policy_engine/`
- **Ports:** 8080 (HTTP/GraphQL), optionally 8443 with TLS
- **Capabilities:** `CAP_BPF`, `CAP_NET_ADMIN`

### policy-client

CLI client for the policy-engine GraphQL API. Bundled with the engine package.

### policy-engine-web

React + TypeScript + Apollo Client web dashboard served by policy-engine at `/`.

### policy-controller

Central fleet management daemon. Manages a fleet of policy-engine nodes: certificate authority, enrollment, ruleset distribution, metrics aggregation.

- **Binary:** `policy-controller`
- **Config:** `/etc/policy-controller/config.toml`
- **Database:** `/var/lib/policy-controller/controller.db` (SQLite)
- **CA data:** `/var/lib/policy-controller/ca.key`, `/var/lib/policy-controller/ca.crt`
- **Ports:** 8443 (HTTP/operator API), 7776 (gRPC enrollment, TLS), 7777 (gRPC management, mTLS)

### policy-controller-client

CLI client for the policy-controller operator API.

### policy-controller-web

React + TypeScript + Apollo Client fleet dashboard served by policy-controller.

### policy-node-agent

Fleet management agent. Runs alongside policy-engine on each managed node, bridging the controller's gRPC management stream to the local GraphQL API.

- **Binary:** `policy-node-agent`
- **Config:** `/etc/policy-node-agent/config.toml`
- **Identity key:** `/var/lib/policy-node-agent/identity.key` (ECDSA P-256, auto-generated; TPM-backed when `/dev/tpmrm0` is usable)
- **Client cert / key:** `/var/lib/policy-node-agent/controller-client.{crt,key}` (issued by controller CA on enrollment)
- **CA cert:** `/var/lib/policy-node-agent/controller-ca.crt` (delivered by the controller in the enrollment response; trust is bootstrapped by SHA-256 pin from the ZTP bundle)
- **Bootstrap bundle:** `/etc/policy-node-agent/bootstrap.bundle` (operator-supplied ZTP token, consumed and deleted on first enrollment)
- **Endpoints cache:** `/var/lib/policy-node-agent/endpoints.json` (controller/enrollment URLs learned from the bundle, persisted so the agent can recover after the bundle is gone)

---

## Debian Package Matrix

Four mutually-exclusive server packages select optional features at build time:

| Package | Suricata IPS/IDS | IPFIX Export |
|---------|:----------------:|:------------:|
| `policy-engine` | — | — |
| `policy-engine-ips` | yes | — |
| `policy-engine-ipfix` | — | yes |
| `policy-engine-ips-ipfix` | yes | yes |

Side packages (combine with any server package):

| Package | Purpose |
|---------|---------|
| `policy-engine-web` | React web UI |
| `policy-engine-client-dev` | Rust client library |
| `policy-controller` | Fleet controller daemon |
| `policy-controller-client` | Controller CLI |
| `policy-controller-web` | Fleet dashboard web UI |
| `policy-node-agent` | Node fleet agent |

---

## BPF Data Plane

Two programs run in the kernel fast path:

**XDP (ingress):** `xdp_policy_main` — attached to the network interface receive path via XDP hook. Processes packets before the kernel networking stack. Returns `XDP_PASS`, `XDP_DROP`, or `XDP_REDIRECT`.

**TC egress:** `tc_policy_main` — attached to the TC (Traffic Control) subsystem on the transmit side. Returns `TC_ACT_OK` (pass) or `TC_ACT_SHOT` (drop).

Both programs use a **tail call dispatcher** to offload optional processing (SNI inspection, QUIC mirroring, FIB forwarding) to separate programs, staying within the BPF verifier's 1M processed-instruction limit.

How packets are matched against rules — the processing pipeline, the two-level LPM trie, tail-call slots, action loop, BPF map constants, and the MAC/SNI/QUIC matchers — is documented in full in [rule-matching.md](rule-matching.md).

### BPF Map Lifecycle

Maps are pinned to `/sys/fs/bpf/policy_engine/`. On daemon startup:

1. Compute hash of embedded XDP+TC skeleton bytes.
2. Compare against `/var/run/policy_engine/.bpf_version`.
3. **Same hash:** Reuse pinned maps, auto-attach programs. State is already in the kernel — no restore needed.
4. **Different hash (upgrade):** Detach our programs from tracked interfaces, clean pin directory, then call `restore_from_store()`.
5. **After reboot:** BPF filesystem is tmpfs (maps gone). `restore_from_store()` re-attaches interfaces and re-applies rules from `state.json`.

The daemon only ever detaches programs from interfaces it owns (tracked via metadata files in `/var/run/policy_engine/`), never disturbing other XDP tools.

---

## Rules, Actions, and Matching

Rules match on any combination of source/destination IP prefix (LPM), ports, protocol, TLS SNI, QUIC version, and source/destination MAC, with up to four prioritised actions each (`PASS`, `DROP`, `LOG`, `INSPECT`; DROP is terminal). The full match-dimension reference, action loop semantics, and protocol-specific matchers are in [rule-matching.md](rule-matching.md). Rules may also carry a TTL or weekly schedule (see [rule-matching.md § Timed rules](rule-matching.md#timed-rules)).

---

## State Persistence

Rule state is persisted to `/var/lib/policy-engine/state.json` using atomic writes (write `.tmp` → `rename`). The `StateStore` trait abstracts the backing store:

- **`FileStateStore`**: Production. Maintains in-memory `Mutex<PersistedState>` and writes the full JSON file on every mutation.
- **`InMemoryStateStore`**: Tests only. No I/O.

`restore_from_store()` replays: attachments first (loads BPF programs, marks interfaces), then default actions, then rules. Per-entry errors are logged as warnings and skipped to avoid one bad rule blocking the rest.

---

## Suricata IPS/IDS Integration

Requires `policy-engine-ips` or `policy-engine-ips-ipfix` package.

### Architecture

```
NIC (ingress)
    │ XDP: ACTION_INSPECT
    │ → writes flow to flows_to_inspect (5-min TTL)
    │ → seeds PASS in flow_verdict_cache (30s TTL)
    │ → returns XDP_PASS (original reaches application)
    │
    ▼ TC ingress (on same interface)
    │ reads flows_to_inspect
    │ bpf_clone_redirect(ctx, pe-inspect0-ifindex, 0)
    │
    ▼ pe-inspect0 veth ──────────────────────▶ pe-inspect1
                                                    │
                                               Suricata (AF-XDP)
                                               reads full TCP stream
                                               matches alert signatures
                                                    │ EVE UNIX socket
                                                    ▼
                                               EveConsumer (Rust)
                                               writes DROP to flow_verdict_cache
                                               for BOTH directions:
                                               client→server AND server→client
                                                    │
    Next packet on flow ──────────────────────▶ XDP: flow_verdict_cache hit
                                               verdict=DROP → XDP_DROP
                                               (line-rate, no Suricata involved)
```

### Modes

- **IPS:** Suricata alerts cause permanent DROP verdicts written to the flow cache. All subsequent packets on the matching flow are dropped at XDP speed.
- **IDS:** Suricata alerts are logged but no DROP verdicts are written. Traffic is never blocked.

### Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `INSPECT_PASS_VERDICT_TTL_NS` | 30s | Initial PASS verdict TTL in verdict cache |
| `INSPECT_CLONE_TTL_NS` | 5min | Flow entry TTL in flows_to_inspect |

---

## IPFIX Flow Export

Requires `policy-engine-ipfix` or `policy-engine-ips-ipfix` package.

The XDP and TC programs maintain a `flow_cache` LRU hash map (65536 entries per direction). Each 5-tuple flow is tracked with byte/packet counters and first/last seen timestamps.

The IPFIX exporter (userspace) periodically reads the flow cache and emits RFC 7011 flow records to a configured UDP collector. Idle timeout and active timeout are configurable.

---

## XDP FIB Forwarding

When enabled, matched packets that would otherwise `XDP_PASS` are instead forwarded at line rate via `bpf_fib_lookup()`. The XDP program:

1. Looks up the routing table via `bpf_fib_lookup()`.
2. Rewrites L2 source and destination MAC addresses.
3. Decrements IPv4 TTL / IPv6 Hop Limit.
4. Returns `XDP_REDIRECT` to the output interface.

Failures fall open to `XDP_PASS` (kernel routing takes over). This is useful for policy-engine nodes acting as transit routers.

---

## uRPF (Unicast Reverse Path Forwarding)

When enabled on an **ingress** interface, the XDP program checks each packet's
*source* address against the FIB via `bpf_fib_lookup()` before policy evaluation
and drops source-spoofed traffic at line rate:

- **loose** — drop only if no route to the source exists via any interface.
- **strict** — drop unless the route back to the source exits via the interface
  the packet arrived on.

uRPF is ingress-only (it is never applied on the TC egress path) and shares the
per-interface `fib_config_map` entry with XDP FIB forwarding, so one map lookup
covers both features. Drops are counted per interface (`urpf_drop_packets` /
`urpf_drop_bytes`). Full design in [urpf.md](urpf.md).

---

## Fleet Controller Architecture

### Certificate Authority

The controller generates a self-signed ECDSA P-384 CA on first run:

```
Controller CA (P-384, self-signed, 10yr)
  /var/lib/policy-controller/ca.key   (0600)
  /var/lib/policy-controller/ca.crt   (distributed to agents)
      │
      ├── Controller gRPC server cert (1yr, includes DNS SAN)
      └── Node client certs (90d default, CommonName = node_id)
```

Node IDs are `hex(SHA-256(public_key_DER))` — stable across hostname changes.

Revoked certificate serials are mirrored from SQLite into an in-memory
`HashSet` (kept in sync via a tokio `watch` channel updated by the node
registry) and consulted by a custom `rustls` `ClientCertVerifier` that
rejects revoked serials *during* the TLS handshake. An application-layer
check after `AgentHello` stays as defense in depth.

### Enrollment Protocol (ZTP, token-based auto-approval)

Enrollment is zero-touch. The operator mints a short-lived **bootstrap bundle**
(URL + CA SHA-256 pin + random token, scoped by TTL / max-uses / optional CIDR)
and distributes the same file to every target host via their existing config
management. The agent reads the bundle on first boot, presents the token, and
the controller auto-approves and returns the per-node mTLS credentials in the
*same* response — no operator click, no polling. See [ztp.md](ztp.md) and
[enrollment-crypto.md](enrollment-crypto.md) for the full security model.

```
Operator workstation                  Controller                    Agent (first boot)
────────────────────                  ──────────                    ──────────────────
1. enroll-token create  ───────────▶  2. Persist token in            (not yet running)
   --ttl --max-uses --cidr               enrollment_tokens; emit
                                         base64 bundle (one-shot).

3. Distribute bundle to fleet
   (Ansible/Puppet/cloud-init)
   → /etc/policy-node-agent/
       bootstrap.bundle (0600)

                                                                     4. Generate identity key
                                                                        (TPM or P-256 file).
                                                                        node_id = hex(SHA-256(SPKI)).

                                                                     5. Read bundle. Open TLS to
                                                                        enrollment_url, pinning the
                                                                        controller CA by SHA-256
                                                                        fingerprint (custom rustls
                                                                        ServerCertVerifier).

                                      6. Verify PoP signature, ◀───  EnrollmentRequest {
                                         redeem bootstrap_token        public_key_der,
                                         atomically (uses_remaining    csr_pem,
                                         --), auto-approve, sign       signature(identity_key,
                                         client cert (P-256, 90d).                SHA-256(csr_pem)),
                                                                       dmi_uuid, hostname,
                                                                       bootstrap_token }
                                      7. EnrollmentResponse {  ─────▶ 8. Persist
                                         status=APPROVED,                controller-client.{key,crt}
                                         key_pem, cert_pem,               and controller-ca.crt under
                                         ca_cert_pem }                    /var/lib/policy-node-agent/.
                                                                          Delete bootstrap.bundle.

                                                                     9. Connect to management gRPC
                                                                        (mTLS, port 7777). Send
                                                                        AgentHello + StateSnapshot.
```

A request with an invalid/expired/exhausted token still creates a `Pending`
record for operator triage (`approveEnrollment` / `rejectEnrollment`); the
normal flow never touches that path.

### Token-redemption safety

- The bundle's CA fingerprint pin defeats MITM against the enrollment leg —
  a rogue server without the controller's actual CA cert cannot complete the
  TLS handshake, so the token is never sent over the wire.
- The token is consumed at first use; `--max-uses` caps blast radius. Lost
  bundles are revoked with `enroll-token revoke`.
- The bundle is deleted after a successful enrollment, so a node that is
  re-imaged starts clean and requires a fresh bundle.

### Credential rotation

The mTLS client cert is renewed by the agent on the management channel
at ~2/3 of its TTL (≈60d for the 90d default) via `RenewClientCert(csr_pem)`.
The client *key* is rotated every Nth renewal (`mtls_key_rotation_renewals`,
default 4 → fresh key roughly every 240d); intermediate renewals reuse the
existing key. The controller revokes the old cert serial as part of the
handoff. The agent identity key is **never** rotated — it anchors the
node_id. Full design in [enrollment-crypto.md](enrollment-crypto.md) Phase 7.

### gRPC Stream Protocol

**Agent → Controller:**

| Message | Description |
|---------|-------------|
| `AgentHello` | First message: node_id, agent_version, protocol_version |
| `Heartbeat` | Liveness ping every 30s |
| `StateSnapshot` | Current rules, attachments, default actions (on connect + on demand) |
| `MetricsUpdate` | Scraped Prometheus text from local `/metrics` (every 30s) |
| `EventBatch` | BPF events forwarded from local WebSocket stream |
| `ConfigApplyResult` | Success/failure after a ConfigPush |

**Controller → Agent:**

| Message | Description |
|---------|-------------|
| `ConfigPush` | Desired ruleset to apply |
| `StateQuery` | Request a fresh StateSnapshot |
| `Disconnect` | Graceful shutdown signal |

### Reconciliation

On controller restart:

1. Load all active nodes from SQLite.
2. Mark all as offline in memory (SQLite unchanged).
3. Agents reconnect and send `StateSnapshot`.
4. Controller diffs snapshot against assigned ruleset.
5. If delta → send `ConfigPush` with full desired state.
6. Nodes that don't reconnect keep enforcing their last applied rules.

The policy-engine and its BPF programs are entirely independent of the controller — an agent or controller outage has zero impact on enforcement.

### Controller State (SQLite)

Schema lives in `fleet/controller/migrations/0001_initial.sql`. Key tables:

| Table | Purpose |
|-------|---------|
| `nodes` | Node registry (id, label, status, hostname, tenant, last_seen) |
| `node_certs` | Issued mTLS client certs (serial, not_before, not_after, key_pem, cert_pem) |
| `node_interfaces` | Per-node discovered interfaces (used for rule validation) |
| `rules` | Per-node / per-interface / per-direction rules (replaces the old `rulesets` model) |
| `revoked_certs` | Revoked certificate serials (mirrored to in-memory verifier) |
| `enrollment_tokens` | ZTP bootstrap tokens (token_id, hashed_secret, TTL, max_uses, uses_remaining, CIDR scope, fleet label) |
| `api_tokens` | Operator API bearer tokens for the controller GraphQL endpoint |
| `operators` | Operator accounts and roles |
| `tenants` | Multi-tenant scoping for nodes / rules / events |
| `audit_log` | Append-only mutation log |
| `events` | Persisted BPF events forwarded by agents |
| `alert_rules`, `receivers`, `silences`, `alert_history` | Alerting subsystem |

---

## HTTP Endpoints

### policy-engine

| Method | Path | Description |
|--------|------|-------------|
| POST | `/graphql` | GraphQL API |
| GET | `/playground` | GraphQL Playground |
| GET | `/ws/events` | WebSocket BPF event stream |
| GET | `/metrics` | Prometheus metrics |
| GET | `/` | Web UI (if `policy-engine-web` installed) |

### policy-controller

| Method | Path | Description |
|--------|------|-------------|
| POST | `/graphql` | Operator GraphQL API |
| GET | `/playground` | GraphQL Playground |
| GET | `/health` | Health check (`{"status":"ok"}`) |
| GET | `/ws/events[?node=<id>]` | WebSocket BPF event stream (all nodes or filtered) |
| GET | `/metrics` | Aggregated Prometheus (all nodes) |
| GET | `/metrics/node/<id>` | Per-node Prometheus metrics |
| GET | `/` | Fleet web UI (if `policy-controller-web` installed) |

---

## Security Model

| Connection | Authentication | TLS |
|------------|----------------|-----|
| Operator → policy-engine API | Bearer token (`POLICY_ENGINE_API_TOKEN` env) | Optional (TLS cert/key config) |
| Agent → controller enrollment | CSR signed by node keypair | TLS (agent trusts controller CA) |
| Agent → controller management | mTLS client cert (issued by controller CA) | mTLS |
| Operator → controller API | _(token auth planned)_ | TLS (same CA) |
| Agent → local policy-engine | None (localhost only) | None |

---

## Configuration Reference

### policy-engine: `/etc/policy-engine/config.toml`

```toml
[server]
host = "127.0.0.1"          # bind address
port = 8080                  # HTTP port
tls_cert = "/etc/policy-engine/server.crt"   # optional TLS
tls_key  = "/etc/policy-engine/server.key"
web_root = "/usr/share/policy-engine-web"    # optional; serves React UI

[affinity]
disabled = false
control_cpus    = [0]        # GraphQL / control thread CPUs
event_cpus      = [1]        # BPF ring buffer polling CPUs
dataplane_cpus  = [2, 3]     # Packet processing CPUs
actix_workers   = 2          # HTTP worker threads
```

Environment variables:
- `POLICY_ENGINE_API_TOKEN` — Bearer token (all endpoints require this if set)
- `RUST_LOG` — Log filter (default: `policy_engine=info`)

### policy-controller: `/etc/policy-controller/config.toml`

```toml
data_dir         = "/etc/policy-controller"      # CA key/cert directory
db_path          = "/var/lib/policy-controller/controller.db"
http_addr        = "0.0.0.0:8443"               # operator API
enrollment_addr  = "0.0.0.0:7776"               # gRPC enrollment (TLS)
management_addr  = "0.0.0.0:7777"               # gRPC management (mTLS)
ca_common_name   = "Policy Controller CA"
server_san       = "controller.local"            # DNS SAN for server cert
node_cert_ttl_days = 90                          # issued node cert TTL
web_root         = "/usr/share/policy-controller/web"  # optional web UI
```

### policy-node-agent: `/etc/policy-node-agent/config.toml`

Most fields are optional — the ZTP bundle carries the URLs and CA pin, and
all path defaults match the systemd unit's StateDirectory. A minimal config
file is typically empty; the example below shows every key for reference.

```toml
# Optional — bundle values override these on first enrollment, then the
# learned endpoints are persisted at `endpoints_path`.
# controller_url = "https://controller.example.com:7777"
# enrollment_url = "https://controller.example.com:7776"

bootstrap_bundle_path = "/etc/policy-node-agent/bootstrap.bundle"
endpoints_path        = "/var/lib/policy-node-agent/endpoints.json"
ca_cert_path          = "/var/lib/policy-node-agent/controller-ca.crt"
identity_key_path     = "/var/lib/policy-node-agent/identity.key"
client_cert_path      = "/var/lib/policy-node-agent/controller-client.crt"
client_key_path       = "/var/lib/policy-node-agent/controller-client.key"
local_server_url      = "http://127.0.0.1:8080/graphql"

# mTLS key is rotated every Nth cert renewal (default 4 ≈ ~240d at 90d TTL).
mtls_key_rotation_renewals  = 4
renewal_check_interval_secs = 3600
```

The agent also accepts `--bootstrap-bundle <path>` on the CLI or
`POLICY_BOOTSTRAP_BUNDLE=<path>` in the environment.

---

## Key Source Files

| File | Purpose |
|------|---------|
| `src/bpf/xdp_policy.bpf.c` | XDP ingress BPF program |
| `src/bpf/tc_policy.bpf.c` | TC egress BPF program |
| `src/bpf/include/policy_common.h` | Shared BPF types and constants |
| `src/paths.rs` | Shared path constants |
| `src/traits.rs` | `BpfOperations` + `NetworkOperations` traits |
| `src/types.rs` | Core types: `PolicyAction`, `ActionParams`, `RuleAction` |
| `src/server/bpf_manager.rs` | Loads/pins BPF programs via libbpf-rs |
| `src/server/policy_service.rs` | Business logic: rule CRUD, attach/detach |
| `src/server/state_store.rs` | `StateStore` trait + `FileStateStore` + `InMemoryStateStore` |
| `src/server/graphql/schema.rs` | GraphQL queries and mutations |
| `src/server/graphql/types.rs` | GraphQL output types |
| `src/server/suricata_coordinator.rs` | Suricata lifecycle orchestration |
| `src/server/veth_manager.rs` | pe-inspect0 ↔ pe-inspect1 veth pair |
| `fleet/controller/migrations/0001_initial.sql` | Authoritative SQLite schema (single migration; controller DB is wiped between major versions pre-1.0) |
| `fleet/controller/src/security/ca.rs` | `FileCertificateAuthority` |
| `fleet/controller/src/security/revocation.rs` | In-memory revoked-serial mirror + rustls `ClientCertVerifier` |
| `fleet/controller/src/store/` | `ControllerStore` trait + SQLite + InMemory |
| `fleet/controller/src/session/` | `NodeSessionManager` (online agents) |
| `fleet/controller/src/node_registry/` | Enrollment, token redemption, approval, cert issuance |
| `fleet/controller/src/grpc/enrollment.rs` | `EnrollmentService` (port 7776, server-TLS) |
| `fleet/controller/src/grpc/management.rs` | Per-agent gRPC stream driver + `RenewClientCert` (port 7777, mTLS) |
| `fleet/agent/src/identity/` | Identity key: TPM-backed + file-backed implementations |
| `fleet/agent/src/enrollment/` | Bundle parsing, CA fingerprint pin, enrollment RPC |
| `fleet/agent/src/enrollment/bundle.rs` | ZTP bootstrap bundle encode/decode |
| `fleet/agent/src/controller_client/` | gRPC stream + StateSnapshot + cert renewal task |
| `fleet/agent/src/config_applier/` | ConfigPush → local GraphQL mutations |
| `fleet/agent/src/metrics_forwarder/` | Scrape local `/metrics`, forward |
| `fleet/agent/src/event_forwarder/` | Subscribe local WS events, forward |
