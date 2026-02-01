# Testing with Netsim

This guide covers running the full integration test suite using `netsim`, a libvirt/QEMU-based
network topology simulator. Tests spin up real Debian 13 VMs, install built packages, and
verify end-to-end behavior including BPF program loading, traffic enforcement, IPS/IDS,
IPFIX flow export, XDP forwarding, multi-node fleet management, and more.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building Packages](#building-packages)
3. [Common Workflow](#common-workflow)
4. [Test Suites](#test-suites)
   - [policy_sanity — Core Functionality](#policy_sanity--core-functionality)
   - [ips_ids — Suricata IPS/IDS](#ips_ids--suricata-ipsids)
   - [ipfix — Flow Export](#ipfix--flow-export)
   - [mac_matching — Layer 2 Filtering](#mac_matching--layer-2-filtering)
   - [xdp_forwarding — FIB Forwarding](#xdp_forwarding--fib-forwarding)
   - [rule_lifecycle — TTL and Scheduled Rules](#rule_lifecycle--ttl-and-scheduled-rules)
   - [persistence — State Across Restarts](#persistence--state-across-restarts)
   - [tls — HTTPS and Certificate Validation](#tls--https-and-certificate-validation)
   - [multi_node — Fleet Controller](#multi_node--fleet-controller)
   - [two_node_iperf — Throughput](#two_node_iperf--throughput)
   - [three_node_iperf — Multi-hop Throughput](#three_node_iperf--multi-hop-throughput)
   - [policy_performance — Rule Lookup Performance](#policy_performance--rule-lookup-performance)
   - [scale_test — Fleet Scale](#scale_test--fleet-scale)
5. [Running Specific Tests](#running-specific-tests)
6. [Debugging Failures](#debugging-failures)
7. [Topology Reference](#topology-reference)

---

## Prerequisites

### Host Requirements

- Linux host with KVM support (`/dev/kvm` accessible)
- libvirt and QEMU installed
- netsim installed and configured for user-mode sessions

```bash
cd netsim
./setup-user-mode.sh    # configures libvirt user session + sudoers
poetry install
```

### Verify Netsim Works

```bash
netsim status
```

### Package Requirements

Each test suite installs one or more `.deb` packages onto VMs via `--install-packages`. Build
the packages you need before running tests (see [Building Packages](#building-packages)).

---

## Building Packages

From the `policy_engine/` directory:

```bash
# Base package (no IPS, no IPFIX)
dpkg-buildpackage -us -uc -b

# With Suricata IPS/IDS
DEB_BUILD_PROFILES=pkg.policy-engine.suricata dpkg-buildpackage -us -uc -b

# With IPFIX flow export
DEB_BUILD_PROFILES=pkg.policy-engine.ipfix dpkg-buildpackage -us -uc -b

# With both IPS/IDS and IPFIX
DEB_BUILD_PROFILES="pkg.policy-engine.suricata pkg.policy-engine.ipfix" \
  dpkg-buildpackage -us -uc -b
```

This produces `.deb` files in the parent directory (`../`). Move or symlink them somewhere
convenient.

---

## Common Workflow

The standard lifecycle for every test suite is:

```bash
cd netsim

# 1. Start the topology (boots VMs, waits for SSH)
netsim start tests/<suite>/<suite>.yaml

# 2. Run tests (installs packages on first run)
python3 -m pytest tests/<suite>/ -v \
    --install-packages /path/to/policy-engine.deb[,/path/to/other.deb]

# 3. Re-run tests without reinstalling (faster iteration)
python3 -m pytest tests/<suite>/ -v

# 4. Destroy VMs when done
netsim destroy tests/<suite>/<suite>.yaml
```

The `--install-packages` flag copies and installs the listed `.deb` files onto all VMs in
the topology. Pass multiple packages as a comma-separated list.

> **Tip:** Topology boot takes ~60s. Leave VMs running between test runs — `netsim start`
> is idempotent and fast if VMs are already running.

---

## Test Suites

### policy_sanity — Core Functionality

**Topology:** `tests/policy_sanity/policy_sanity.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine`

```bash
netsim start tests/policy_sanity/policy_sanity.yaml

python3 -m pytest tests/policy_sanity/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_policy_sanity.py` | XDP attach/detach (auto/native/generic modes), rule add/delete, IPv4/IPv6 PASS/DROP enforcement, protocol matching (TCP/UDP/ICMP), port matching, combined src+dst+port rules |
| `test_egress_attachment.py` | TC egress attach and detach |
| `test_egress_attachment_negative.py` | Error cases: double-attach, detach non-attached interface |
| `test_egress_traffic.py` | Egress DROP enforcement for outbound traffic |
| `test_egress_default_action.py` | Default action (pass/drop) for unmatched egress traffic |
| `test_egress_rule_management.py` | Egress rule add/delete/flush/list |
| `test_lpm_fallback.py` | LPM ancestor walking: /32, /24, /16, /8, /0 matches; more-specific wins |
| `test_sni_matching.py` | TLS SNI exact and wildcard (`*.example.com`) matching over real HTTPS traffic |
| `test_quic.py` | QUIC v1/v2 version detection and filtering |
| `test_log_rate_limit.py` | LOG action with and without rate limiting; verifies event counts |
| `test_malformed_packets.py` | Fragment handling, truncated headers, non-IP traffic |
| `test_many_flows.py` | Stress test with many concurrent flows; verifies BPF map capacity |

```bash
# Run a specific test file
python3 -m pytest tests/policy_sanity/test_sni_matching.py -v

# Run a single test
python3 -m pytest tests/policy_sanity/test_policy_sanity.py::test_ipv4_drop -v
```

---

### ips_ids — Suricata IPS/IDS

**Topology:** `tests/ips_ids/ips_ids.yaml`  
**VMs:** 2 — `server` (policy-engine + Suricata), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64  
**Memory:** server=2GB (Suricata needs more RAM)

**Package required:** `policy-engine-ips` or `policy-engine-ips-ipfix`

```bash
netsim start tests/ips_ids/ips_ids.yaml

python3 -m pytest tests/ips_ids/ -v \
    --install-packages ../policy-engine-ips_*.deb
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_inspect_mode.py` | Enable IPS mode, enable IDS mode, mode switching, `pe-inspect0`/`pe-inspect1` veth creation/destruction, verify Suricata starts with AF-XDP config |
| `test_ips_traffic.py` | INSPECT action on rules, flow verdict cache seeded (PASS), Suricata alert → DROP verdict written, subsequent packets dropped at XDP speed, IDS mode (alert but no block), flow cache TTL expiry |
| `test_suricata_rules.py` | Deploy custom Suricata rules via GraphQL mutation, rule reload, verify new signatures trigger on matching traffic |

```bash
# Run only IPS traffic tests
python3 -m pytest tests/ips_ids/test_ips_traffic.py -v

# Run with verbose Suricata log output
python3 -m pytest tests/ips_ids/ -v -s
```

---

### ipfix — Flow Export

**Topology:** `tests/ipfix/ipfix.yaml`  
**VMs:** 2 — `server` (policy-engine with IPFIX), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine-ipfix` or `policy-engine-ips-ipfix`

```bash
netsim start tests/ipfix/ipfix.yaml

python3 -m pytest tests/ipfix/ -v \
    --install-packages ../policy-engine-ipfix_*.deb
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_flow_export_config.py` | Enable/disable IPFIX via GraphQL, configure collector address/port, configure idle and active timeout values, verify `flowExportStatus` query reflects config |
| `test_flow_export_traffic.py` | Generate traffic, verify flows appear in XDP flow cache, verify IPFIX records are exported to a test collector on the client VM, check 5-tuple fields in records |

---

### mac_matching — Layer 2 Filtering

**Topology:** `tests/mac_matching/mac_matching.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.2.1.0/24, 2001:db8:2::/64

**Package required:** `policy-engine`

```bash
netsim start tests/mac_matching/mac_matching.yaml

python3 -m pytest tests/mac_matching/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test file:** `test_mac_matching.py`

What is tested:
- Source MAC address filtering (`--src-mac`)
- Destination MAC address filtering (`--dst-mac`)
- Combined MAC + IP + port rules
- MAC rules on both ingress (XDP) and egress (TC)
- Verifies that traffic with matching MAC is dropped, other traffic passes
- Verifies MAC rules survive rule list/delete lifecycle

---

### xdp_forwarding — FIB Forwarding

**Topology:** `tests/xdp_forwarding/xdp_forwarding.yaml`  
**VMs:** 3 — `client` (net1), `transit` (net1+net2, policy-engine), `server` (net2)  
**Networks:** `net1` — 10.1.1.0/24 and `net2` — 10.1.2.0/24

This is the only 3-node topology in the core test suite. The `transit` VM acts as a router
with policy-engine attached on both interfaces.

**Package required:** `policy-engine`

```bash
netsim start tests/xdp_forwarding/xdp_forwarding.yaml

python3 -m pytest tests/xdp_forwarding/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test file:** `test_xdp_forwarding.py`

What is tested:
- Enable FIB forwarding via GraphQL mutation
- Client → transit → server traffic is forwarded at XDP speed (no kernel stack)
- Verify `fib_forwarded_packets` counter increments
- Verify `fib_fallback_packets` counter for non-routable destinations
- Disable FIB forwarding → traffic reverts to kernel routing
- Rules still apply when FIB forwarding is active

---

### rule_lifecycle — TTL and Scheduled Rules

**Topology:** `tests/rule_lifecycle/rule_lifecycle.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine`

```bash
netsim start tests/rule_lifecycle/rule_lifecycle.yaml

python3 -m pytest tests/rule_lifecycle/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_ttl_rules.py` | Add rule with `--expires-after-secs`, verify traffic is blocked, wait for TTL expiry, verify traffic passes again; managed-rules query shows TTL rules with remaining time |
| `test_scheduled_rules.py` | Add rule with a schedule window; verify rule is active/inactive based on current time; timezone handling (UTC, America/Toronto); `managedRules` query shows schedule windows |
| `test_lifecycle_events.py` | WebSocket event stream emits rule-expired and rule-activated events at the right times |

> **Note:** TTL and schedule tests may require adjusting the schedule window to align with
> the test host's clock, or mocking time via VM clock manipulation.

---

### persistence — State Across Restarts

**Topology:** `tests/persistence/persistence.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine`

```bash
netsim start tests/persistence/persistence.yaml

python3 -m pytest tests/persistence/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test file:** `test_state_persistence.py`

What is tested:
- Add rules, attach interfaces, set default actions
- Restart the `policy-engine` daemon (or reboot the VM)
- Verify all rules are restored from `/var/lib/policy-engine/state.json`
- Verify XDP/TC programs are re-attached to the same interfaces
- Verify default actions are restored
- Traffic enforcement works immediately after restart without manual reconfiguration

---

### tls — HTTPS and Certificate Validation

**Topology:** `tests/tls/tls.yaml`  
**VMs:** 1 — `server` (policy-engine with TLS)

**Package required:** `policy-engine`

```bash
netsim start tests/tls/tls.yaml

python3 -m pytest tests/tls/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_tls_enforcement.py` | Server starts with TLS cert/key, HTTPS connections succeed with trusted CA, connections fail without CA cert, `--tls-insecure` bypasses validation |
| `test_tls_policy_ops.py` | Full rule management workflow over HTTPS: add, list, delete, flush, attach, detach, stats |

---

### multi_node — Fleet Controller

**Topology:** `tests/multi_node/multi_node.yaml`  
**VMs:** 4 — `controller`, `node1`, `node2`, `node3`  
**Networks:** `mgmt` — 10.10.0.0/24 (all VMs), `data` — 10.20.0.0/24 (nodes only)

This is the largest topology and exercises the complete fleet management workflow.

**Packages required:**
- On controller: `policy-controller`, `policy-controller-client`
- On nodes: `policy-engine`, `policy-node-agent`

```bash
netsim start tests/multi_node/multi_node.yaml

python3 -m pytest tests/multi_node/ -v \
    --install-packages \
        /path/to/policy-engine_*.deb,\
        /path/to/policy-node-agent_*.deb,\
        /path/to/policy-controller_*.deb,\
        /path/to/policy-controller-client_*.deb
```

**Test classes and scenarios:**

#### TestEnrollment

Verifies all 3 nodes successfully complete ZTP enrollment.

| Test | What is tested |
|------|---------------|
| `test_all_nodes_active` | All 3 nodes reach `active` status after approval |
| `test_nodes_have_labels` | Labels set during approval appear on nodes |
| `test_nodes_appear_online` | All active nodes appear in `onlineNodes` (agents connected via mTLS) |

The fixture `enrolled_nodes`:
1. Waits for 3 pending enrollment requests (120s timeout)
2. Approves each with a label (`node1`, `node2`, `node3`)
3. Waits for all to reach `active` status

#### TestConfigDistribution

Verifies rulesets are pushed from controller to nodes.

| Test | What is tested |
|------|---------------|
| `test_ruleset_pushed_to_all_nodes` | Create a drop-all ruleset, assign to all 3 nodes, push, verify rules appear in each node's local policy-engine GraphQL API |
| `test_push_config_all_returns_success` | `pushConfigAll` mutation succeeds when all nodes are online |

#### TestMetricsVisibility

Verifies controller aggregates node metrics.

| Test | What is tested |
|------|---------------|
| `test_metrics_endpoint_responds` | `/metrics/node/<id>` returns 200 after agent scrapes local `/metrics` (waits 35s for first scrape) |
| `test_aggregated_metrics_endpoint` | `/metrics` returns 200 (aggregated fleet metrics) |

#### TestControllerRestart

Verifies behavior during controller outage and recovery.

| Test | What is tested |
|------|---------------|
| `test_nodes_enforce_during_controller_outage` | Stop controller, verify all node `policy-engine` services are still running and enforcing rules |
| `test_reconciliation_after_controller_restart` | Restart controller, wait for agents to reconnect, verify all nodes are still `active` and desired config is reconciled |

#### TestDecommission

Verifies certificate revocation.

| Test | What is tested |
|------|---------------|
| `test_decommission_blocks_reconnect` | Decommission node3, restart its agent, verify node3 does NOT appear in `onlineNodes` (revoked cert rejected by controller mTLS verifier) |
| `test_remove_decommissioned_node` | After decommission, `removeNode` succeeds and node disappears from registry |

**Running individual scenarios:**

```bash
# Only enrollment tests
python3 -m pytest tests/multi_node/test_multi_node.py::TestEnrollment -v

# Only config distribution
python3 -m pytest tests/multi_node/test_multi_node.py::TestConfigDistribution -v

# Only decommission
python3 -m pytest tests/multi_node/test_multi_node.py::TestDecommission -v
```

**Fixture scoping:** All fixtures are `package`-scoped, meaning VMs are started once and
shared across all test classes. The `enrolled_nodes` fixture runs enrollment and approval
once; subsequent tests reuse the same enrolled state.

---

### two_node_iperf — Throughput

**Topology:** `tests/two_node_iperf/two_node_iperf.yaml`  
**VMs:** 2 — `server`, `client`

**Package required:** `policy-engine`

```bash
netsim start tests/two_node_iperf/two_node_iperf.yaml

python3 -m pytest tests/two_node_iperf/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test file:** `test_two_node_iperf.py`

What is tested:
- Baseline iperf3 throughput without policy-engine
- Throughput with XDP attached (PASS rules only)
- Throughput impact of DROP rules
- Throughput impact of LOG rules
- Verifies BPF processing overhead is within acceptable bounds

---

### three_node_iperf — Multi-hop Throughput

**Topology:** `tests/three_node_iperf/three_node_iperf.yaml`  
**VMs:** 3 — `client`, `transit` (policy-engine + routing), `server`

**Package required:** `policy-engine`

```bash
netsim start tests/three_node_iperf/three_node_iperf.yaml

python3 -m pytest tests/three_node_iperf/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test file:** `test_three_node_iperf.py`

What is tested:
- Client → transit → server throughput without FIB forwarding (kernel routing)
- Client → transit → server throughput with FIB forwarding enabled (XDP redirect)
- Verifies FIB forwarding provides measurable throughput improvement
- Verifies policy rules are enforced even with FIB forwarding active

---

### policy_performance — Rule Lookup Performance

**Topology:** `tests/policy_performance/policy_performance.yaml`
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)

**Package required:** `policy-engine`

```bash
netsim start tests/policy_performance/policy_performance.yaml

python3 -m pytest tests/policy_performance/ -v \
    --install-packages ../policy-engine_*.deb
```

**Test file:** `test_rule_performance.py`

What is tested:
- Rule lookup overhead at varying ruleset sizes
- Throughput regression checks for the policy-engine fast path

---

### scale_test — Fleet Scale

**Topology:** `tests/scale_test/scale_test.yaml`
**VMs:** 2 — `controller` (policy-controller), `docker-host` (runs N engine+agent
container pairs on a docker bridge)
**Network:** `mgmt` — 10.10.0.0/24

Scales the fleet by running many policy-engine + policy-node-agent pairs as
Docker containers on a single VM, all enrolling against one controller. Engine
containers do not attach BPF programs, so they can share a bridge network and
avoid the `--network host` requirement.

**Package required:** `policy-controller` (installed on the controller VM only).
The engine and agent run from local Docker images — build them first:

```bash
# In policy-engine/ — produces policy-engine:0.1.0 and policy-node-agent:0.1.0
make docker-images   # or whatever target builds the local images
```

```bash
netsim start tests/scale_test/scale_test.yaml

python3 -m pytest tests/scale_test/ -v \
    --install-packages ../policy-controller_*.deb \
    --scale-nodes 10
```

**Test file:** `test_scale.py`

What is tested:
- N engine+agent container pairs auto-enroll against a single controller
- Time-to-Active and time-to-online for the fleet
- Controller stays responsive under concurrent enrollment

**Relevant CLI options** (registered in `tests/conftest.py`):

| Option | Default | Notes |
|--------|---------|-------|
| `--scale-nodes` | `10` | Number of engine+agent pairs |
| `--engine-image` | `policy-engine:0.1.0` | Must exist in local Docker daemon |
| `--agent-image` | `policy-node-agent:0.1.0` | Must exist in local Docker daemon |

> **Tip:** Bump `docker-host` VM memory in `scale_test.yaml` for higher node
> counts (10 → 4GB, 25 → 8GB, 50 → 16GB).

---

## Running Specific Tests

### By suite

```bash
python3 -m pytest tests/policy_sanity/ -v
python3 -m pytest tests/ips_ids/ -v
python3 -m pytest tests/multi_node/ -v
```

### By test class

```bash
python3 -m pytest tests/multi_node/test_multi_node.py::TestEnrollment -v
```

### By test name

```bash
python3 -m pytest tests/policy_sanity/test_policy_sanity.py::test_ipv4_drop -v
python3 -m pytest -k "test_sni" -v
python3 -m pytest -k "ttl" -v
```

### With output captured (useful for debugging)

```bash
python3 -m pytest tests/ips_ids/ -v -s
```

### Re-run failed tests only

```bash
python3 -m pytest tests/policy_sanity/ -v --lf
```

### Parallel test execution

```bash
python3 -m pytest tests/policy_sanity/ -v -n auto  # requires pytest-xdist
```

---

## Debugging Failures

### Check VM status

```bash
netsim status tests/<suite>/<suite>.yaml
```

### SSH into a VM

```bash
netsim connect tests/<suite>/<suite>.yaml server
```

### View service logs on VM

```bash
# Inside VM
journalctl -u policy-engine -f
journalctl -u policy-engine --since "5 minutes ago"

# For multi-node:
journalctl -u policy-controller -f      # on controller VM
journalctl -u policy-node-agent -f      # on node VMs
```

### Check BPF programs

```bash
# Inside VM
bpftool prog list
bpftool map list
ls /sys/fs/bpf/policy_engine/
```

### Check rules on a node (multi_node tests)

```bash
# Inside node VM
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{ rules(direction: INGRESS) { ruleId srcPrefix dstPrefix } }"}' \
  http://127.0.0.1:8080/graphql | jq .
```

### Increase test verbosity

Add `-s` to see SSH command output and test logging:

```bash
python3 -m pytest tests/multi_node/ -v -s --log-cli-level=DEBUG
```

### Package installation failures

If `--install-packages` fails, check that the `.deb` path is correct and the package is
compatible with Debian 13 (Trixie):

```bash
netsim connect tests/policy_sanity/policy_sanity.yaml server
# Inside VM:
dpkg -i /tmp/policy-engine_*.deb
apt-get install -f
```

---

## Topology Reference

| Suite | Topology | VMs | Networks | Notes |
|-------|----------|-----|---------|-------|
| policy_sanity | policy_sanity.yaml | 2: server, client | net1: 10.1.1.0/24 + IPv6 | Core tests |
| ips_ids | ips_ids.yaml | 2: server, client | net1: 10.1.1.0/24 + IPv6 | server needs 2GB RAM |
| ipfix | ipfix.yaml | 2: server, client | net1: 10.1.1.0/24 + IPv6 | IPFIX package |
| mac_matching | mac_matching.yaml | 2: server, client | net1: 10.2.1.0/24 + IPv6 | |
| xdp_forwarding | xdp_forwarding.yaml | 3: client, transit, server | net1+net2: 10.1.1/2.0/24 + IPv6 | Transit routing |
| rule_lifecycle | rule_lifecycle.yaml | 2: server, client | net1: 10.1.1.0/24 + IPv6 | Clock-sensitive |
| persistence | persistence.yaml | 2: server, client | net1: 10.1.1.0/24 + IPv6 | Reboot required |
| tls | tls.yaml | 1: server | net1: 10.1.1.0/24 + IPv6 | |
| multi_node | multi_node.yaml | 4: controller + node1/2/3 | mgmt: 10.10.0.0/24, data: 10.20.0.0/24 | Fleet tests |
| two_node_iperf | two_node_iperf.yaml | 2: server, client | – | iperf3 required |
| three_node_iperf | three_node_iperf.yaml | 3: client, transit, server | – | iperf3 required |
| policy_performance | policy_performance.yaml | 2: server, client | net1: 10.1.1.0/24 + IPv6 | Rule-lookup perf |
| scale_test | scale_test.yaml | 2: controller, docker-host | mgmt: 10.10.0.0/24 | Engine/agent run as Docker containers |

All VMs use the Debian 13 (Trixie) genericcloud amd64 image.

---

## Running All Test Suites

Use the `tests/run_all.sh` wrapper. It auto-discovers every `tests/<name>/<name>.yaml`,
selects the right `--install-packages` set per suite, starts/destroys the topology
between suites, and prints a pass/fail summary at the end (takes 30–60 minutes).

```bash
cd netsim
tests/run_all.sh ..             # PKG_DIR defaults to the parent directory
# or point at a staging dir of .debs:
tests/run_all.sh /tmp/policy-packages
```

Overrides (env vars):

- `SUITES="ipfix tls"` — run a subset.
- `SKIP="rule_lifecycle"` — omit suites (empty by default). `scale_test`
  requires the `policy-engine:0.1.0` and `policy-node-agent:0.1.0` Docker
  images to exist locally; skip it if you haven't built them.
- `LOG_DIR=/tmp/logs` — where per-suite logs go (default `pytest-logs/`).

The wrapper exits non-zero if any suite fails.
