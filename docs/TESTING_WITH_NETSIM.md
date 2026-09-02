# Testing with Netsim

This guide covers running the integration test suites in `python/tests/`. They spin up real
Debian 13 VMs, install the built packages, and verify end-to-end behavior including BPF
program loading, traffic enforcement, IPS/IDS, IPFIX flow export, XDP forwarding, multi-node
fleet management, and more.

The VMs come from [netsim](https://github.com/pdmorrow/netsim), a libvirt/QEMU
topology simulator this project depends on. netsim supplies the topology, VM lifecycle, SSH
access and package installation as pytest fixtures; the suites themselves are ours. See
`python/README.md` for the layout.

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
   - [policy_performance — Rule Lookup Performance](#policy_performance--rule-lookup-performance)
   - [scale_test — Fleet Scale](#scale_test--fleet-scale)
5. [Running Specific Tests](#running-specific-tests)
6. [Debugging Failures](#debugging-failures)
7. [Topology Reference](#topology-reference)

---

## Prerequisites

### Host Requirements

- Linux host with KVM support (`/dev/kvm` accessible)
- libvirt and QEMU installed, and **not** using the AppArmor security driver — it blocks
  QEMU from reading images under `~/.netsim`. Set `security_driver = "none"` in
  `/etc/libvirt/qemu.conf` and restart `libvirtd`.
- `libvirt-dev` and `pkg-config`, to build `libvirt-python`

The suites live in this repo under `python/tests/`. netsim arrives as a dependency, so
installing this project is all that is needed:

```bash
poetry install
```

The libvirt user session is configured once, with the script from a netsim checkout:

```bash
git clone git@github.com:pdmorrow/netsim.git
netsim/setup-user-mode.sh    # configures libvirt user session + sudoers
```

### Verify Netsim Works

```bash
poetry run netsim status
```

### Package Requirements

Each suite's topology YAML names the `.deb` packages each of its nodes installs, and pytest
resolves those globs against `--package-dir` before booting a single VM. Build the packages
you need first (see [Building Packages](#building-packages)).

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

Every suite runs the same way:

```bash
make deb                                    # .debs land in the parent directory

poetry run pytest python/tests/<suite>/ --package-dir ..
```

pytest owns the topology. The autouse `running_topology` fixture boots the VMs, installs
each node's packages, configures interfaces, and destroys everything afterwards — including
when a test fails. Boot takes about a minute per run.

`--package-dir` is where the `.deb` files are. Each topology also names a default, so the
flag can be dropped when the packages are where `dpkg-buildpackage` left them.

Suites whose nodes declare per-feature package sets need `--feature` to say which build to
install:

```bash
poetry run pytest python/tests/ips_ids/ --feature ips --package-dir ..
```

Run one suite per invocation. `python/tests/` is a single Python package, so pytest sets
up the package-scoped topology once for the whole tree; naming two suites at once makes
the second run against the first one's VMs. `python/run_all.sh` calls pytest once per
suite for this reason.

> **Tip:** `--pause-on-failure` keeps the topology up when a test fails and prints the
> `ssh` command for each node.

---

## Test Suites

### policy_sanity — Core Functionality

**Topology:** `python/tests/policy_sanity/policy_sanity.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine`

```bash
poetry run pytest python/tests/policy_sanity/ -v \
    --package-dir ..
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
poetry run pytest python/tests/policy_sanity/test_sni_matching.py -v

# Run a single test
poetry run pytest python/tests/policy_sanity/test_policy_sanity.py::test_ipv4_drop -v
```

---

### ips_ids — Suricata IPS/IDS

**Topology:** `python/tests/ips_ids/ips_ids.yaml`  
**VMs:** 2 — `server` (policy-engine + Suricata), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64  
**Memory:** server=2GB (Suricata needs more RAM)

**Package required:** `policy-engine-ips` or `policy-engine-ips-ipfix`

```bash
poetry run pytest python/tests/ips_ids/ -v \
    --package-dir ..
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_inspect_mode.py` | Enable IPS mode, enable IDS mode, mode switching, `pe-inspect0`/`pe-inspect1` veth creation/destruction, verify Suricata starts with AF-XDP config |
| `test_ips_traffic.py` | INSPECT action on rules, flow verdict cache seeded (PASS), Suricata alert → DROP verdict written, subsequent packets dropped at XDP speed, IDS mode (alert but no block), flow cache TTL expiry |
| `test_suricata_rules.py` | Deploy custom Suricata rules via GraphQL mutation, rule reload, verify new signatures trigger on matching traffic |

```bash
# Run only IPS traffic tests
poetry run pytest python/tests/ips_ids/test_ips_traffic.py -v

# Run with verbose Suricata log output
poetry run pytest python/tests/ips_ids/ -v -s
```

---

### ipfix — Flow Export

**Topology:** `python/tests/ipfix/ipfix.yaml`  
**VMs:** 2 — `server` (policy-engine with IPFIX), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine-ipfix` or `policy-engine-ips-ipfix`

```bash
poetry run pytest python/tests/ipfix/ -v \
    --package-dir ..
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_flow_export_config.py` | Enable/disable IPFIX via GraphQL, configure collector address/port, configure idle and active timeout values, verify `flowExportStatus` query reflects config |
| `test_flow_export_traffic.py` | Generate traffic, verify flows appear in XDP flow cache, verify IPFIX records are exported to a test collector on the client VM, check 5-tuple fields in records |

---

### mac_matching — Layer 2 Filtering

**Topology:** `python/tests/mac_matching/mac_matching.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.2.1.0/24, 2001:db8:2::/64

**Package required:** `policy-engine`

```bash
poetry run pytest python/tests/mac_matching/ -v \
    --package-dir ..
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

**Topology:** `python/tests/xdp_forwarding/xdp_forwarding.yaml`  
**VMs:** 3 — `client` (net1), `transit` (net1+net2, policy-engine), `server` (net2)  
**Networks:** `net1` — 10.1.1.0/24 and `net2` — 10.1.2.0/24

This is the only 3-node topology in the core test suite. The `transit` VM acts as a router
with policy-engine attached on both interfaces.

**Package required:** `policy-engine`

```bash
poetry run pytest python/tests/xdp_forwarding/ -v \
    --package-dir ..
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

**Topology:** `python/tests/rule_lifecycle/rule_lifecycle.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine`

```bash
poetry run pytest python/tests/rule_lifecycle/ -v \
    --package-dir ..
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

**Topology:** `python/tests/persistence/persistence.yaml`  
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)  
**Network:** `net1` — 10.1.1.0/24, 2001:db8:1::/64

**Package required:** `policy-engine`

```bash
poetry run pytest python/tests/persistence/ -v \
    --package-dir ..
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

**Topology:** `python/tests/tls/tls.yaml`  
**VMs:** 1 — `server` (policy-engine with TLS)

**Package required:** `policy-engine`

```bash
poetry run pytest python/tests/tls/ -v \
    --package-dir ..
```

**Test files and what they cover:**

| File | What is tested |
|------|---------------|
| `test_tls_enforcement.py` | Server starts with TLS cert/key, HTTPS connections succeed with trusted CA, connections fail without CA cert, `--tls-insecure` bypasses validation |
| `test_tls_policy_ops.py` | Full rule management workflow over HTTPS: add, list, delete, flush, attach, detach, stats |

---

### multi_node — Fleet Controller

**Topology:** `python/tests/multi_node/multi_node.yaml`  
**VMs:** 4 — `controller`, `node1`, `node2`, `node3`  
**Networks:** `mgmt` — 10.10.0.0/24 (all VMs), `data` — 10.20.0.0/24 (nodes only)

This is the largest topology and exercises the complete fleet management workflow.

**Packages required:**
- On controller: `policy-controller`, `policy-controller-client`
- On nodes: `policy-engine`, `policy-node-agent`

```bash
poetry run pytest python/tests/multi_node/ -v \
    --package-dir ..
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
poetry run pytest python/tests/multi_node/test_multi_node.py::TestEnrollment -v

# Only config distribution
poetry run pytest python/tests/multi_node/test_multi_node.py::TestConfigDistribution -v

# Only decommission
poetry run pytest python/tests/multi_node/test_multi_node.py::TestDecommission -v
```

**Fixture scoping:** All fixtures are `package`-scoped, meaning VMs are started once and
shared across all test classes. The `enrolled_nodes` fixture runs enrollment and approval
once; subsequent tests reuse the same enrolled state.

---

### iperf throughput — in the netsim repo

`two_node_iperf` and `three_node_iperf` measure raw and multi-hop throughput on a bare
topology. They test netsim itself rather than policy-engine, so they live in the netsim
repo under `tests/`.

---

### policy_performance — Rule Lookup Performance

**Topology:** `python/tests/policy_performance/policy_performance.yaml`
**VMs:** 2 — `server` (policy-engine), `client` (traffic source)

**Package required:** `policy-engine`

```bash
poetry run pytest python/tests/policy_performance/ -v \
    --package-dir ..
```

**Test file:** `test_rule_performance.py`

What is tested:
- Rule lookup overhead at varying ruleset sizes
- Throughput regression checks for the policy-engine fast path

---

### scale_test — Fleet Scale

**Topology:** `python/tests/scale_test/scale_test.yaml`
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
poetry run pytest python/tests/scale_test/ -v \
    --package-dir ..
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
poetry run pytest python/tests/policy_sanity/ -v
poetry run pytest python/tests/ips_ids/ -v
poetry run pytest python/tests/multi_node/ -v
```

### By test class

```bash
poetry run pytest python/tests/multi_node/test_multi_node.py::TestEnrollment -v
```

### By test name

```bash
poetry run pytest python/tests/policy_sanity/test_policy_sanity.py::test_ipv4_drop -v
poetry run pytest -k "test_sni" -v
poetry run pytest -k "ttl" -v
```

### With output captured (useful for debugging)

```bash
poetry run pytest python/tests/ips_ids/ -v -s
```

### Re-run failed tests only

```bash
poetry run pytest python/tests/policy_sanity/ -v --lf
```

### Parallel test execution

```bash
poetry run pytest python/tests/policy_sanity/ -v -n auto  # requires pytest-xdist
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
poetry run pytest python/tests/multi_node/ -v -s --log-cli-level=DEBUG
```

### Package installation failures

pytest validates every package glob before booting a VM, so a bad `--package-dir` or a
missing build fails immediately with the offending pattern named. If installation itself
fails, check the package is compatible with Debian 13 (Trixie):

```bash
netsim connect python/tests/policy_sanity/policy_sanity.yaml server
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
| policy_performance | policy_performance.yaml | 2: server, client | net1: 10.1.1.0/24 + IPv6 | Rule-lookup perf |
| scale_test | scale_test.yaml | 2: controller, docker-host | mgmt: 10.10.0.0/24 | Engine/agent run as Docker containers |

All VMs use the Debian 13 (Trixie) genericcloud amd64 image.

---

## Running All Test Suites

Use the `python/run_all.sh` wrapper. It auto-discovers every
`python/tests/<name>/<name>.yaml`, runs the suites in sequence, and prints a pass/fail
summary at the end (takes 30–60 minutes).

```bash
python/run_all.sh                       # PKG_DIR defaults to ../..
# or point at a staging dir of .debs:
python/run_all.sh /tmp/policy-packages
```

Equivalently, `make test-integration`, or `make test-integration SUITE=policy_sanity`
for one.

Overrides (env vars):

- `SUITES="ipfix tls"` — run a subset.
- `SKIP="rule_lifecycle"` — omit suites (empty by default). `scale_test`
  requires the `policy-engine:0.1.0` and `policy-node-agent:0.1.0` Docker
  images to exist locally; skip it if you haven't built them.
- `LOG_DIR=/tmp/logs` — where per-suite logs go (default `pytest-logs/`).

The wrapper exits non-zero if any suite fails.
