# Policy Engine — User Guide

## Table of Contents

1. [Installation](#installation)
2. [Standalone Mode: policy-engine](#standalone-mode-policy-engine)
3. [Attaching to Network Interfaces](#attaching-to-network-interfaces)
4. [Managing Rules](#managing-rules)
5. [Rule Matching](#rule-matching)
6. [Advanced Rule Features](#advanced-rule-features)
7. [Statistics and Monitoring](#statistics-and-monitoring)
8. [Suricata IPS/IDS](#suricata-ipsids)
9. [IPFIX Flow Export](#ipfix-flow-export)
10. [XDP FIB Forwarding](#xdp-fib-forwarding)
11. [TLS/HTTPS](#tlshttps)
12. [Fleet Management: policy-controller](#fleet-management-policy-controller)
13. [Web Interface](#web-interface)
14. [GraphQL API Reference](#graphql-api-reference)

---

## Installation

### Choose a Package

Select one server package based on the features you need:

| Package | IPS/IDS | IPFIX |
|---------|:-------:|:-----:|
| `policy-engine` | — | — |
| `policy-engine-ips` | yes | — |
| `policy-engine-ipfix` | — | yes |
| `policy-engine-ips-ipfix` | yes | yes |

Install your chosen package and optional add-ons:

```bash
# Base install
sudo dpkg -i policy-engine_*.deb

# Optional: web UI
sudo dpkg -i policy-engine-web_*.deb

# Optional: fleet agent (managed deployments)
sudo dpkg -i policy-node-agent_*.deb
```

Install dependencies if needed:

```bash
sudo apt-get install -f
```

### Start the Service

```bash
sudo systemctl enable --now policy-engine
sudo systemctl status policy-engine
```

Verify it is running:

```bash
policy-client status
```

---

## Standalone Mode: policy-engine

The policy-engine daemon listens on `http://127.0.0.1:8080/graphql` by default.

### Configuration

Edit `/etc/policy-engine/config.toml`:

```toml
[server]
host = "127.0.0.1"
port = 8080
# Uncomment to enable TLS:
# tls_cert = "/etc/policy-engine/server.crt"
# tls_key  = "/etc/policy-engine/server.key"

# Uncomment to serve the web UI:
# web_root = "/usr/share/policy-engine-web"
```

To restrict API access with a bearer token:

```bash
echo "export POLICY_ENGINE_API_TOKEN=mysecrettoken" | sudo tee /etc/policy-engine/env
sudo systemctl restart policy-engine
```

Pass the token in client commands:

```bash
policy-client --token mysecrettoken status
# Or set the environment variable:
export POLICY_ENGINE_API_TOKEN=mysecrettoken
policy-client status
```

### Point the Client at a Remote Server

```bash
policy-client --server http://10.0.0.5:8080/graphql status
policy-client --server https://10.0.0.5:8443/graphql --tls-ca-cert /path/to/ca.crt status
policy-client --server https://10.0.0.5:8443/graphql --tls-insecure status
```

---

## Attaching to Network Interfaces

The policy-engine does nothing until you attach it to a network interface. XDP handles **ingress** (inbound traffic) and TC handles **egress** (outbound traffic).

### Attach XDP (Ingress)

```bash
# Auto-select best available mode (native > offload > generic)
policy-client attach ingress --interface eth0

# Explicit mode selection
policy-client attach ingress --interface eth0 --mode native
policy-client attach ingress --interface eth0 --mode generic  # always works, lower performance
policy-client attach ingress --interface eth0 --mode offload  # NIC hardware acceleration
```

### Attach TC (Egress)

```bash
policy-client attach egress --interface eth0
```

### List Attached Interfaces

```bash
policy-client show interfaces
```

### Detach

```bash
policy-client detach ingress --interface eth0
policy-client detach egress --interface eth0
policy-client detach all   # detach everything
```

---

## Managing Rules

### Add a Rule

```bash
# Drop all traffic from a CIDR
policy-client rule add --direction ingress --src 192.168.100.0/24 --action drop:0

# Allow traffic to a specific destination and port
policy-client rule add --direction ingress \
  --src 0.0.0.0/0 --dst 10.0.0.1 --dport 443 --proto tcp \
  --action pass:0

# Log all ICMP (no rate limit)
policy-client rule add --direction ingress --proto icmp --action log:0

# Log with rate limit (one log event per 5 seconds per rule)
policy-client rule add --direction ingress --src 10.0.0.0/8 --action log:5000

# Multiple actions: log then drop
policy-client rule add --direction ingress --src 10.0.0.100 --action log:0 --action drop:1

# Egress rules
policy-client rule add --direction egress --dst 8.8.8.8 --action pass:0
```

The action format is `ACTION:PRIORITY` where priority determines evaluation order within a rule (lower number = higher priority). For LOG, an optional third field is the rate-limit in milliseconds: `log:0:5000` limits to one log per 5 seconds.

### List Rules

```bash
policy-client rule list --direction ingress
policy-client rule list --direction egress
```

### Delete a Rule

```bash
# By rule ID (shown in rule list)
policy-client rule delete --direction ingress --id 1234567890

# By source CIDR (deletes all rules with that exact source)
policy-client rule delete --direction ingress --src 192.168.100.0/24
```

### Flush All Rules

```bash
policy-client rule flush --direction ingress
policy-client rule flush --direction egress
```

### Default Action

The default action applies to packets that do not match any rule.

```bash
# Drop unmatched packets (deny-by-default)
policy-client config default-action --action drop --direction ingress

# Allow unmatched packets (allow-by-default, the default)
policy-client config default-action --action pass --direction ingress
```

---

## Rule Matching

### IP Prefix Matching

Rules use Longest Prefix Match (LPM). A more specific prefix takes precedence.

```bash
# Block a /24, but allow a specific host within it
policy-client rule add --direction ingress --src 10.0.1.0/24 --action drop:0
policy-client rule add --direction ingress --src 10.0.1.42/32 --action pass:0
```

### Protocol Matching

```bash
policy-client rule add --direction ingress --proto tcp --action pass:0
policy-client rule add --direction ingress --proto udp --action drop:0
policy-client rule add --direction ingress --proto icmp --action log:0
policy-client rule add --direction ingress --proto icmpv6 --action pass:0
```

### Port Matching

```bash
# Drop inbound SSH
policy-client rule add --direction ingress --dport 22 --proto tcp --action drop:0

# Allow outbound HTTPS
policy-client rule add --direction egress --dport 443 --proto tcp --action pass:0

# Drop traffic from a specific source port
policy-client rule add --direction ingress --sport 53 --action drop:0
```

### IPv6

Rules apply to both IPv4 and IPv6 when using `--proto any` (the default). Specify an IPv6 CIDR for the source or destination to target IPv6 traffic specifically:

```bash
policy-client rule add --direction ingress --src 2001:db8::/32 --action drop:0
```

---

## Advanced Rule Features

### TLS SNI Matching

Match on the TLS Server Name Indication extension in ClientHello packets. This works for any TLS traffic (HTTPS, SMTP/TLS, etc.) without decryption.

```bash
# Exact match
policy-client rule add --direction ingress --sni "example.com" --action drop:0

# Wildcard suffix match (matches example.com, api.example.com, etc.)
policy-client rule add --direction ingress --sni "*.example.com" --action drop:0

# Allow only specific domain, drop everything else
policy-client rule add --direction ingress --dport 443 --sni "allowed.com" --action pass:0
policy-client config default-action --action drop --direction ingress
```

### QUIC Version Filtering

Filter QUIC (HTTP/3) traffic by protocol version:

```bash
# Block QUIC v1 (RFC 9000)
policy-client rule add --direction ingress --quic-version v1 --action drop:0

# Block QUIC v2 (RFC 9369)
policy-client rule add --direction ingress --quic-version v2 --action drop:0

# Block any QUIC version
policy-client rule add --direction ingress --quic-version any --action drop:0
```

### MAC Address Matching

Match on Layer 2 source or destination MAC address:

```bash
# Block traffic from a specific MAC
policy-client rule add --direction ingress --src-mac aa:bb:cc:dd:ee:ff --action drop:0

# Allow only traffic to a specific MAC
policy-client rule add --direction ingress --dst-mac 11:22:33:44:55:66 --action pass:0
```

### TTL Rules (Auto-Expiring)

Rules with a TTL expire and are removed automatically:

```bash
# Block an IP for 1 hour
policy-client rule add --direction ingress --src 198.51.100.1 --action drop:0 \
  --expires-after-secs 3600

# Temporary allow during maintenance (30 minutes)
policy-client rule add --direction ingress --src 10.0.5.0/24 --action pass:0 \
  --expires-after-secs 1800

# List rules with TTL or schedule
policy-client rule managed-rules --direction ingress
```

### Scheduled Rules

Rules that are only active during a weekly schedule window:

```bash
# Block during business hours (Mon-Fri 9am-5pm, Toronto timezone)
policy-client rule add --direction ingress --src 10.0.0.0/8 --action drop:0 \
  --schedule-window "1:09:00-5:17:00" --schedule-tz "America/Toronto"

# Allow access only on weekends
policy-client rule add --direction ingress --dst 10.0.5.100 --action pass:0 \
  --schedule-window "6:00:00-7:23:59" --schedule-tz "UTC"
```

Schedule format: `DAY:HH:MM-DAY:HH:MM` where DAY is 1=Monday through 7=Sunday.

---

## Statistics and Monitoring

### Global Interface Statistics

```bash
policy-client show stats --interface eth0 --direction ingress
policy-client show stats --interface eth0 --direction egress
```

Shows total packets, bytes, parse errors, and more.

### Per-Rule Statistics

```bash
# Stats for all rules
policy-client show rules --direction ingress

# Stats for a specific rule
policy-client show rule-stats --direction ingress --id 1234567890
```

### Performance Statistics

```bash
# Processing time histogram, bandwidth, per-protocol breakdown
policy-client show performance --interface eth0 --direction ingress
```

### Clear Statistics

```bash
policy-client clear-stats global --interface eth0 --direction ingress
policy-client clear-stats interface --interface eth0 --direction ingress
```

### Prometheus Metrics

The policy-engine exposes Prometheus metrics at `http://localhost:8080/metrics`. Scrape this with Prometheus or any compatible collector.

### Real-Time Event Stream

The WebSocket event stream at `ws://localhost:8080/ws/events` emits BPF ring buffer events in real time (rule matches, flow events, etc.). The web UI displays these in the Event Stream panel.

---

## Suricata IPS/IDS

Requires `policy-engine-ips` or `policy-engine-ips-ipfix` package.

### Enable IPS Mode

```bash
# Enable Intrusion Prevention System (Suricata alerts → DROP)
policy-client inspect enable --mode ips

# Enable Intrusion Detection System (alerts only, no blocking)
policy-client inspect enable --mode ids
```

Inspection only happens on interfaces that are explicitly enabled. With no
`--interface` flag, `inspect enable` enables every currently XDP-attached
interface (matching the historical node-global behaviour); pass one or more
`--interface` flags to scope it, or toggle interfaces individually:

```bash
policy-client inspect enable --mode ips --interface eth0 --interface eth1
policy-client inspect interface eth2 on
policy-client inspect interface eth0 off
```

### Configure Inspect Rules

Add INSPECT actions to rule(s) to select which traffic Suricata inspects:

```bash
# Inspect all HTTP traffic
policy-client rule add --direction ingress --dport 80 --proto tcp --action inspect:0

# Inspect traffic from untrusted subnet
policy-client rule add --direction ingress --src 203.0.113.0/24 --action inspect:0
```

Non-INSPECT traffic is never sent to Suricata and is not subject to IPS/IDS overhead.

### Check Status

```bash
policy-client inspect status
policy-client suricata status
```

### Deploy Custom Suricata Rules

```bash
# Deploy rules from a local file
policy-client suricata deploy-rules --file /path/to/my-rules.rules --name custom.rules

# Reload Suricata after rule changes
policy-client suricata reload
```

### View Active Verdicts

```bash
# Count of flows with cached verdicts
policy-client inspect verdicts --direction ingress

# List individual verdicts
policy-client inspect verdict-list --direction ingress
```

### Disable IPS/IDS

```bash
policy-client inspect disable
```

This destroys the `pe-inspect0`/`pe-inspect1` veth pair and stops Suricata inspection.

---

## IPFIX Flow Export

Requires `policy-engine-ipfix` or `policy-engine-ips-ipfix` package.

### Configure and Enable

```bash
# Enable flow export to a local collector on UDP 2055
policy-client config flow-export enable \
  --host 127.0.0.1 --port 2055 \
  --idle-timeout 30 --active-timeout 300

# Check status
policy-client show flow-export
```

### Disable

```bash
policy-client config flow-export disable
```

Flow records include: source IP, destination IP, source port, destination port, protocol, byte count, packet count, first seen, last seen timestamps.

---

## XDP FIB Forwarding

Enable line-rate packet forwarding on transit/router nodes. When enabled, packets that would `XDP_PASS` are forwarded via `bpf_fib_lookup()` at XDP speed, bypassing the kernel networking stack.

```bash
# Enable FIB forwarding
policy-client config fib-forward enable

# Check status
policy-client show fib-forward

# Disable
policy-client config fib-forward disable
```

This is useful when policy-engine runs on a transit node that routes traffic between networks.

---

## TLS/HTTPS

### Enable TLS on the Server

Generate or obtain a certificate, then configure:

```toml
# /etc/policy-engine/config.toml
[server]
tls_cert = "/etc/policy-engine/server.crt"
tls_key  = "/etc/policy-engine/server.key"
```

```bash
sudo systemctl restart policy-engine
```

### Client with TLS

```bash
# Trust a specific CA certificate
policy-client --server https://hostname:8080/graphql --tls-ca-cert /path/to/ca.crt status

# Skip certificate validation (testing only)
policy-client --server https://hostname:8080/graphql --tls-insecure status
```

---

## Fleet Management: policy-controller

The policy-controller manages a fleet of policy-engine nodes centrally. Each node runs `policy-node-agent` which connects to the controller and receives ruleset pushes.

### Controller Setup

Install the controller package:

```bash
sudo dpkg -i policy-controller_*.deb policy-controller-client_*.deb
sudo dpkg -i policy-controller-web_*.deb   # optional web UI
sudo apt-get install -f
```

Configure `/etc/policy-controller/config.toml`:

```toml
http_addr       = "0.0.0.0:8443"
enrollment_addr = "0.0.0.0:7776"
management_addr = "0.0.0.0:7777"
server_san      = "controller.yourdomain.com"
node_cert_ttl_days = 90
```

Start the controller:

```bash
sudo systemctl enable --now policy-controller
```

The CA key and certificate are generated automatically on first run at `/var/lib/policy-controller/ca.key` and `/var/lib/policy-controller/ca.crt`.

### Node Agent Setup

Agent enrollment is **zero-touch only**: the operator mints one short-lived
**bootstrap bundle**, distributes the same bundle file to every target host
via their existing config-mgmt (Ansible, Puppet, manual scp, whatever's
already running), and installs the package. The agent auto-enrols and
auto-approves with no operator clicks. There is no manual CA-cert-copy path
anymore — the agent runs under a hardened systemd unit (`ProtectSystem=strict`,
`DynamicUser=yes`) that makes operator-deposited files in `/etc/policy-node-agent/`
unwritable to the agent, so post-enrollment state has to live under
`/var/lib/policy-node-agent/`, which the bundle path delivers naturally.

The bundle carries the controller URL, a SHA-256 fingerprint of the controller
CA cert (pinned by the agent on the first TLS handshake — no pre-distributed
cert needed), and a random enrollment token scoped by TTL and max-uses.
See [ztp.md](ztp.md) for the security model.

**Step 1 — Mint a bundle on the operator workstation:**

```bash
policy-controller-client --url http://controller:8443 enroll-token create \
  --controller-url https://controller.yourdomain.com:7777 \
  --enrollment-url https://controller.yourdomain.com:7776 \
  --ttl 1h \
  --max-uses 50 \
  --label edge-fleet \
  --bundle-only > bundle.b64
```

Tunables:
- `--ttl` accepts `s`/`m`/`h`/`d` suffixes (`1h`, `30m`, `7d`). Pick the
  shortest window that covers your rollout.
- `--max-uses` caps how many nodes may redeem this token.
- `--cidr 10.0.0.0/8` (optional) restricts which source addresses may redeem.
- `--label` (optional) is applied to every node enrolled via this token.
- `--enrollment-url` is inferred from `--controller-url` (port `7777` → `7776`)
  if omitted.

The bundle is shown **exactly once**. Treat it like an SSH private key.

**Step 2 — Distribute the bundle to target hosts** via your existing
config-mgmt. The same file goes on every host in the rollout batch:

```bash
ansible -i fleet.ini -m copy \
  -a "src=bundle.b64 dest=/etc/policy-node-agent/bootstrap.bundle mode=0600" \
  edge-fleet
```

**Step 3 — Install the packages on each host:**

```bash
sudo dpkg -i policy-engine_*.deb policy-node-agent_*.deb
sudo apt-get install -f
sudo systemctl enable --now policy-engine
sudo systemctl enable --now policy-node-agent
```

That's it. The agent reads the bundle on startup, pins the CA fingerprint for
the enrollment TLS handshake, presents the token, receives auto-approved mTLS
credentials in the same response, persists them, and **deletes the consumed
bundle from disk**. The agent then joins the management stream.

**Step 4 — Manage tokens:**

```bash
# Inspect outstanding tokens (newest first)
policy-controller-client enroll-token list

# Revoke a token immediately if leaked
policy-controller-client enroll-token revoke <token_id>
```

Expired tokens drop off automatically; no cleanup is required.

The agent also accepts `--bootstrap-bundle /path/to/bundle.b64` on the CLI or
`POLICY_BOOTSTRAP_BUNDLE=/path/to/bundle.b64` in the environment, useful for
ad-hoc enrollments without a config-mgmt push.

### Reviewing enrollments

ZTP-enrolled nodes auto-approve and appear directly as `active`. To audit
what happened, the controller's audit log records `enrollment_token_created`,
`enrollment_token_redeemed`, and `enrollment_approved` events:

```bash
policy-controller-client audit list --limit 50
policy-controller-client nodes list --status active
```

A node that presents an invalid or expired token still lands in `pending`
(the token doesn't auto-approve, but the enrollment record is created so the
operator can investigate). To handle these cases:

```bash
policy-controller-client nodes list --status pending
policy-controller-client nodes approve <node_id> --label "office-gateway"
policy-controller-client nodes reject  <node_id> --reason "unrecognised hardware"
```

### Creating and Assigning Rulesets

Create a ruleset. The `--rules-json` value is a JSON array of rule objects in `AddRuleInput` format:

```bash
policy-controller-client rulesets create \
  --name "baseline-security" \
  --description "Block known bad actors" \
  --default-ingress drop \
  --rules-json '[
    {"direction":"INGRESS","src":"0.0.0.0/0","dst":"0.0.0.0/0",
     "sport":0,"dport":22,"protocol":"tcp",
     "actions":[{"action":"DROP","priority":0,"param":0}]},
    {"direction":"INGRESS","src":"10.0.0.0/8","dst":"0.0.0.0/0",
     "sport":0,"dport":0,"protocol":"any",
     "actions":[{"action":"PASS","priority":0,"param":0}]}
  ]'
```

Assign the ruleset to a node:

```bash
policy-controller-client rulesets assign <node_id> <ruleset_id>
```

Push the configuration to the node immediately:

```bash
policy-controller-client nodes push <node_id>
```

Push to all online nodes at once:

```bash
policy-controller-client nodes push-all
```

### Fleet Suricata IPS/IDS

Nodes running the `policy-engine-ips` package advertise a `suricata`
capability; the commands below are rejected for plain-engine nodes.

```bash
# Enable IPS (or "ids"/"off") on a node, then turn inspection on for an interface.
# Inspection only happens on enabled interfaces, and only for INSPECT-action
# rules (push those with the normal rule commands).
policy-controller-client inspect set-mode <node_id> ips
policy-controller-client inspect interface <node_id> eth0 on
policy-controller-client inspect status <node_id>

# Named fleet rulesets — stored centrally, materialised on assigned nodes as
# /etc/suricata/rules/policy-engine/fleet-<name>.rules (node-local rule files
# are never touched). Assigned nodes reconverge automatically on drift.
policy-controller-client suricata-rules create base --file ./base.rules
policy-controller-client suricata-rules assign <node_id> <ruleset_id>
policy-controller-client suricata-rules list
policy-controller-client suricata-rules push <node_id>       # force sync + confirm
policy-controller-client suricata-rules unassign <node_id> <ruleset_id>

# Central alert history (newest first).
policy-controller-client alerts list --limit 50
policy-controller-client alerts list --node-id <node_id> --min-severity 2
```

Alerts also stream live over the controller's `ws://controller:8443/ws/alerts`
(all nodes, or `?node=<id>`), and are queryable via the `suricataAlerts`
GraphQL query.

### Monitoring the Fleet

```bash
# List all nodes with status
policy-controller-client nodes list

# Show only active/online nodes
policy-controller-client nodes list --status active
policy-controller-client nodes online

# View audit log
policy-controller-client audit list --limit 50
```

### Decommissioning a Node

Decommissioning revokes the node's client certificate and blocks it from reconnecting:

```bash
policy-controller-client nodes decommission <node_id>
```

After decommission, the node can be permanently removed from the registry:

```bash
policy-controller-client nodes remove <node_id>
```

### Prometheus Metrics via Controller

The controller aggregates Prometheus metrics from all managed nodes:

```
# All nodes (concatenated)
curl http://controller:8443/metrics

# Specific node
curl http://controller:8443/metrics/node/<node_id>
```

### WebSocket Events via Controller

Connect to the controller's event stream to receive BPF events from all managed nodes:

```
# All nodes (events tagged with node_id)
ws://controller:8443/ws/events

# Filter to a specific node
ws://controller:8443/ws/events?node=<node_id>
```

---

## Web Interface

### policy-engine Web UI

Install `policy-engine-web` and configure `web_root` in `/etc/policy-engine/config.toml`. Then browse to `http://localhost:8080/`.

Panels:
- **Status** — daemon version, uptime, loaded features
- **Interfaces** — attach/detach XDP and TC programs
- **Rules** — add, list, delete rules with full field support
- **Statistics** — per-interface and per-rule counters
- **Performance** — processing time histogram, bandwidth, protocol breakdown
- **Event Stream** — real-time BPF event feed
- **Inspect (IPS)** — enable/disable Suricata, deploy rules _(IPS package only)_
- **FIB Forwarding** — toggle XDP forwarding
- **Flow Export** — IPFIX configuration _(IPFIX package only)_

### policy-controller Web UI

Install `policy-controller-web`. Browse to `http://controller:8443/`.

Pages:
- **Fleet Dashboard** — all nodes, online/offline status, health indicators
- **Enrollment Queue** — approve or reject pending nodes
- **Ruleset Editor** — create, edit, and delete rulesets
- **Node Detail** — per-node live stats, assigned ruleset, events; the IPS/IDS
  mode selector and per-interface inspection toggles appear here for
  suricata-capable nodes
- **Suricata Rules** — create/edit fleet Suricata rulesets and assign them to
  nodes, with per-node in-sync badges
- **IDS Alerts** — live + historical Suricata alerts across the fleet
- **Audit Log** — full mutation history

### GraphQL Playground

Both services expose a GraphQL Playground for ad-hoc queries:

- policy-engine: `http://localhost:8080/playground`
- policy-controller: `http://controller:8443/playground`

---

## GraphQL API Reference

### policy-engine Queries

```graphql
status                                  # daemon status
serverFeatures                          # compiled features (suricata, ipfix)
interfaces                              # attached interfaces
availableInterfaces                     # all system network interfaces
stats(interface: String!, direction: GqlDirection!)  # global counters
ethertypeStats(interface: String!, direction: GqlDirection!)
rules(direction: GqlDirection!)         # all rules + stats
managedRules(direction: GqlDirection!)  # TTL/scheduled rules
fibForwarding                           # FIB forwarding status (bool)
flowExportStatus                        # IPFIX config + active flows
inspectStatus                           # Suricata mode + veth info
performanceStats(interface, direction)  # histogram + proto breakdown
auditLog(limit: Int)
```

### policy-engine Mutations

```graphql
attachIngress(interface: String!, mode: XdpMode!)
detachIngress(interface: String!)
attachTc(interface: String!)
detachTc(interface: String!)
detachAll

addRule(direction, src, dst, sport, dport, protocol, actions, sni,
        quicVersion, srcMac, dstMac, expiresAfterSecs, scheduleWindow, scheduleTz)
addRules(rules: [AddRuleInput!]!)
deleteRule(direction, id, src)
deleteRules(rules: [DeleteRuleInput!]!)
flushRules(direction: GqlDirection!)
setDefaultAction(action: PolicyAction!, direction: GqlDirection!)

setFibForwarding(input: SetFibForwardingInput!)
configureFlowExport(input: FlowExportInput!)

configureInspect(mode: InspectMode!)
setInspectInterface(interface: String!, enabled: Boolean!)  # per-interface enable
disableInspect
deploySuricataRules(filename: String!, rules: String!)
reloadSuricataRules

clearGlobalStats(interface, direction)
clearRuleStats(ruleId, direction)
clearAllRuleStats(direction)
clearAllStats
```

### policy-controller Queries

```graphql
nodes(status: String)          # list nodes, optional status filter
node(id: ID!)                  # single node
pendingEnrollments             # enrollment queue
rulesets                       # all rulesets
ruleset(id: ID!)
auditLog(limit: Int, offset: Int)
caCertPem                      # controller CA PEM
onlineNodes                    # IDs of currently connected agents
enrollmentTokens               # ZTP bootstrap tokens (newest first)

# Suricata IPS/IDS (nodes with the "suricata" capability)
suricataRulesets               # all fleet Suricata rulesets
suricataRuleset(id: ID!)       # one ruleset, with content
nodeSuricataRulesets(nodeId: ID!)   # assigned rulesets + per-file inSync
nodeSuricataRuleFiles(nodeId: ID!)  # agent-reported rule files (fleet + local)
suricataAlerts(filter: SuricataAlertFilterInput, limit: Int)  # IDS alerts, newest first
```

`node(id:)` exposes `inspectMode` and the raw `capabilities` JSON;
`nodeInterfaces(nodeId:)` exposes `inspectEnabled` per interface.

### policy-controller Mutations

```graphql
approveEnrollment(nodeId: ID!, label: String)
rejectEnrollment(nodeId: ID!, reason: String)
decommissionNode(nodeId: ID!)
removeNode(nodeId: ID!)
labelNode(nodeId: ID!, label: String!)

createEnrollmentToken(enrollmentUrl: String!, controllerUrl: String!,
                      ttlSeconds: Int!, maxUses: Int!,
                      cidrScope: String, fleetLabel: String)
revokeEnrollmentToken(tokenId: ID!)

createRuleset(name, description, rulesJson, defaultActionIngress, defaultActionEgress)
updateRuleset(id, name, description, rulesJson, defaultActionIngress, defaultActionEgress)
deleteRuleset(id: ID!)
assignRuleset(nodeId: ID!, rulesetId: ID!)
unassignRuleset(nodeId: ID!)

pushConfig(nodeId: ID!)
pushConfigAll

# Suricata IPS/IDS (gated on the node's "suricata" capability)
setInspectMode(nodeId: ID!, mode: String!)              # "disabled"/"ips"/"ids"
setInspectInterface(nodeId: ID!, interfaceName: String!, enabled: Boolean!)
createSuricataRuleset(name: String!, content: String!)
updateSuricataRuleset(id: ID!, content: String!)
deleteSuricataRuleset(id: ID!)
assignSuricataRuleset(nodeId: ID!, rulesetId: ID!)
unassignSuricataRuleset(nodeId: ID!, rulesetId: ID!)
pushSuricataRulesets(nodeId: ID!)                       # force a sync + confirm
```
