# uRPF — Unicast Reverse Path Forwarding

uRPF drops source-spoofed packets at line rate inside the XDP program. When
enabled on an **ingress** interface, every IPv4/IPv6 packet's *source* address
is checked against the kernel routing table (FIB): if there is no legitimate
route back to that source, the packet is dropped before it reaches policy
evaluation or the kernel network stack.

This blocks whole classes of source-address spoofing and reflection/DDoS
traffic, and implements the BCP 38 / RFC 3704 ingress-filtering model in the
data path. See <https://en.wikipedia.org/wiki/Reverse-path_forwarding>.

## Modes

uRPF is configured **per ingress interface** and has three modes:

| Mode | Behaviour |
|---|---|
| `off` | No reverse-path check (default). |
| `loose` | Drop only if **no route to the source exists via any interface**. Catches fully unroutable / bogon / martian sources while tolerating asymmetric routing. |
| `strict` | Drop unless the best route back to the source **exits via the interface the packet arrived on**. Strongest anti-spoofing, but will drop legitimately asymmetrically-routed flows. |

Choose **strict** on edge/access interfaces where traffic is expected to be
symmetric (e.g. a customer-facing port that should only ever source its own
prefix). Choose **loose** on transit/peering interfaces where routing may be
asymmetric but you still want to drop traffic from unroutable sources.

## How it works

uRPF runs early in `xdp_policy_main`, right after the packet's flow key is
parsed and before the flow-verdict cache and policy lookup — so spoofed traffic
is discarded as cheaply as possible:

1. `xdp_policy_main` parses the L3 header and looks up the ingress ifindex in
   the per-interface config map. If uRPF is `off` for that interface (the
   common case) the check is a single hash-map lookup and processing continues
   normally.
2. If uRPF is `loose` or `strict`, `xdp_urpf_check()` issues a
   `bpf_fib_lookup()` in **output** mode (`BPF_FIB_LOOKUP_OUTPUT`) using the
   packet's **source** address as the lookup destination — i.e. "if this node
   originated a packet to that source, which route/interface would it use?".
   Output mode is used deliberately rather than the forwarding (input) lookup:
   the input lookup only returns a usable route when IP forwarding is enabled,
   so on an ordinary host (forwarding off) it would make uRPF drop *all* inbound
   traffic. Output mode works on hosts and routers alike and honours
   policy-routing (`ip rule`) tables, not just the main table.
3. A route is considered to exist if the lookup returns `BPF_FIB_LKUP_RET_SUCCESS`
   or `BPF_FIB_LKUP_RET_NO_NEIGH` (uRPF cares about the route, not whether the
   L2 neighbour is resolved yet).
   - **loose**: pass if any route exists; otherwise drop.
   - **strict**: pass only if the returned egress ifindex equals the ingress
     ifindex; otherwise drop.
4. On failure the packet returns `XDP_DROP` and per-interface drop counters are
   incremented. On success processing continues to the policy lookup.

### Ingress only

uRPF is an **XDP ingress** feature and is **never** applied on the TC egress
path — reverse-path filtering on egress is meaningless. The engine rejects an
attempt to enable uRPF on an interface that has no XDP program attached (e.g. a
TC egress-only interface) with an explicit error.

### Storage

The per-interface uRPF mode is stored alongside the FIB-forwarding mode in the
shared `fib_config_map` BPF hash map (keyed by ifindex, pinned under
`/sys/fs/bpf/policy_engine/`). A single map lookup therefore covers both XDP
ingress features. The entry survives policy-engine restarts as long as the
pinned BPF state is intact; after a BPF program upgrade the configuration must
be reapplied. The controller also persists the per-interface uRPF mode in its
SQLite store (`node_interfaces.urpf_mode`) and re-pushes it to the agent after a
restart.

## Metrics

Every packet dropped by the reverse-path check is counted per interface:

| Counter | Meaning |
|---|---|
| `urpf_drop_packets` | Packets dropped because they failed the uRPF check |
| `urpf_drop_bytes` | Bytes dropped because they failed the uRPF check |

These are exported on the engine `/metrics` endpoint as
`policy_engine_urpf_drop_packets_total` / `policy_engine_urpf_drop_bytes_total`
(labelled by `interface` and `direction`), surfaced in the `stats` GraphQL
query (`urpfDropPackets` / `urpfDropBytes`), and shown in the **uRPF** section
of the Stats panel in both web UIs (only when non-zero).

## Caveats

- **ECMP / multipath**: `bpf_fib_lookup()` returns a single egress interface.
  On a host with equal-cost multipath routes to a source, strict mode may drop
  traffic that arrived on a valid-but-different member link. Prefer loose mode
  in ECMP environments.
- **Asymmetric routing**: strict mode drops legitimate traffic whose return
  path differs from its arrival interface. Use loose mode where asymmetry is
  expected.
- **Routing table dependence**: uRPF accelerates filtering but relies on the
  kernel FIB being correctly populated. A missing or default-only route can
  cause loose mode to pass (default route) or strict mode to drop.
- **Control / non-unicast traffic is exempt**: uRPF is a *unicast* check, so
  traffic that is never unicast-forwarded bypasses it. The exemptions are
  evaluated only when uRPF is enabled on the interface (nothing is added to the
  disabled fast path), and only the listed source/destination cases are skipped
  — a multicast/broadcast *source* is still treated as a martian and dropped.

  | Family | Exempted | Covers |
  |---|---|---|
  | IPv6 | source `fe80::/10`; destination `ff00::/8` | NDP, SLAAC/DAD (the `::` source goes to a solicited-node multicast address), MLD, RS/RA |
  | IPv4 | source `0.0.0.0`; source `169.254.0.0/16`; destination `255.255.255.255`; destination `224.0.0.0/4` | DHCP/BOOTP, RFC 3927 link-local, limited broadcast, multicast |

  Without these, enabling uRPF would break IPv6 neighbour discovery / address
  autoconfiguration and IPv4 DHCP on the protected segment.

## Enabling via the web UI

On the engine dashboard, the **uRPF (Reverse Path Filtering)** panel lists every
attached ingress interface with an Off / Loose / Strict selector. On the
controller fleet UI, each ingress interface row in the per-node detail view has
a `uRPF off/loose/strict` dropdown next to its XDP attachment indicator and the
`FWD` (FIB forwarding) toggle.

## Enabling via GraphQL

Engine:

```graphql
mutation {
  setUrpf(input: { interface: "eth0", mode: STRICT }) {
    success
    message
  }
}

query {
  urpf {
    interface
    mode
  }
}
```

Controller (per node):

```graphql
mutation {
  setUrpf(nodeId: "<node-id>", interfaceName: "eth0", mode: "strict") {
    success
    message
  }
}
```

## Requirements

- Linux kernel 5.2 or later (`bpf_fib_lookup` with full params support).
- The interface must have XDP attached (`attachIngress`). uRPF cannot be enabled
  on an interface without an XDP program.
- The kernel routing table must be populated normally; uRPF consults the FIB but
  does not configure routing.
- IP forwarding does **not** need to be enabled: the check uses an output-route
  lookup, so uRPF works on ordinary hosts and edge nodes, not just routers.

## Relationship to XDP Forward Mode

uRPF and [XDP Forward Mode](xdp-forward-mode.md) are independent per-interface
ingress features that share the same config map. uRPF runs first (on packet
ingress); FIB forwarding runs last (at the `XDP_PASS` exit). Both can be enabled
on the same interface: spoofed traffic is dropped by uRPF before it can be
forwarded.
