# XDP Forward Mode

XDP Forward Mode enables line-rate packet forwarding for transit traffic on a
**per-ingress-interface** basis. When enabled on an interface, packets that
pass policy on that interface are forwarded via a kernel FIB lookup inside the
XDP program and redirected directly to the egress interface — bypassing the
kernel network stack entirely.

## How it works

Normally, when policy-engine passes a packet (`XDP_PASS`), the kernel's
routing subsystem handles forwarding: it consults the routing table, resolves
the next-hop via ARP/neighbour lookup, and hands the packet to the egress
driver. This involves several context switches and is bounded by the kernel's
per-packet processing overhead.

With XDP Forward Mode enabled on the ingress interface, the flow is:

1. `xdp_policy_main` evaluates the packet against policy rules.
2. If the verdict is pass, a BPF tail call transfers execution to
   `xdp_fib_dispatch` (XDP dispatcher slot 1).
3. `xdp_fib_dispatch` looks up the ingress ifindex in `fib_config_map` (hash
   map keyed by ifindex). If not present / disabled, it returns `XDP_PASS`.
4. If enabled, it calls `bpf_fib_lookup()` with the packet's L3 header to
   resolve the next-hop interface, source MAC, and destination MAC.
5. If the lookup succeeds, the Ethernet header is rewritten in-place (src/dst
   MACs updated, TTL/hop-limit decremented) and `bpf_redirect()` sends the
   packet directly to the egress interface — returning `XDP_REDIRECT`.
6. The packet never enters the kernel network stack.

The tail-call architecture keeps `xdp_policy_main` within the BPF verifier's
1 million processed-instruction limit by giving the FIB logic its own
independent budget.

### Fail-open behaviour

If `bpf_fib_lookup()` fails for any reason — ARP not yet resolved, no route,
multicast, etc. — the packet falls back to `XDP_PASS` and the kernel handles
it normally. Three global statistics counters track the outcome:

| Counter | Meaning |
|---|---|
| `fibForwardedPackets` / `fibForwardedBytes` | Packets successfully forwarded via `bpf_redirect()` |
| `fibFallbackPackets` | Packets where FIB lookup failed; fell back to `XDP_PASS` |

Both counters are visible in the Stats panel of the web UI and via the
`stats` GraphQL query.

## Policy interaction

DROP rules are always evaluated **before** the FIB stage. A packet that
matches a DROP rule is dropped at line rate and never reaches `xdp_fib_dispatch`.
PASS and LOG rules proceed to the FIB stage when forward mode is enabled on
the ingress interface.

### ⚠️ Interaction with egress TC filtering

Because forwarded packets are emitted directly from XDP via `bpf_redirect()`,
they **do not traverse the kernel TX path** on the outbound interface. This
means any **TC egress policy attached to the outbound interface is NOT
applied** to FIB-forwarded traffic. If you need egress policy to apply to
transit traffic, leave FIB forwarding disabled on the ingress interface so
packets take the normal routing path.

## Enabling via the web UI

On the engine dashboard, the **XDP Forward Mode** panel lists every attached
ingress interface with its own toggle. On the controller fleet UI, each
interface row in the per-node detail view has an `FWD on/off` toggle next to
its XDP attachment indicator. When FIB forwarding is active the XDP label
switches to `XDP[FWD]`, and hovering the label shows the TC-bypass warning.

## Enabling via GraphQL

```graphql
mutation {
  setFibForwarding(input: { interface: "eth0", enabled: true }) {
    success
    message
  }
}
```

Query current state (per interface):

```graphql
query {
  fibForwarding {
    interface
    enabled
  }
}
```

## Enabling via the CLI

```bash
policy-client fib-forwarding enable eth0
policy-client fib-forwarding disable eth0
policy-client fib-forwarding status
```

## Requirements

- Linux kernel 5.2 or later (`bpf_fib_lookup` with full params support).
- The interface must have XDP attached (`attachIngress`). Enabling FIB
  forwarding on an interface without XDP attached has no effect.
- The kernel routing table and ARP/neighbour cache must be populated normally;
  XDP Forward Mode accelerates forwarding but does not replace routing
  configuration.

## Persistence

XDP Forward Mode state is stored in a BPF hash map (`fib_config_map`, keyed
by ifindex) pinned to `/sys/fs/bpf/policy_engine/`. It survives policy-engine
restarts as long as the pinned BPF state is not cleaned up (i.e. the BPF
program version has not changed). After a software upgrade that changes the
BPF programs, all configuration must be reapplied. The controller also
persists the per-interface enabled set in its SQLite store (`node_interfaces.
fib_forwarding`) and re-pushes it to the agent after restart.
