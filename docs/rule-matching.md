# Rule Matching

This is the single reference for how policy-engine matches packets against
rules — from the match dimensions an operator configures, down through the
XDP/TC data plane, the two-level LPM trie, the action loop, and the
protocol-specific matchers (MAC, TLS SNI, QUIC) and rule lifecycle (TTL and
schedules).

For the high-level system picture (binaries, fleet controller, packaging) see
[ARCHITECTURE.md](ARCHITECTURE.md). For FIB forwarding of passed packets see
[xdp-forward-mode.md](xdp-forward-mode.md).

## Contents

- [Match dimensions](#match-dimensions)
- [The data plane](#the-data-plane)
  - [XDP and TC programs](#xdp-and-tc-programs)
  - [Tail-call slots](#tail-call-slots)
  - [Packet processing pipeline](#packet-processing-pipeline)
  - [Two-level LPM architecture](#two-level-lpm-architecture)
  - [BPF map constants](#bpf-map-constants)
- [Actions and the action loop](#actions-and-the-action-loop)
- [MAC matching](#mac-matching)
- [SNI matching](#sni-matching)
- [Timed rules](#timed-rules)

---

## Match dimensions

Each rule matches on any combination of the following. Omitting a field makes
it a wildcard. Together the IP 5-tuple plus the two MAC fields give full
**7-tuple matching**, with SNI and QUIC version as further optional
constraints.

| Field | Type | Wildcard | Notes |
|-------|------|----------|-------|
| `src` | Source IPv4/IPv6 CIDR prefix (LPM) | `0.0.0.0/0` or omit | Level-1 LPM key |
| `dst` | Destination IPv4/IPv6 CIDR prefix (LPM) | `0.0.0.0/0` or omit | Level-2 LPM key |
| `sport` | Source port | `0` or omit | |
| `dport` | Destination port | `0` or omit | |
| `protocol` | `tcp` / `udp` / `icmp` / `icmpv6` / `any` | `any` | |
| `sni` | TLS Server Name Indication | omit | exact or `*.suffix`; see [SNI matching](#sni-matching) |
| `quic_version` | QUIC version filter (`v1`, `v2`, or specific value) | omit | UDP only |
| `srcMac` | 6-byte source MAC address | omit | exact; see [MAC matching](#mac-matching) |
| `dstMac` | 6-byte destination MAC address | omit | exact; see [MAC matching](#mac-matching) |

All fields compose orthogonally — e.g. a rule may constrain source prefix,
destination port, SNI, and source MAC simultaneously, and **all** specified
fields must match for the rule to fire.

---

## The data plane

### XDP and TC programs

Two programs run in the kernel fast path:

- **XDP (ingress):** `xdp_policy_main` — attached to the interface receive path
  via the XDP hook. Processes packets before the kernel networking stack.
  Returns `XDP_PASS`, `XDP_DROP`, or `XDP_REDIRECT`.
- **TC egress:** `tc_policy_main` — attached to the TC (Traffic Control)
  subsystem on the transmit side. Returns `TC_ACT_OK` (pass) or `TC_ACT_SHOT`
  (drop).

Both use a **tail-call dispatcher** to offload optional processing (SNI
inspection, QUIC mirroring, FIB forwarding) to separate programs, keeping each
program within the BPF verifier's 1M processed-instruction limit by giving the
offloaded logic its own independent instruction budget.

Source: `src/bpf/xdp_policy.bpf.c`, `src/bpf/tc_policy.bpf.c`, shared types in
`src/bpf/include/policy_common.h`.

### Tail-call slots

| Direction | Slot | Program | Purpose |
|-----------|------|---------|---------|
| XDP | 0 | `xdp_sni_inspect` | TLS SNI matching (TCP) |
| XDP | 1 | `xdp_fib_dispatch` | Line-rate FIB forwarding (see [xdp-forward-mode.md](xdp-forward-mode.md)) |
| XDP | 3 | `xdp_quic_initial_inspect` | Mirror QUIC client Initials to userspace |
| TC | 0 | `tc_sni_inspect` | TLS SNI matching (egress, TCP) |
| TC | 2 | `tc_quic_initial_inspect` | Mirror QUIC client Initials to userspace |

### Packet processing pipeline

```
Packet arrives
    │
    ▼
Parse L2 (Ethernet, VLAN)
    │
    ▼
Parse L3 (IPv4 / IPv6) → update per-L3 stats
    │
    ▼
Parse L4 (TCP / UDP / ICMP / QUIC detection)
    │
    ▼
Check flow_verdict_cache (per-flow fast-path: plain L4, SNI, Suricata IPS/IDS)
    │ Cache hit → apply cached verdict (PASS or DROP), bump rule_stats, return
    │ Cache miss ↓
    ▼
Two-level LPM lookup:
    Level 1: src_lpm_v4/v6  → src_group_id
    Level 2: src_groups_v4/v6[group_id] → dst LPM → L4 rules
    (Ancestor walk: up to 8 levels per trie for prefix fallback)
    │
    ▼
For each matching L4 rule (priority order):
    ├── PASS    → update stats, continue to next rule
    ├── DROP    → update stats, stop, return XDP_DROP / TC_ACT_SHOT
    ├── LOG     → update stats, rate-limit check, emit ring buffer event
    └── INSPECT → write to flows_to_inspect, seed PASS in verdict cache
    │
    ▼
SNI / QUIC matching (tail call if rule carries an SNI pattern)
    │
    ▼
Default action (per-interface, configured)
    │
    ▼
FIB forwarding (tail call if enabled on the ingress interface)
    │
    ▼
Return XDP_PASS / XDP_DROP / XDP_REDIRECT  (or TC_ACT_OK / TC_ACT_SHOT)
```

### Two-level LPM architecture

IP matching uses a two-level Longest Prefix Match trie to support independent
source and destination prefixes without the exponential blowup of a combined
trie.

```
src_lpm_v4  (LPM_TRIE)
  key: src_ip / prefixlen
  value: { src_prefixlen, src_group_id }
      │
      └─→ src_groups_v4 (HASH_OF_MAPS)
            key: src_group_id
            value: inner map (dst_lpm_v4_inner, LPM_TRIE)
                      key: dst_ip / prefixlen
                      value: { dst_prefixlen, count, rules[MAX_L4_RULES] }
                                              │
                                              └─→ l4_rule[] {
                                                    sport, dport, protocol
                                                    sni_match_type, rule_id
                                                    priority, actions[]
                                                  }
```

Both levels use ancestor walking (up to `MAX_LPM_ANCESTORS = 8`), so a packet
from `10.1.2.3` will match rules for `10.1.2.0/24`, `10.1.0.0/16`,
`10.0.0.0/8`, and `0.0.0.0/0` in order of specificity.

The `l4_rule` struct is kept at **96 bytes**. MAC fields live in a separate
sidecar map (see [MAC matching](#mac-matching)) rather than inline, to avoid
exceeding the BPF branch-range limit (±32 767 instructions) in the
aggressively-unrolled rule scan loops.

### BPF map constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SRC_GROUPS` | 4096 | Level-1 source prefix groups |
| `MAX_DST_ENTRIES_PER_GROUP` | 512 | Destination prefixes per source group |
| `MAX_L4_RULES` | 8 | L4 rules per destination prefix |
| `MAX_LPM_ANCESTORS` | 8 | Ancestor walk depth |
| `MAX_ACTIONS_PER_RULE` | 4 | Actions per rule |
| `MAX_FLOW_VERDICTS` | 65536 | Verdict cache entries (per direction) |
| `MAX_FLOWS_TO_INSPECT` | 65536 | Flows queued for Suricata |
| `MAX_SNI_LEN` | 128 | TLS SNI pattern bytes |
| `SNI_PULL_MAX` | 4096 | `bpf_skb_pull_data` ceiling for TC SNI inspect |

---

## Actions and the action loop

| Action | Value | Effect | Terminal? |
|--------|-------|--------|-----------|
| `PASS` | 0 | Allow packet, continue to next action / rule | no |
| `DROP` | 1 | Drop packet silently; selected as the final verdict | **yes** |
| `LOG` | 2 | Emit a ring-buffer `PolicyEvent`, allow packet. Optional `param`: rate-limit interval in nanoseconds since the last LOG for that rule (0 = unlimited) | no |
| `INSPECT` | 3 | Mirror packet to Suricata for deep inspection. Requires the IPS package. | no |

A matched rule carries up to `MAX_ACTIONS_PER_RULE = 4` actions, walked in
priority order. The loop semantics are **`LOG → DROP → PASS`**: `LOG` and
`PASS` continue, `DROP` is terminal and stops evaluation. After the loop, the
final action (PASS by default, DROP if any DROP fired) is what gets applied and
cached.

### Verdict cache

The cache is the per-flow fast path for **every** verdict source, not just the
heavy matchers. After the first packet of a flow resolves its verdict, the
action is written to `flow_verdict_cache` (XDP) / `tc_flow_verdict_cache` (TC),
keyed by the captured 5-tuple:

```
key       = FlowVerdictKey from the captured 5-tuple
action    = final action (PASS / DROP)
rule_id   = matched rule (0 for the default-action path / SNI / IPS)
expires   = now + TTL
direction = Ingress (XDP) or Egress (TC)
```

Three classes of writer populate it:

1. **Plain policy (L3 prefix + L4 port)** — `xdp_policy_write_verdict` /
   `tc_policy_write_verdict` seed the PASS/DROP from the two-level LPM walk (and
   the per-interface default action) so that the **O(ancestors²) trie walk runs
   at most once per flow**. This is the common case and the reason the cache
   exists in non-IPS builds. Only *cacheable* flows are seeded — a rule carrying
   a `LOG`, `INSPECT`, or `TAIL_CALL` action clears the `cacheable` flag in
   `process_rule_actions` so those flows keep re-evaluating every packet
   (per-packet logging, IPS mirroring). SNI rules go through the tail-call path
   and are seeded there.
2. **SNI inspectors** — `xdp_sni_inspect` / `tc_sni_inspect` (TCP) and
   `process_quic_sample` (UDP/QUIC) after the ClientHello is matched.
3. **Suricata IPS** — the EVE consumer writes DROP verdicts; the `INSPECT`
   action seeds a short PASS so the flow isn't re-mirrored on every packet.

On a hit the dataplane bumps the per-verdict `packets`/`bytes`, the global
`verdict_pass`/`verdict_drop` and `policy_pass`/`policy_drops` counters, and —
when `rule_id != 0` — `rule_stats[rule_id]` and the global `policy_matches`
counter. So per-rule and per-action counters stay accurate per packet even
though rule evaluation is skipped; a cached hit counts identically to a fresh
LPM match. (`rule_id == 0` — the default-action path, or SNI/IPS verdicts —
does not bump `rule_stats`/`policy_matches`, since no policy rule matched.)

TTLs:

| State | TTL | Set by |
|-------|-----|--------|
| Plain policy verdict (PASS / DROP, incl. default action) | **never** (0) | `POLICY_VERDICT_EXPIRES_NS` |
| SNI flow verdict (PASS / DROP, both transports) | 10 min | `SNI_VERDICT_TTL_NS` / `QUIC_VERDICT_TTL_NS` |
| Suricata INSPECT initial PASS verdict | 30 s | `INSPECT_PASS_VERDICT_TTL_NS` |
| Suricata flow entry in `flows_to_inspect` | 5 min | `INSPECT_CLONE_TTL_NS` |

Plain policy verdicts **never expire on time**: a PASS/DROP is a deterministic
function of the 5-tuple and the current rule set, which is flushed from the cache
the moment it changes (see below), and capacity is bounded by LRU eviction — so
there is no time-based reason to drop them. SNI/QUIC verdicts *do* expire (10
min) because they are keyed by the 5-tuple but decided by the SNI hostname, which
is **not** part of the key: a reused 5-tuple (ephemeral-port reuse to a CDN /
SAN-shared IP) can carry a different hostname on a later connection, and
rule-change flushing does not cover that (the rules didn't change, the connection
did). IPS/IDS verdicts keep short TTLs so Suricata re-inspects periodically.

The cache maps are **`LRU_HASH`** (not plain `HASH`). With every flow seeded and
plain policy verdicts never expiring, a plain hash would fill to
`MAX_FLOW_VERDICTS` and reject new inserts; LRU instead evicts the
least-recently-used entry under pressure (dead flows, which aren't being hit, go
first). Eviction is always safe — an evicted flow simply pays one more LPM walk
on its next packet, and the walk is the authoritative fallback.

BPF maps don't auto-expire on time, so the dataplane still treats an expired hit
as a miss and re-evaluates, and the stale entry persists until userspace deletes
it. `FlowVerdictManager` (`flow_verdict_manager.rs`) is the evictor: a background
sweep started in `http.rs` removes expired entries from both directions every
30 s, using `CLOCK_MONOTONIC` to match the `bpf_ktime_get_ns()` `expires_ns`.
It runs in **every build**.

**Invalidation on rule change.** Because non-IPS verdicts are long-lived, any
rule mutation must flush them or a stale verdict would outlive the rule set that
produced it. `PolicyService::invalidate_flow_verdicts` (→ `clear_flow_verdicts`)
is called after every BPF-map policy change — `add_rule`, `add_rules_batch`,
`delete_rule`, and the TTL/schedule transitions in `handle_timer_expiry` — for
the affected direction. (It sweeps the whole per-direction cache; a per-rule-set
generation counter checked in BPF would avoid the sweep if bulk runtime edits
over a hot cache ever become a bottleneck.)

#### Inspecting the cache

The cache contents are visible end-to-end:

```bash
# Single host — count, then the individual entries (soonest-expiring first)
policy-client inspect verdicts --direction ingress
policy-client inspect verdicts --direction ingress --list --limit 1000

# Fleet — read a node's live cache through the controller
policy-controller-client verdicts <node-id> --direction ingress --limit 1000
```

The GraphQL surface is `flowVerdictList(direction, limit)` on the engine and
`nodeFlowVerdicts(nodeId, direction, limit)` on the controller. Because the
cache is live BPF state (not part of the periodic Prometheus snapshot), the
controller query issues an on-demand `FlowVerdictQuery` to the node's agent and
waits for the reply — so it errors if the node is offline. Both the policy-engine
web UI (Inspect panel) and the policy-controller web UI (per-node **Verdict
Cache** tab) render the same data. Results are capped at `limit` (default 1000).

### Per-rule stats

On every match, both directions bump `rule_stats` / `tc_rule_stats` (a plain
HASH, not per-CPU): `packets += 1`, `bytes += pkt_len`, `last_seen_ns = now`.
This keeps `policy-client show rule-stats` accurate for every transport. TCP
does this in BPF (`tc_update_rule_stats`); the QUIC userspace path does it via
`BpfOperations::bump_rule_stats`.

---

## MAC matching

MAC fields are an optional Layer 2 extension to the IP 5-tuple. Both are
always optional; omitting a field matches any MAC (wildcard). If both are set,
**both must match**.

### Format

Colon-separated lowercase hexadecimal octets: `aa:bb:cc:dd:ee:ff`.

All-zeros (`00:00:00:00:00:00`) is **not** a valid filter value — it means
wildcard in the BPF representation. Pass the field as `null` / omit it instead.

### Direction

MAC matching works on both ingress (XDP) and egress (TC):

- **Ingress:** `srcMac` is the sender's MAC; `dstMac` is the receiving
  interface's MAC.
- **Egress:** `srcMac` is the sending interface's MAC; `dstMac` is the
  next-hop (peer NIC on the same L2 segment).

### Implementation

MAC fields live in a **sidecar BPF hash map** (`mac_rules` for ingress,
`tc_mac_rules` for egress), keyed by `rule_id`, consulted *after* the L4 match
identifies the rule. This keeps the main `l4_rule` struct at 96 bytes and
avoids exceeding the BPF branch-range limit in the unrolled rule loops.

The check runs in a dedicated `__noinline` subprogram (`check_mac_rule_xdp` /
`check_mac_rule_tc`), so each call from the rule scan loop is a single BPF call
instruction rather than inline code. Rules without MAC fields
(`mac_match_flags == 0`) incur only a single predicted-not-taken branch —
effectively zero overhead at XDP line rates.

`eth->h_source` and `eth->h_dest` are at Ethernet frame offset 0 regardless of
VLAN tags, so MAC matching is correct for both tagged and untagged frames.

### Limitations

- **Exact match only** — OUI/prefix matching (e.g. `aa:bb:cc:xx:xx:xx/24`) is
  not supported. The sidecar map value reserves bytes for a future
  prefix-length field.
- **IP LPM required** — a pure L2 MAC rule still needs an IP LPM entry to be
  reached. Use `src: "0.0.0.0/0"` / `dst: "0.0.0.0/0"` when MAC is the only
  criterion.

### Configuration

```bash
# Drop all inbound traffic from a specific MAC
policy-client rule add --direction ingress \
    --src 0.0.0.0/0 --action drop:0 \
    --src-mac aa:bb:cc:dd:ee:ff

# Drop outbound traffic to a specific destination MAC
policy-client rule add --direction egress \
    --src 0.0.0.0/0 --action drop:0 \
    --dst-mac 11:22:33:44:55:66

# Combine src and dst — both must match
policy-client rule add --direction ingress \
    --src 10.0.0.0/8 --action drop:0 \
    --src-mac aa:bb:cc:dd:ee:ff \
    --dst-mac 11:22:33:44:55:66
```

```graphql
mutation {
  addRule(input: {
    direction: INGRESS
    src: "0.0.0.0/0"
    protocol: "any"
    actions: [{ action: DROP, priority: 0 }]
    srcMac: "aa:bb:cc:dd:ee:ff"
  }) { success message }
}
```

MAC fields appear (null when unset) in both the `rules` and `managedRules`
query responses as `srcMac` / `dstMac`.

---

## SNI matching

Rules with an `sni` criterion match TLS Server Name Indication on both
transports:

- **TCP TLS** — parsed in-kernel by `xdp_sni_inspect` / `tc_sni_inspect`,
  walking the ClientHello directly out of the skb / `xdp_md` buffer.
- **UDP QUIC** — Initial packets are AEAD-protected, so BPF ships every client
  Initial to userspace, which derives the per-Initial keys, decrypts,
  reassembles CRYPTO fragments, and extracts the SNI.

Both paths converge on the same `sni_rules` / `tc_sni_rules` map (patterns are
configured once), the same `LOG → DROP → PASS` action loop, the same
`flow_verdict_cache` fast-path short-circuit, and the same `rule_stats`
counters (see [Actions and the action loop](#actions-and-the-action-loop)).

```
                    ┌─────────────────────────────────────────────┐
                    │              BPF (XDP / TC)                 │
  client → server ──┤   main → rule lookup → has sni? ───┐         │
                    │                                     ▼         │
                    │   TCP: bpf_tail_call(SNI_SLOT)                │
                    │   UDP: bpf_tail_call(QUIC_SLOT)               │
                    │                                     │         │
                    │   ┌─────────────────────────────────┘         │
                    │   ▼                                           │
                    │   TCP:                  UDP/QUIC:             │
                    │   tc_sni_inspect        tc_quic_initial_inspect
                    │   bpf_skb_pull_data     header-only checks    │
                    │   parse TLS CH inline   ringbuf-emit Initial  │
                    │   match SNI            (every Initial in burst)
                    │   walk actions[]                              │
                    │   write verdict cache                         │
                    │   bump rule_stats                             │
                    │   LOG → events ringbuf                        │
                    └──────────────────────┬────────────────────────┘
                                           │ (UDP path only)
                                           ▼
                    ┌─────────────────────────────────────────────┐
                    │            userspace (policy-engine)         │
                    │   quic_inspect_events ringbuf consumer →    │
                    │     derive Initial keys (HKDF + AES-128-GCM) │
                    │     decrypt; append CRYPTO chunks to         │
                    │     ReassemblyTable[(5-tuple, DCID)]         │
                    │     parse ClientHello, extract server_name   │
                    │     match against sni_rules mirror           │
                    │     walk actions[] (DROP terminal)           │
                    │     update_flow_verdict (60 s)               │
                    │     bump_rule_stats                          │
                    │     LOG → broadcast(PolicyEvent)             │
                    └─────────────────────────────────────────────┘
```

### `evt->verdict` is a `PolicyAction` enum

The event struct's `verdict` field is decoded in userspace as
`PolicyAction { Pass=0, Drop=1, Log=2 }` — **not** as a TC/XDP return code. All
four event-emission sites translate `final_verdict`
(`TC_ACT_OK`/`TC_ACT_SHOT`, `XDP_PASS`/`XDP_DROP`) to `ACTION_PASS` /
`ACTION_DROP` before storing, because the numeric values collide
(`TC_ACT_SHOT = 2` would render as `LOG`, `XDP_PASS = 2` likewise).

### TCP path

`xdp_sni_inspect` (XDP ingress) and `tc_sni_inspect` (TC egress) are dispatcher
tail-call targets (XDP slot 0, TC slot 0). The main program queues every rule
whose `sni_match_type != SNI_MATCH_NONE` into `pkt_scratch.sni_pending[]`, then
tail-calls the inspector once. The inspector parses the ClientHello once and
checks each pending rule's SNI pattern in turn.

#### `match_sni_in_packet`

In-kernel walk of the TLS handshake (`include/policy_common.h`):

```
TCP header           — read doff via direct byte access, advance off
TLS Record           — content_type==0x16 (Handshake), advance 5
Handshake header     — msg_type==0x01 (ClientHello), advance 4
ClientHello fixed    — legacy_version[2] + random[32]
session_id           — sid_len[1] + sid[0..32]
cipher_suites        — csl[2] + suites[csl]
compression_methods  — cml[1] + methods[cml]
extensions           — total[2], then walk up to MAX_TLS_EXTENSIONS items
                      looking for type 0x0000 (server_name, RFC 6066 §3)
```

Verifier discipline that's non-obvious from the source:

- All packet offsets are kept as scalars, repeatedly bounds-checked against
  `0x3000` so the verifier narrows the tnum at each step.
- Each iteration of the extension scan **rebuilds** the packet pointer from a
  freshly-narrowed scalar (`safe_off &= 0x3fff` with an asm barrier to force a
  real `AND`), because adding a runtime variable to a `pkt_ptr` always resets
  the verifier's range tracking to 0.
- `bpf_skb_load_bytes` is not used here — the parser reads directly from
  `data..data_end` for performance.

#### `bpf_skb_pull_data` for TSO/GSO

On TC egress, the kernel hands BPF a single super-skb for whatever the TCP
stack queued for TSO segmentation. The linear region typically holds only
L2/L3/L4 headers (~50–60 bytes); the rest sits in paged fragments inaccessible
via direct packet access.

Modern TLS 1.3 ClientHellos are large — a Brave→Google CH runs ~2 KB because
the post-quantum `X25519MLKEM768` `key_share` extension alone is ~1.3 KB.
`server_name` lands in the second segment of any naive parse, beyond the linear
region. `tc_sni_inspect` therefore calls `bpf_skb_pull_data(ctx, min(ctx->len,
SNI_PULL_MAX))` (`SNI_PULL_MAX = 4096`) before reading `ctx->data` /
`ctx->data_end`, then re-reads the pointers since pull may have moved them. XDP
doesn't need this — it operates on raw frame buffers below the TCP stack, with
no GSO super packets.

#### LOG emission

`tc_emit_event` reserves a `policy_event` on the `tc_events` ringbuf with
`action=ACTION_LOG`, `verdict=<final action>`, rule_id, captured flow, SNI bytes
(up to `MAX_SNI_LEN`). Userspace forwards this to WebSocket subscribers via the
broadcast channel.

### UDP/QUIC path

#### Why userspace

The QUIC ClientHello is encrypted under the Initial-packet AEAD before it
leaves the client. BPF can't recover the plaintext (no AES primitives). Initial
keys, however, derive deterministically from the Destination Connection ID and
a per-version salt (RFC 9001 §5.2 for v1, RFC 9369 §3.3 for v2), so any on-path
observer can derive them — no secret to learn. The work is just too heavy for
BPF.

#### BPF side: header check + ringbuf

`xdp_quic_initial_inspect` and `tc_quic_initial_inspect` are dispatcher
tail-call targets (XDP slot 3, TC slot 2). The main program tail-calls them
when a UDP packet matches a rule whose `sni_match_type` is non-zero.

| Step | Action | Failure mode |
|------|--------|--------------|
| 1 | Bound `l4_off ≤ 512` so the verifier sees a constrained packet offset | pass packet, no event |
| 2 | Confirm ≥ 7 bytes of QUIC header available | pass |
| 3 | `(first & 0xC0) == 0xC0` — long header + fixed bit | pass |
| 4 | Version is `0x00000001` (v1) or `0x6b3343cf` (v2) | pass |
| 5 | Long-header type matches Initial (v1: `0b00`, v2: `0b01`) | pass |
| 6 | `1 ≤ dcid_len ≤ 20` | pass |
| 7 | Reserve a `quic_inspect_event` on the ringbuf, fill 5-tuple + version + first ≤ 1280 B of payload, submit | drop the inspection; userspace picks up the next Initial in the burst |

The BPF program **does not seed a verdict**. Modern Firefox/Chrome spread the
ClientHello across multiple Initials with deliberately gappy, out-of-order
CRYPTO frames, so userspace must see every Initial in the burst to reassemble.
Seeding even a short PASS would short-circuit packets 2..N at the main entry and
starve the reassembler. Until userspace writes the verdict, the L4 path keeps
tail-calling — bounded by handshake length (well under 100 packets per flow).

Two non-obvious verifier workarounds in the source:

1. **`bpf_xdp_load_bytes` size argument**: the compiler folds `cl > 0 && cl <=
   MAX` into a single subtract-and-compare that doesn't narrow the original
   register and keeps an unbarriered copy alive across `__asm__ "+r"` separation
   barriers. Round-trip the length through a `volatile` stack slot and keep the
   two bounds compares as separate `if`s.
2. **DCID copy**: per-iteration packet reads of `evt->dcid[i] = q[6+i]` trip
   bounds checking because the verifier can't propagate `(q + 6 + dcid_len <=
   data_end)` to each `i` inside the loop. Drop the DCID from the event struct;
   userspace pulls it from `payload[6..6+dcid_len]`.

#### Userspace decrypt

`src/server/quic_initial.rs` implements key derivation, header protection
removal, and AEAD decrypt.

**Key derivation (RFC 9001 §5.2 / RFC 9369 §3.3):**

```
initial_secret        = HKDF-Extract(salt=version_salt, ikm=DCID)
client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
key  = HKDF-Expand-Label(client_initial_secret, "quic key" | "quicv2 key", "", 16)
iv   = HKDF-Expand-Label(client_initial_secret, "quic iv"  | "quicv2 iv",  "", 12)
hp   = HKDF-Expand-Label(client_initial_secret, "quic hp"  | "quicv2 hp",  "", 16)
```

Version salts:

- v1: `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
- v2: `0x0dede3def700a6db819381be6e269dcbf9bd2ed9`

Tested against RFC 9001 §A.1 (DCID = `0x8394c8f03e515708`).

**Header protection removal:**

```
sample = packet[pn_offset + 4 .. pn_offset + 4 + 16]
mask   = AES-128-ECB(hp_key, sample)               # single block
hdr[0] ^= mask[0] & 0x0f                           # long header: low 4 bits
pn_len = (hdr[0] & 0x03) + 1                       # 1..4 bytes
for i in 0..pn_len: pn_bytes[i] = packet[pn_offset + i] ^ mask[1 + i]
```

For the first Initial we assume `largest_pn = 0`, so the truncated packet
number on the wire is the full packet number.

**AEAD decrypt:**

```
nonce      = iv XOR (left-zero-padded pn)
aad        = unprotected_header (header up to and including pn bytes)
ciphertext = packet[pn_offset + pn_len .. pn_offset + length]
plaintext  = AES-128-GCM-decrypt(key, nonce, aad, ciphertext)
```

Tested against RFC 9001 §A.2: confirms the output starts with a `CRYPTO` frame
(`0x06`) and the reassembled stream begins with TLS Handshake byte `0x01`
(ClientHello).

#### Frame walk

Only frame types legal in an Initial are accepted; anything else rejects the
Initial as malformed:

- `PADDING` (`0x00`)
- `PING` (`0x01`)
- `ACK` (`0x02`) / `ACK_ECN` (`0x03`)
- `CRYPTO` (`0x06`)
- `CONNECTION_CLOSE` (`0x1c` / `0x1d`)

CRYPTO frame data is **not** assumed to start at offset 0 or to be contiguous
within a single Initial. Every `(offset, bytes)` chunk is appended to the
reassembly entry.

#### Cross-packet reassembly

`ReassemblyTable` (in `quic_initial.rs`) is a `HashMap` keyed by `(5-tuple,
DCID)`, owned by the per-direction consumer task. For each Initial:

1. Decrypt and extract its CRYPTO chunks (no chunk is discarded).
2. Append to the entry; touch `last_seen`.
3. Re-walk chunks in offset order to produce the largest contiguous prefix from
   offset 0 and classify:
   - `Sni(name)` — full CH, `server_name` found. Entry removed; verdict written.
   - `NoSni` — full CH, no `server_name`. Entry removed; PASS verdict written.
   - `Partial { have, need }` — TLS handshake header parsed; awaiting body. Entry retained.
   - `NeedMore { contiguous }` — < 4 bytes contiguous from 0; can't even read the handshake length. Entry retained.
   - `NotClientHello` — contiguous prefix exists but first byte isn't `0x01`. Entry removed; no verdict (L4 path keeps handling the flow normally).

Bounds: ≤ 4 KiB of CRYPTO bytes per flow, ≤ 4096 concurrent flows (oldest
evicted when full), 5-second per-flow idle timeout swept every 2 seconds by the
consumer task.

The ClientHello body length is read from the standard TLS handshake header
(`msg_type(1) + length(3)`), so we know exactly when "enough" has arrived
rather than re-attempting parse on every chunk.

#### ClientHello parsing and rule matching

A minimal hand-rolled walk (shared between the UDP and TCP-userspace paths):
`legacy_version → random → session_id → cipher_suites → compression_methods →
extensions`, then a linear scan for the `server_name` extension (type `0x0000`,
RFC 6066 §3). Only the first `host_name` entry is returned. No external TLS
parser dependency.

`match_sni_rules` walks `list_policy_rules_v4` + `list_policy_rules_v6`, filters
to UDP rules with `sni_match_type != SNI_MATCH_NONE`, looks up each matching
rule's `SniRuleEntry`, and returns the first match's full action list (scanned
in `rule_id` order for determinism). The caller runs the standard action loop.
The map mirror is the same `sni_rules` (XDP) / `tc_sni_rules` (TC) map the TCP
path uses, so userspace and the BPF inspector see exactly the same patterns.

### Limitations

- **Retry / 0-RTT / Handshake / Short-header QUIC packets** — not inspected.
  Only client Initials are decrypted.
- **Server-sent QUIC Initials** — keys derive from the `server_initial_secret`;
  we only handle the client path.
- **Unknown QUIC versions** — the BPF pre-check filters out anything that isn't
  v1 or v2 before the ringbuf event is emitted.
- **Pre-existing sessions** — if a client has a live TCP TLS or QUIC connection
  from before the rule was installed, there are no further ClientHellos to
  inspect; the rule doesn't retroactively apply until the client opens a new
  connection.
- **First QUIC Initial leaks per flow** — the BPF Initial inspector mirrors the
  Initial to userspace and returns `TC_ACT_OK` / `XDP_PASS`. Userspace decrypts
  and writes the DROP verdict *after* the packet has left the NIC, so the first
  Initial of every new QUIC flow reaches the server. Subsequent packets hit the
  verdict cache and drop, so the handshake can't complete — blocking still works
  in practice, but the server observes the connection attempt and the client's
  ClientHello. Doing this in BPF would require AES in BPF (unavailable) or a
  speculative-drop-then-rewind primitive (doesn't exist); the leak is intrinsic
  to the userspace-decrypt design.
- **HTTP/2 connection coalescing across SAN-shared siblings** — when a server's
  certificate covers multiple hostnames (e.g. `*.bing.com`, `*.bing.net`,
  `*.live.com` on one cert), browsers reuse an existing TLS connection for any
  covered hostname without opening a new one. If a live connection to a sibling
  SNI exists, requests to the rule-targeted SNI ride that connection and never
  produce a ClientHello. Symptom: rule stats stay flat while the page loads.
  Mitigation requires rules covering the full SAN set, or an L3/ASN block for
  the property's edge — SNI matching is per-hostname, not per-site.
- **HTTP/3 ↔ TCP fallback** — browsers race QUIC and TCP. Blocking only one
  transport often doesn't block the site, because the browser silently falls
  back within a few hundred ms. To actually block, install both a UDP/443 and a
  TCP/443 rule with the same SNI pattern.
- **ECH (Encrypted Client Hello)** — the outer SNI is a public cover name; the
  real SNI is encrypted under a separate handshake. We see only the outer name
  on both transports.
- **TLS spanning more than `SNI_PULL_MAX` (4 KiB) bytes** — pathological CH
  sizes get truncated in `tc_sni_inspect`. The parser's internal bound is
  `0x3000` (12 KiB); raising `SNI_PULL_MAX` to match would handle it at the cost
  of a slightly bigger `bpf_skb_pull_data` call on every SNI-rule packet.

### Configuration

```bash
# Drop QUIC traffic to evil.example via the Initial-SNI path
policy-client rule add \
    --direction ingress \
    --protocol udp --dport 443 \
    --sni evil.example.com \
    --action drop:0

# Drop TCP TLS traffic to the same name (HTTP/3 fallback story)
policy-client rule add \
    --direction ingress \
    --protocol tcp --dport 443 \
    --sni evil.example.com \
    --action drop:0

# Wildcard, log first then drop
policy-client rule add \
    --direction egress \
    --protocol udp --dport 443 \
    --sni '*.example.com' \
    --action log:1000000000 --action drop:0
```

Validation gates ICMP and `any` (no SNI semantics). UDP and TCP both succeed;
the BPF tail call chosen by the dispatcher decides which inspector runs.

### Testing

- **Unit (Rust)** — `src/server/quic_initial.rs` and
  `src/server/tests/quic_initial_inspect_tests.rs`. Covers RFC 9001 §A.1 (key
  derivation) and §A.2 (full Initial decrypt) reference vectors, a synthetic
  ClientHello with/without SNI, exact and wildcard rule matching, end-to-end
  verdict write via the mock BPF adaptor, multi-action (`LOG + DROP`) handling,
  and cross-packet CRYPTO reassembly against two real captured Firefox→YouTube
  Initial packets (committed as hex fixtures). The synthetic single-Initial path
  alone is not enough to catch reassembly regressions; the real-pcap fixture is.
- **End-to-end (netsim)** — `python/tests/sni_matching/`, covering both the TCP
  path (scapy ClientHellos, `tls_sni_send.py`) and the UDP path (QUIC v1/v2
  Initials via aioquic, `quic_sni_send.py`). Bring up a two-node
  topology, install SNI policy rules on the server, fire real ClientHellos from
  the client, and assert that the rule packet counter advances and a verdict
  appears in `flow_verdict_cache`.

---

## Timed rules

Policy rules can carry a lifecycle constraint — either a **TTL** (auto-remove
after N seconds) or a **weekly schedule** (active only during recurring time
windows). Rules with either constraint are called *managed rules* and are
tracked separately from permanent rules in the rule registry. TTL and schedule
are mutually exclusive.

The scheduler runs every 30 seconds, so removal or window transitions may lag by
up to that interval.

### TTL rules

A TTL rule is automatically removed from the BPF maps once its deadline passes.
TTL rules are always `active` from the moment they are added until they expire
or are manually deleted.

```bash
policy-client rule add --direction ingress \
    --src 198.51.100.1/32 --action drop:0 \
    --expires-after-secs 3600
```

```graphql
mutation {
  addRule(input: {
    direction: INGRESS
    src: "198.51.100.1/32"
    protocol: "any"
    actions: [{ action: DROP, priority: 0 }]
    expiresAfterSecs: 3600
  }) { success message }
}
```

`expiresAfterSecs` must be a positive integer; zero is rejected.

### Scheduled rules

A scheduled rule is installed into (or removed from) the BPF maps according to a
set of weekly recurring time windows:

- **Inside** a window, the rule state is `active` and present in the BPF maps.
- **Outside** all windows, the rule state is `inactive` and absent from the BPF
  maps but remains registered (reinstalled at the next window start).

Windows are specified in local time using an IANA timezone name (default `UTC`).

#### Window format

Each window is a half-open interval `[start, end)` of day-of-week + time:

| Field | Values |
|-------|--------|
| `dayOfWeek` | 0 = Sunday … 6 = Saturday |
| `hour` | 0–23 |
| `minute` | 0–59 |

A window where `end` ≤ `start` (in week-minutes) wraps across the
Saturday/Sunday boundary (e.g. Saturday 23:00 → Sunday 01:00). Multiple windows
are OR-ed: the rule is active if the current time falls within *any* of them.

On the CLI, a window is `DAY:HH:MM-DAY:HH:MM`; multiple `--schedule-window`
flags are OR-ed together.

```bash
# Block 10.0.0.0/8 on weekdays 09:00–17:00 Eastern Time
policy-client rule add --direction ingress \
    --src 10.0.0.0/8 --action drop:0 \
    --schedule-window 1:09:00-5:17:00 \
    --schedule-tz "America/Toronto"

# Wrap-around window: Saturday 23:00 through Sunday 01:00 UTC
policy-client rule add --direction ingress \
    --src 0.0.0.0/0 --action drop:0 \
    --schedule-window 6:23:00-0:01:00
```

```graphql
mutation {
  addRule(input: {
    direction: INGRESS
    src: "10.0.0.0/8"
    protocol: "any"
    actions: [{ action: DROP, priority: 0 }]
    schedule: {
      windows: [
        {
          start: { dayOfWeek: 1, hour: 9, minute: 0 }
          end:   { dayOfWeek: 1, hour: 17, minute: 0 }
        }
      ]
      timezone: "America/Toronto"
    }
  }) { success message }
}
```

### Querying and deleting managed rules

Permanent rules (no lifecycle constraint) are returned by the `rules` query.
Managed rules are returned by the separate `managedRules` query, which includes
lifecycle metadata (`ruleState`, `expiresAtMs`, `schedule`).

```bash
policy-client rule managed-rules --direction ingress
policy-client rule delete --direction ingress --id 9001   # removes from registry + BPF maps immediately
```

```graphql
query {
  managedRules(direction: INGRESS) {
    ruleId srcPrefix dstPrefix sport dport protocol
    actions { action priority param }
    ruleState        # "active" or "inactive"
    expiresAtMs      # ms since epoch (TTL rules only, null otherwise)
    schedule {       # schedule rules only, null otherwise
      timezone
      windows { start { dayOfWeek hour minute } end { dayOfWeek hour minute } }
    }
  }
}
```

### Rule lifecycle event stream

Every state change to a managed (or permanent) rule is broadcast as a JSON
event over a WebSocket endpoint:

```
GET /ws/rule-events
```

Upgrade with a standard `Upgrade: websocket` handshake. The server sends a
heartbeat ping every 15 seconds and a `Close(1001 Away)` frame on shutdown.
Behind TLS the endpoint is `wss://`.

Each message is a JSON object:

```json
{
  "event_type":   "activated",
  "rule_id":      9001,
  "direction":    "INGRESS",
  "timestamp_ms": 1712345678000,
  "reason":       "schedule_window_start"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | `"activated"` \| `"deactivated"` \| `"deleted"` \| `"expired"` |
| `rule_id` | integer | The rule ID |
| `direction` | string | `"INGRESS"` or `"EGRESS"` |
| `timestamp_ms` | integer | Unix timestamp in milliseconds |
| `reason` | string \| absent | Human-readable cause (below) |

| Reason | Trigger |
|--------|---------|
| `ttl_expired` | TTL deadline passed; rule removed by scheduler |
| `schedule_window_start` | Entered a schedule window; rule installed in BPF maps |
| `schedule_window_end` | Left all schedule windows; rule removed from BPF maps |
| _(absent)_ | Permanent rule activated or rule deleted by API call |

Behaviour: all connected clients receive every event (fan-out); no replay (only
events after a client connects); lag protection (a client more than 256 events
behind silently skips missed events, logged server-side); the web UI reconnects
with exponential backoff (1 s → 30 s).

### Persistence

The rule registry is **in-memory only** and does not survive server restarts.
Managed rules must be re-added after a restart; any partially-elapsed TTL resets.
```
