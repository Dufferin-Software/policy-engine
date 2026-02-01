# SNI Matching

Policy rules with an `sni` criterion match TLS Server Name Indication on
both transports:

* **TCP TLS** — parsed in-kernel by `xdp_sni_inspect` / `tc_sni_inspect`
  walking the ClientHello directly out of the skb / xdp_md buffer.
* **UDP QUIC** — Initial packets are AEAD-protected, so BPF ships every
  client Initial to userspace, which derives the per-Initial keys,
  decrypts, reassembles CRYPTO fragments, and extracts SNI.

Both paths converge on the same `sni_rules` / `tc_sni_rules` map (so the
rule patterns are configured once), the same action loop semantics
(`LOG → DROP → PASS`, terminal on DROP, mirroring `tc/actions.h`), the
same `flow_verdict_cache` for fast-path short-circuit on subsequent
packets, and the same `rule_stats` counters so operator-visible packet
and byte counts work the same way for both.

## Pipeline

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

## Shared semantics

### Action application

A matched rule's `actions[0..num_actions]` are walked in priority order
on both paths.  `tc_sni_inspect` runs the loop in BPF
(`tc_policy.bpf.c`); the QUIC userspace consumer runs the equivalent
loop in `process_quic_sample` (`event_stream.rs`).

| Action | Effect | Stops further actions? |
|---|---|---|
| `LOG` | Emit a `PolicyEvent` with `action=LOG`, `verdict=<final action so far>`, rule_id, 5-tuple, SNI.  Rate-limited by the per-action `param` (nanoseconds since the last LOG for that rule); 0 = no limit.  Storage: `rule_stats.last_log_ns` in BPF, `HashMap<rule_id, last_log_ns>` in the QUIC consumer task. | no |
| `DROP` | Selects DROP as the final action; verdict cache is written with DROP so the L4 fast path drops every subsequent packet in the flow. | **yes** |
| `PASS` | No-op; the loop continues. | no |

After the loop, the verdict cache entry is written with whichever final
action the loop selected (`PASS` by default, `DROP` if any DROP fired).

### `evt->verdict` is a `PolicyAction` enum

The event struct field is decoded in userspace as
`PolicyAction { Pass=0, Drop=1, Log=2 }` — **not** as a TC/XDP return
code.  All four event-emission sites translate `final_verdict`
(`TC_ACT_OK`/`TC_ACT_SHOT`, `XDP_PASS`/`XDP_DROP`) to `ACTION_PASS` /
`ACTION_DROP` before storing, because the numeric values collide:
`TC_ACT_SHOT=2` would render as `LOG`, `XDP_PASS=2` likewise.

### Verdict cache

```
key      = FlowVerdictKey from the captured 5-tuple
action   = final action after walking the rule's actions[]
expires  = now + 60 s
direction = Ingress (XDP) or Egress (TC)
```

TCP writes the verdict in-kernel from `xdp_sni_inspect` /
`tc_sni_inspect` directly (via `bpf_map_update_elem` against
`flow_verdict_cache` / `tc_flow_verdict_cache`) once the action loop has
selected its final action — DROP on a match whose terminal action is
DROP, PASS on a match whose actions all PASS-equivalent (LOG/PASS), and
PASS on the no-match-after-all-rules-exhausted path so non-matching
flows also fast-path.  QUIC writes from userspace via
`BpfOperations::update_flow_verdict` after Initial decryption.  Both
paths use `SNI_VERDICT_TTL_NS` / `QUIC_VERDICT_TTL_NS` = 60 s, sized to
cover the bulk of a TCP TLS or QUIC session so the BPF fast path
drops/passes every subsequent packet without re-running inspection.  The
cleanup task in `http.rs` evicts expired entries.

### Per-rule stats

Both paths bump `rule_stats` / `tc_rule_stats` (a plain HASH, not
per-CPU) on a match: `packets += 1`, `bytes += pkt_len`,
`last_seen_ns = now`.  TCP does this in BPF via `tc_update_rule_stats`;
QUIC does it from userspace via `BpfOperations::bump_rule_stats`.  This
keeps `policy-client show rule-stats` accurate for both transports.

## TCP path

`xdp_sni_inspect` (XDP ingress) and `tc_sni_inspect` (TC egress) are
dispatcher tail-call targets (XDP slot 0, TC slot 0).  The main program
queues every rule whose `sni_match_type != SNI_MATCH_NONE` into
`pkt_scratch.sni_pending[]`, then tail-calls the inspector once.  The
inspector iterates the pending list, parsing the ClientHello once and
checking each pending rule's SNI pattern in turn.

### `match_sni_in_packet`

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

* All packet offsets are kept as scalars, repeatedly bounds-checked
  against `0x3000` so the verifier narrows the tnum at each step.
* Each iteration of the extension scan **rebuilds** the packet pointer
  from a freshly-narrowed scalar (`safe_off &= 0x3fff` with an asm
  barrier to force a real `AND`), because adding a runtime variable to
  a pkt_ptr always resets the verifier's range tracking to 0.
* `bpf_skb_load_bytes` is not used here — the parser reads directly
  from `data..data_end` for performance.

### `bpf_skb_pull_data` for TSO/GSO

On TC egress, the kernel hands BPF a single super-skb for whatever the
TCP stack queued for TSO segmentation.  The linear region of that skb
typically holds only L2/L3/L4 headers (~50–60 bytes); the rest of the
payload sits in paged fragments inaccessible via direct packet access.

Modern TLS 1.3 ClientHellos are large — a Brave→Google CH runs ~2 KB
because the post-quantum `X25519MLKEM768` `key_share` extension alone
is ~1.3 KB.  `server_name` lands in the second segment of any naive
parse, beyond the linear region, and the in-kernel parser would bail at
the first read past it.

`tc_sni_inspect` therefore calls `bpf_skb_pull_data(ctx, min(ctx->len,
SNI_PULL_MAX))` (with `SNI_PULL_MAX = 4096` in `policy_common.h`)
before reading `ctx->data` / `ctx->data_end`, then re-reads the
pointers since pull may have moved them.  XDP doesn't need this — it
operates on raw frame buffers below the TCP stack, with no GSO super
packets.

### LOG emission

`tc_emit_event` reserves a `policy_event` on the `tc_events` ringbuf
with `action=ACTION_LOG`, `verdict=<final action>`, rule_id, captured
flow, SNI bytes (up to `MAX_SNI_LEN`).  Userspace forwards this to
WebSocket subscribers via the broadcast channel.

## UDP/QUIC path

### Why userspace

The QUIC ClientHello is encrypted under the Initial-packet AEAD before
it leaves the client.  BPF can't recover the plaintext (no AES
primitives).  Initial keys, however, derive deterministically from the
Destination Connection ID and a per-version salt (RFC 9001 §5.2 for v1,
RFC 9369 §3.3 for v2), so any on-path observer can derive them — no
secret to learn.  The work is just too heavy for BPF.

### BPF side: header check + ringbuf

`xdp_quic_initial_inspect` and `tc_quic_initial_inspect` are dispatcher
tail-call targets (XDP slot 3, TC slot 2).  The main program tail-calls
them when a UDP packet matches a rule whose `sni_match_type` is
non-zero.

| Step | Action | Failure mode |
|---|---|---|
| 1 | Bound `l4_off ≤ 512` so the verifier sees a constrained packet offset | pass packet, no event |
| 2 | Confirm ≥ 7 bytes of QUIC header available | pass |
| 3 | `(first & 0xC0) == 0xC0` — long header + fixed bit | pass |
| 4 | Version is `0x00000001` (v1) or `0x6b3343cf` (v2) | pass |
| 5 | Long-header type matches Initial (v1: `0b00`, v2: `0b01`) | pass |
| 6 | `1 ≤ dcid_len ≤ 20` | pass |
| 7 | Reserve a `quic_inspect_event` on the ringbuf, fill in 5-tuple + version + first ≤ 1280 B of payload, submit | drop the inspection; userspace will pick up the next Initial in the burst |

The BPF program **does not seed a verdict**.  Modern Firefox/Chrome
spread the ClientHello across multiple Initials with deliberately gappy,
out-of-order CRYPTO frames, so userspace must see every Initial in the
burst to reassemble.  Seeding even a short PASS would short-circuit
packets 2..N at the main entry and starve the reassembler.  Until
userspace writes the verdict, the L4 path keeps tail-calling — bounded
by handshake length (well under 100 packets per flow).

Two non-obvious verifier workarounds in the source:

1. **`bpf_xdp_load_bytes` size argument**: the compiler folds
   `cl > 0 && cl <= MAX` into a single subtract-and-compare that
   doesn't narrow the original register and keeps an unbarriered copy
   alive across `__asm__ "+r"` separation barriers.  Round-trip the
   length through a `volatile` stack slot and keep the two bounds
   compares as separate `if`s.
2. **DCID copy**: per-iteration packet reads of `evt->dcid[i] = q[6+i]`
   trip bounds checking because the verifier can't propagate
   `(q + 6 + dcid_len <= data_end)` to each `i` inside the loop.  Drop
   the DCID from the event struct; userspace pulls it from
   `payload[6..6+dcid_len]`.

### Userspace decrypt

`src/server/quic_initial.rs` implements key derivation, header
protection removal, and AEAD decrypt.

**Key derivation (RFC 9001 §5.2 / RFC 9369 §3.3)**:

```
initial_secret        = HKDF-Extract(salt=version_salt, ikm=DCID)
client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
key  = HKDF-Expand-Label(client_initial_secret, "quic key" | "quicv2 key", "", 16)
iv   = HKDF-Expand-Label(client_initial_secret, "quic iv"  | "quicv2 iv",  "", 12)
hp   = HKDF-Expand-Label(client_initial_secret, "quic hp"  | "quicv2 hp",  "", 16)
```

Version salts:

* v1: `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`
* v2: `0x0dede3def700a6db819381be6e269dcbf9bd2ed9`

Tested against RFC 9001 §A.1 (DCID = `0x8394c8f03e515708`).

**Header protection removal**:

```
sample = packet[pn_offset + 4 .. pn_offset + 4 + 16]
mask   = AES-128-ECB(hp_key, sample)               # single block
hdr[0] ^= mask[0] & 0x0f                           # long header: low 4 bits
pn_len = (hdr[0] & 0x03) + 1                       # 1..4 bytes
for i in 0..pn_len: pn_bytes[i] = packet[pn_offset + i] ^ mask[1 + i]
```

For the first Initial we assume `largest_pn = 0`, so the truncated
packet number on the wire is the full packet number.

**AEAD decrypt**:

```
nonce      = iv XOR (left-zero-padded pn)
aad        = unprotected_header (header up to and including pn bytes)
ciphertext = packet[pn_offset + pn_len .. pn_offset + length]
plaintext  = AES-128-GCM-decrypt(key, nonce, aad, ciphertext)
```

Tested against RFC 9001 §A.2: confirms the output starts with a
`CRYPTO` frame (`0x06`) and the reassembled stream begins with TLS
Handshake byte `0x01` (ClientHello).

### Frame walk

Only frame types legal in an Initial are accepted; anything else
rejects the Initial as malformed:

* `PADDING` (`0x00`)
* `PING` (`0x01`)
* `ACK` (`0x02`) / `ACK_ECN` (`0x03`)
* `CRYPTO` (`0x06`)
* `CONNECTION_CLOSE` (`0x1c` / `0x1d`)

CRYPTO frame data is **not** assumed to start at offset 0 or to be
contiguous within a single Initial.  Every `(offset, bytes)` chunk is
appended to the reassembly entry.

### Cross-packet reassembly

`ReassemblyTable` (in `quic_initial.rs`) is a `HashMap` keyed by
`(5-tuple, DCID)`, owned by the per-direction consumer task.  For each
Initial:

1. Decrypt and extract its CRYPTO chunks (no chunk is discarded).
2. Append to the entry; touch `last_seen`.
3. Re-walk chunks in offset order to produce the largest contiguous
   prefix from offset 0 and classify:
   * `Sni(name)` — full CH, `server_name` found.  Entry removed; verdict written.
   * `NoSni` — full CH, no `server_name`.  Entry removed; PASS verdict written.
   * `Partial { have, need }` — TLS handshake header parsed; awaiting body.  Entry retained.
   * `NeedMore { contiguous }` — < 4 bytes contiguous from 0; can't even read the handshake length.  Entry retained.
   * `NotClientHello` — contiguous prefix exists but first byte isn't `0x01`.  Entry removed; no verdict (L4 path keeps handling the flow normally).

Bounds: ≤ 4 KiB of CRYPTO bytes per flow, ≤ 4096 concurrent flows
(oldest evicted when full), 5-second per-flow idle timeout swept every
2 seconds by the consumer task.

The ClientHello body length is read from the standard TLS handshake
header (`msg_type(1) + length(3)`), so we know exactly when "enough"
has arrived rather than re-attempting parse on every chunk.

### ClientHello parsing

Minimal hand-rolled walk shared between the UDP and TCP-userspace-only
paths: `legacy_version → random → session_id → cipher_suites →
compression_methods → extensions`, then a linear scan for the
`server_name` extension (type `0x0000`, RFC 6066 §3).  Only the first
`host_name` entry is returned.  No external TLS parser dependency.

### Rule matching

`match_sni_rules` walks `list_policy_rules_v4` + `list_policy_rules_v6`,
filters to UDP rules with `sni_match_type != SNI_MATCH_NONE`, looks up
each matching rule's `SniRuleEntry`, and returns the first match's full
action list (scanned in `rule_id` order for determinism).  The caller
runs the action loop documented under *Shared semantics*.

The map mirror is the same `sni_rules` (XDP) / `tc_sni_rules` (TC) map
the TCP path uses, so userspace and the BPF SNI inspector see exactly
the same configured patterns.

## TTLs and lifecycle

| State | TTL | Set by |
|---|---|---|
| flow_verdict (PASS / DROP, both transports) | 60 s | TCP: `tc_sni_inspect` action loop; UDP: `process_quic_sample` |
| QUIC reassembly entry idle timeout | 5 s | `ReassemblyTable::evict_stale` |
| LOG rate limit (per rule, both transports) | per-action `param` ns | TCP: `tc_rule_stats.last_log_ns` (CAS); UDP: `HashMap<rule_id, last_log_ns>` in consumer task |

## Limitations

* **Retry / 0-RTT / Handshake / Short-header QUIC packets** — not
  inspected.  Only client Initials are decrypted.
* **Server-sent QUIC Initials** — keys derive from the
  `server_initial_secret`; we only handle the client path.
* **Unknown QUIC versions** — the BPF pre-check filters out anything
  that isn't v1 or v2 before the ringbuf event is emitted.
* **Pre-existing sessions** — if a client has a live TCP TLS or QUIC
  connection to a server from before the rule was installed, there are
  no further ClientHellos to inspect; the rule doesn't retroactively
  apply until the client opens a new connection.
* **First QUIC Initial leaks per flow** — the BPF Initial inspector
  mirrors the Initial to userspace and returns `TC_ACT_OK` / `XDP_PASS`
  (see *BPF side: header check + ringbuf*).  Userspace decrypts and
  writes the DROP verdict *after* the packet has left the NIC, so the
  first Initial of every new QUIC flow reaches the server.  Subsequent
  packets in that flow hit the verdict cache and drop, so the handshake
  can't complete — blocking still works in practice, but the server
  observes the connection attempt and the client's ClientHello.  Doing
  this in BPF would require either AES in BPF (not available) or a
  speculative-drop-then-rewind primitive (doesn't exist); the leak is
  intrinsic to the userspace-decrypt design.
* **HTTP/2 connection coalescing across SAN-shared siblings** — when a
  server's certificate covers multiple hostnames (e.g. `*.bing.com`,
  `*.bing.net`, `*.live.com` all on one cert), browsers reuse an existing
  TLS connection for any covered hostname without opening a new one.  If
  a live connection to a sibling SNI exists, requests to the rule-targeted
  SNI ride that connection and never produce a ClientHello for inspection.
  Symptom: rule stats stay flat or low while the page loads anyway.
  Mitigation requires rules covering the full SAN set, or an L3/ASN block
  for the property's edge — SNI matching is per-hostname, not per-site.
* **HTTP/3 ↔ TCP fallback** — browsers race QUIC and TCP.  Blocking
  only one transport often doesn't block the site, because the browser
  silently falls back to the other within a few hundred ms.  To
  actually block, install both a UDP/443 and a TCP/443 rule with the
  same SNI pattern.
* **ECH (Encrypted Client Hello)** — the outer SNI is a public cover
  name; the real SNI is encrypted under a separate handshake.  We see
  only the outer name on both transports.
* **TLS spanning more than `SNI_PULL_MAX` (4 KiB) bytes** — pathological
  CH sizes will get truncated in `tc_sni_inspect`.  The parser's
  internal bound is `0x3000` (12 KiB); raising `SNI_PULL_MAX` to match
  would handle it at the cost of a slightly bigger `bpf_skb_pull_data`
  call on every SNI-rule packet.

## Configuration

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

Validation gates ICMP and `any` (no SNI semantics).  UDP and TCP both
succeed; the BPF tail call chosen by the dispatcher decides which
inspector runs.

## Testing

* **Unit (Rust)** — `src/server/quic_initial.rs` and
  `src/server/tests/quic_initial_inspect_tests.rs`.  Covers RFC 9001
  §A.1 (key derivation) and §A.2 (full Initial decrypt) reference
  vectors, a synthetic ClientHello with/without SNI, exact and wildcard
  rule matching, end-to-end verdict write via the mock BPF adaptor,
  multi-action (`LOG + DROP`) handling, and cross-packet CRYPTO
  reassembly against two real captured Firefox→YouTube Initial packets
  (committed as hex fixtures alongside the test).  The synthetic
  single-Initial path alone is not enough to catch reassembly
  regressions; the real-pcap fixture is.
* **End-to-end (netsim)** — `tests/quic_sni_matching/` (UDP path) and
  `tests/policy_sanity/test_sni_matching.py` (TCP path).  Bring up a
  two-node topology, install SNI policy rules on the server, fire real
  ClientHellos from the client, and assert that the rule packet counter
  advances and a verdict appears in `flow_verdict_cache`.
