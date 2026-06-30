# TODO

## SNI verdict cache: revisit the 10-minute TTL

The SNI flow verdict (`SNI_VERDICT_TTL_NS`, written by `tc_sni_write_verdict` /
its XDP counterpart) uses a fixed 10-minute wall-clock TTL. This is a defensible
default, but it's a heuristic papering over a key/decision mismatch: the entry is
keyed by the 5-tuple but the verdict is actually decided by the SNI hostname,
which is not part of the key.

### The crux: reused 5-tuples are not re-inspected

On 5-tuple reuse, the new connection's ClientHello is **never re-inspected**: the
verdict-cache check at `tc_policy_egress` (`tc_policy.bpf.c:639-648`)
short-circuits and returns the stale verdict *before* the SNI tail call ever
dispatches. So the entire TTL is the staleness window, and re-inspection only
happens after the entry expires. This is why the TTL can't simply be raised —
it directly trades correctness for cache-hit rate.

### Failure mode 1 — collateral over-blocking on the DROP side (correctness/security)

Block `evil.com` on a CDN/SAN-shared edge IP. The DROP'd handshake can't
complete, dies fast, and frees the ephemeral port. Under connection churn to the
same big IP, the port can be reused within 10 min for an *allowed* hostname,
which then inherits the cached DROP → legit traffic silently blocked for up to
10 min, then self-heals. This is the documented aliasing case
(`docs/rule-matching.md:240-249`). Bounded and self-healing, so tolerable for
most deployments, but genuinely problematic behind a Cloudflare/Fastly/Google-
class IP.

### Failure mode 2 — performance cliff on long-lived PASS flows

A connection living past 10 min (video stream, websocket, gRPC stream,
DB-over-TLS, tunnel) loses its verdict mid-stream. The next data packet misses
the cache, re-walks the two-level LPM, and tail-calls `tc_sni_inspect` — which
finds application data, not a ClientHello, so `sni_seen` stays 0 and it **does
not re-seed** (`tc_policy.bpf.c:803`, `:951`). Every remaining packet of that
connection then pays full LPM + tail-call + `bpf_skb_pull_data(<=4096)` with no
way to re-cache. For a high-throughput long-lived TLS flow this is a real
per-packet regression after the 10-min mark, not a one-off.

### Better-than-tuning fix: connection-liveness eviction

Tie verdict lifetime to connection liveness instead of wall-clock — evict the
entry on TCP FIN/RST. This kills both failure modes at once:

- A closed connection's 5-tuple immediately drops its verdict, so a reused
  5-tuple's SYN misses and the new ClientHello gets inspected fresh (fixes #1).
- A live connection keeps its verdict for its whole duration with no cliff
  (fixes #2).

Cost is complexity: needs FIN/RST handling in the dataplane plus an idle-TTL
fallback for no-clean-close cases (half-open, killed connections). For QUIC
there is no cheap, trustworthy connection-close signal, so a wall-clock TTL
stays the right tool there regardless.

### Recommendations (in order of effort)

1. **Keep 10m as-is** if traffic is dominated by short connections and egress is
   not behind big SAN-shared IPs — it's a fine default.
2. **Make the TTL configurable** (cheap): operators behind CDN-heavy egress can
   lower it to shrink the collateral window; latency-insensitive deployments can
   raise it.
3. **Connection-tracked eviction for the TCP path** (the real fix) if either
   failure mode bites in practice.

### Open question to confirm first

Reasoned from the BPF source (`tc_policy.bpf.c`, `tc/actions.h`), not a running
system. Before acting on the FIN/RST idea, confirm there isn't already an
eviction path elsewhere — e.g. `FlowVerdictManager` (`flow_verdict_manager.rs`)
beyond the periodic expiry sweep described in `docs/rule-matching.md`.
