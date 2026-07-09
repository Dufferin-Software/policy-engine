// SPDX-License-Identifier: GPL-2.0-only
/*
 * XDP Policy Engine - Main XDP program with LPM-based policy matching
 *
 * Supports CIDR prefix matching using BPF LPM trie maps for source IP.
 * More specific prefixes (longer prefix length) are matched first.
 */

#include "../include/bpf_helpers.h"
#include "../include/policy_common.h"
#include "../include/vmlinux_subset.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Per-rule statistics map
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_POLICY_RULES);
  __type(key, __u64); /* rule_id */
  __type(value, struct rule_stats);
} rule_stats SEC(".maps");

/*
 * Global per-CPU statistics
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, __u32);
  __type(value, struct global_stats);
} global_stats SEC(".maps");

/*
 * Ethertype statistics map (per-interface, tracks counts per ethertype)
 * Key: (ifindex << 16) | ethertype
 * Value: packet count
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, MAX_INTERFACES *MAX_ETHERTYPE_COUNTERS);
  __type(key, __u32);
  __type(value, __u64);
} ethertype_stats SEC(".maps");

/*
 * Non-IP sender statistics (per-interface, per-source-MAC, per-ethertype)
 * Key: struct nonip_sender_key  Value: struct nonip_sender_stats
 * LRU_HASH so oldest entries are evicted automatically when full.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, struct nonip_sender_key);
  __type(value, struct nonip_sender_stats);
} nonip_senders SEC(".maps");

/*
 * Tail call program array for dispatcher
 * Slot 0: content inspection
 */
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, MAX_DISPATCHER_PROGS);
  __type(key, __u32);
  __type(value, __u32);
} xdp_dispatcher SEC(".maps");

/*
 * Ring buffer for events
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

/*
 * Ring buffer for QUIC Initial inspection events (XDP ingress).
 *
 * Each event is ~1.3 KB (payload[1280] + DCID + metadata).  Sized at 1 MB so
 * roughly ~750 events can buffer before the producer drops; userspace consumer
 * drains continuously.
 *
 * Written exclusively by xdp_quic_initial_inspect (tail call slot
 * XDP_DISPATCHER_QUIC_SLOT) after the cheap long-header / version / Initial-
 * type pre-checks succeed.  Userspace performs Initial-key derivation and
 * ClientHello parsing off the fast path.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024); /* 1 MB */
} quic_inspect_events SEC(".maps");

/*
 * Flow verdict cache - generic verdict cache for fast-path enforcement.
 * Writers: Suricata EVE consumer (IPS DROP verdicts), QUIC SNI inspector
 * (post-Initial-decryption decisions, userspace), the in-kernel TCP SNI
 * inspector xdp_sni_inspect (PASS/DROP after walking matched rule actions),
 * and future inspectors.
 * Always compiled in so the cache is available even without the Suricata
 * feature.
 *
 * LRU_HASH (not plain HASH): the plain policy fast path now seeds a verdict for
 * every flow, and those never expire on time (POLICY_VERDICT_EXPIRES_NS == 0),
 * so on a busy host a plain HASH would fill and reject new inserts.
 * LRU lets the kernel evict the least-recently-used entry under pressure; an
 * evicted entry just costs one more two-level LPM walk when its flow reappears,
 * so correctness is preserved (the LPM walk is the authoritative fallback).
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_FLOW_VERDICTS);
  __type(key, struct flow_verdict_key);
  __type(value, struct flow_verdict);
} flow_verdict_cache SEC(".maps");

#ifdef SURICATA_IPS
/*
 * Inspect configuration (mode, mirror interface)
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct inspect_config);
} inspect_config SEC(".maps");

/*
 * Flows to inspect: written by XDP INSPECT action, read by TC ingress.
 * Value is the expiry timestamp (bpf_ktime_get_ns() + INSPECT_CLONE_TTL_NS).
 * TC ingress clones matching flows to pe-inspect0 via bpf_clone_redirect;
 * Suricata on pe-inspect1 receives the full TCP stream for L7 inspection.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FLOWS_TO_INSPECT);
  __type(key, struct flow_inspect_key);
  __type(value, __u64); /* expiry timestamp in ns */
} flows_to_inspect SEC(".maps");
#endif /* SURICATA_IPS */

/*
 * SNI rules map: keyed by rule_id, contains the TLS SNI pattern to match.
 * Written by userspace when a rule with SNI criteria is installed.
 * Read exclusively by xdp_sni_inspect (tail call slot 0).
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_POLICY_RULES);
  __type(key, __u64); /* rule_id */
  __type(value, struct sni_rule_entry);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} sni_rules SEC(".maps");

/*
 * MAC rule sidecar map.  Keyed by rule_id (u64); value is struct mac_rule_entry.
 * Only populated for rules that have mac_match_flags != 0.  Looked up in the
 * rule scan loops when the flag is set; common (no-MAC) rules pay only a single
 * unpredicted branch that resolves to "skip lookup".
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_POLICY_RULES);
  __type(key, __u64); /* rule_id */
  __type(value, struct mac_rule_entry);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} mac_rules SEC(".maps");

/*
 * MAC sidecar check helper.  Looks up rule_id in the mac_rules map and
 * calls match_mac.  Returns 1 if MAC criteria are satisfied, 0 otherwise.
 * Returns 1 (pass) if mac_match_flags is zero (fast path, no lookup needed).
 *
 * Marked __noinline so this becomes its own BPF subprogram.  The 8-iteration
 * unrolled rule-scan loop in xdp_policy_main would otherwise inline 8 copies
 * of the map-lookup + comparison code, bloating the program past the ±32767
 * instruction branch-range limit.  As a subprogram, only a single BPF call
 * instruction is emitted per loop iteration.
 *
 * pkt_src and pkt_dst must be PTR_TO_STACK (i.e. local array, not a raw
 * packet pointer) so the verifier accepts them as subprogram arguments.
 */
static __noinline __u8 check_mac_rule_xdp(const __u8 *pkt_src,
                                          const __u8 *pkt_dst,
                                          __u8 mac_match_flags,
                                          __u64 rule_id) {
  if (!mac_match_flags)
    return 1;
  struct mac_rule_entry *me = bpf_map_lookup_elem(&mac_rules, &rule_id);
  if (!me)
    return 0;
  return match_mac(pkt_src, pkt_dst, mac_match_flags, me);
}

/*
 * Scratch space for per-packet metadata (used by tail call chain).
 *
 * sni_pending[] holds all L4-matching SNI rules collected by the main program.
 * xdp_sni_inspect processes them one at a time via chained tail calls:
 *   sni_idx < sni_count  → check sni_pending[sni_idx], bump idx and re-call on
 * mismatch sni_idx >= sni_count → exhausted, return XDP_PASS
 */
struct pkt_meta {
  struct flow_key flow; /* 40 bytes */
  __u32 pkt_len;        /* 4  bytes */
  __u16 l4_off;         /* 2  bytes — L4 header offset from start of packet */
  __u8 sni_count;       /* 1  byte  — number of valid entries in sni_pending */
  __u8 sni_idx;         /* 1  byte  — next entry for xdp_sni_inspect to check */
  __u8 sni_seen;        /* 1  byte  — non-zero once match_sni_in_packet parsed a
                                       ClientHello (sni_result != 0).  Gates the
                                       no-match PASS verdict write so TCP SYNs
                                       and other non-TLS segments don't poison
                                       the cache before the real CH arrives. */
  __u8 _sni_pad[5];     /* explicit padding so the layout is obvious — t0 below
                           is 8-byte aligned regardless of compiler choice */
  __u64
      t0;                                             /* 8  bytes — packet start timestamp for processing-time histogram */
  __u16 l3_off;                                       /* 2  bytes — L3 header offset (for FIB forwarding in tail calls) */
  __u16 eth_proto;                                    /* 2  bytes — ethertype after VLAN stripping (for FIB forwarding) */
  struct sni_pending_entry sni_pending[MAX_L4_RULES]; /* 8 × 80 = 640 bytes */
  /* Flow cache tail call fields — written by FLOW_CACHE_TAIL_CALL, read by xdp_flow_cache_update */
  __u32 fc_verdict; /* XDP return code to pass through */
  __u32 fc_action;  /* ACTION_PASS / ACTION_DROP / etc. */
  __u64 fc_rule_id; /* matched rule id (or 0) */
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct pkt_meta);
} pkt_scratch SEC(".maps");

/*
 * Per-interface default action when no rule matches (configurable from userspace).
 * Keyed by ingress ifindex → u32 action (ACTION_PASS / ACTION_DROP).
 * Absent entry → ACTION_PASS.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, __u32);
  __type(value, __u32);
} default_action SEC(".maps");

/*
 * Per-interface FIB forwarding configuration (written by userspace).
 * Keyed by ingress ifindex: when mode == FIB_FORWARD_ENABLED for the packet's
 * ingress interface, the XDP program attempts bpf_fib_lookup() and redirects
 * directly to the next-hop interface, bypassing the kernel routing stack.
 * Absent entry or mode == FIB_FORWARD_DISABLED → normal XDP_PASS.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, __u32);
  __type(value, struct fib_config);
} fib_config_map SEC(".maps");

/*
 * Flow cache configuration — enables/disables per-flow accounting for IPFIX.
 * Written by userspace (ARRAY, key=0); read by the XDP program on every
 * successfully parsed packet.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct flow_cache_config);
} flow_cache_config_map SEC(".maps");

/*
 * Per-flow accounting cache for IPFIX export (ingress direction).
 * LRU_HASH auto-evicts the least-recently-used entry when full.
 * Key: struct flow_key (5-tuple). Value: struct flow_cache_entry.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct flow_key);
  __type(value, struct flow_cache_entry);
} flow_cache SEC(".maps");

/*
 * Two-level LPM: source prefix tries (IPv4 and IPv6).
 * Value contains the matched prefix length and a group ID that indexes into
 * src_groups_v4/v6 (HASH_OF_MAPS → inner dst LPM tries).
 */
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, struct src_lpm_key_v4);
  __type(value, struct src_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} src_lpm_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, struct src_lpm_key_v6);
  __type(value, struct src_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} src_lpm_v6 SEC(".maps");

/*
 * Inner dst LPM trie prototypes (IPv4 and IPv6).
 * libbpf creates these at load time; they serve as the prototype that userspace
 * clones when creating per-group inner maps to insert into src_groups_v4/v6.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_DST_ENTRIES_PER_GROUP);
  __type(key, struct lpm_key_v4);
  __type(value, struct dst_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} dst_lpm_v4_inner SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_DST_ENTRIES_PER_GROUP);
  __type(key, struct lpm_key_v6);
  __type(value, struct dst_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} dst_lpm_v6_inner SEC(".maps");

/*
 * HASH_OF_MAPS: src_group_id → inner dst LPM trie (IPv4 and IPv6).
 * Userspace creates inner dst LPM tries and inserts them here by group ID.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, __u32);
  __array(values, dst_lpm_v4_inner);
} src_groups_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, __u32);
  __array(values, dst_lpm_v6_inner);
} src_groups_v6 SEC(".maps");

/* Per-IP-protocol, per-L3-protocol, per-QUIC-version, and processing-time-
 * histogram counters live inside struct global_stats (see policy_common.h) —
 * updated through the global_stats pointer the datapath already holds, no
 * extra map lookups. */

/*
 * Build a flow_verdict_cache key from a parsed flow_key.  Shared by the
 * verdict-cache lookup in xdp_policy_main, the verdict writers below, and the
 * INSPECT pass-verdict writer in actions.h (hence defined before the include
 * block) so all stay in sync on field layout (address family, addresses,
 * ports, proto).
 */
static __always_inline void
flow_verdict_key_from_flow(struct flow_verdict_key *fv_key,
                           const struct flow_key *flow, __u32 ifindex) {
  if (flow->af == AF_INET) {
    fv_key->saddr4 = flow->saddr4;
    fv_key->daddr4 = flow->daddr4;
  } else {
    __builtin_memcpy(fv_key->saddr6, flow->saddr6, 16);
    __builtin_memcpy(fv_key->daddr6, flow->daddr6, 16);
  }
  fv_key->sport = flow->sport;
  fv_key->dport = flow->dport;
  fv_key->protocol = flow->protocol;
  fv_key->af = flow->af;
  fv_key->ifindex = ifindex;
}

// clang-format off
#include "parse.h"
#include "stats.h"
#include "events.h"
#include "actions.h"
#include "lookup.h"
#include "fib.h"
#include "urpf.h"
// clang-format on

/*
 * FIB_TAIL_CALL - if FIB forwarding is enabled, tail-call xdp_fib_dispatch.
 *
 * Uses a tail call so the FIB forwarding logic (bpf_fib_lookup + L2 rewrite)
 * lives in a separate XDP program with its own BPF verifier instruction budget.
 * If the tail call returns (slot not loaded), execution falls through to the
 * surrounding XDP_PASS return.
 *
 * Only place this at XDP_PASS return sites for IPv4/IPv6 traffic.
 */
#define FIB_TAIL_CALL(ctx)                                            \
  do {                                                                \
    __u32 __fib_key = (ctx)->ingress_ifindex;                         \
    const struct fib_config *__fc =                                   \
        bpf_map_lookup_elem(&fib_config_map, &__fib_key);             \
    if (__fc && __fc->mode == FIB_FORWARD_ENABLED)                    \
      bpf_tail_call((ctx), &xdp_dispatcher, XDP_DISPATCHER_FIB_SLOT); \
  } while (0)

/*
 * FLOW_CACHE_TAIL_CALL — tail-call xdp_flow_cache_update with flow metadata.
 *
 * Stores the flow key, length, rule id, action, and final verdict into the
 * per-CPU pkt_scratch slot, then tail-calls XDP_DISPATCHER_FLOW_CACHE_SLOT.
 * xdp_flow_cache_update will update the flow cache map and (for PASS verdicts)
 * chain on to xdp_fib_dispatch (FIB_TAIL_CALL inside that program).
 *
 * Fail-open: if the tail call slot is not loaded (e.g. feature disabled at
 * compile time) the bpf_tail_call is a no-op and execution continues with
 * the plain `return (_verdict)` below.
 *
 * _ctx:     struct xdp_md *
 * _fk:      const struct flow_key * — 5-tuple flow key
 * _len:     __u32 — packet length in bytes
 * _rid:     __u64 — matched rule_id (0 if no rule matched)
 * _act:     __u32 — ACTION_PASS / ACTION_DROP / ACTION_INSPECT
 * _verdict: __u32 — XDP_PASS / XDP_DROP / XDP_REDIRECT
 */
#define FLOW_CACHE_TAIL_CALL(_ctx, _fk, _len, _rid, _act, _verdict)           \
  do {                                                                        \
    __u32 _fc_key = 0;                                                        \
    struct pkt_meta *_fcm = bpf_map_lookup_elem(&pkt_scratch, &_fc_key);      \
    if (_fcm) {                                                               \
      __builtin_memcpy(&_fcm->flow, (_fk), sizeof(struct flow_key));          \
      _fcm->pkt_len = (_len);                                                 \
      _fcm->fc_rule_id = (_rid);                                              \
      _fcm->fc_action = (_act);                                               \
      _fcm->fc_verdict = (_verdict);                                          \
      bpf_tail_call((_ctx), &xdp_dispatcher, XDP_DISPATCHER_FLOW_CACHE_SLOT); \
    }                                                                         \
    return (_verdict);                                                        \
  } while (0)

/*
 * Seed flow_verdict_cache with the action selected by xdp_sni_inspect after
 * walking a matched rule's actions[] (or PASS on the no-match-after-all-rules-
 * exhausted path).  Caller passes the canonical ingress 5-tuple in flow.
 * Subsequent packets on the same flow short-circuit at xdp_policy_main's
 * verdict-cache check without re-running the SNI tail call.
 *
 * BPF_ANY so a DROP from a later rule in the chain overwrites an earlier
 * PASS seeded by an exhausted no-match probe on the same flow.
 */
static __always_inline void
xdp_sni_write_verdict(const struct flow_key *flow, __u32 action, __u64 now_ns,
                      __u32 ifindex) {
  struct flow_verdict_key fv_key = {};
  flow_verdict_key_from_flow(&fv_key, flow, ifindex);

  struct flow_verdict v = {};
  v.action = action;
  v.expires_ns = now_ns + SNI_VERDICT_TTL_NS;
  bpf_map_update_elem(&flow_verdict_cache, &fv_key, &v, BPF_ANY);
}

/*
 * Seed flow_verdict_cache from the plain policy fast path (the two-level LPM
 * result — L3 prefix + L4 port/proto — or the default action; no SNI / IPS).
 * After the first packet of a flow walks the trie, the resulting PASS/DROP is
 * cached so every subsequent packet on the same 5-tuple short-circuits at the
 * verdict-cache check in xdp_policy_main, skipping the O(ancestors^2) walk.
 * These verdicts never expire on time (POLICY_VERDICT_EXPIRES_NS == 0): they are
 * flushed on rule change and reclaimed by LRU under pressure.  rule_id (0 for
 * the default-action path) is stored so userspace can attribute the entry's
 * per-flow packet/byte counters back to rule_stats (see verdict_harvest.rs).
 * Callers must only invoke this for cacheable flows (pure PASS/DROP — see
 * process_rule_actions' cacheable flag).
 *
 * __noinline so the ~100 bytes of key + verdict live in this subprogram's
 * frame instead of xdp_policy_main's: main's frame plus its deepest callee
 * must fit the 512-byte combined stack limit (same reasoning as
 * tc_policy_write_verdict).
 */
static __noinline void
xdp_policy_write_verdict(const struct flow_key *flow, __u32 action,
                         __u64 rule_id, __u64 now_ns, __u32 ifindex) {
  struct flow_verdict_key fv_key = {};
  flow_verdict_key_from_flow(&fv_key, flow, ifindex);

  struct flow_verdict v = {};
  v.action = action;
  v.rule_id = rule_id;
  v.timestamp_ns = now_ns;
  v.expires_ns = POLICY_VERDICT_EXPIRES_NS;
  bpf_map_update_elem(&flow_verdict_cache, &fv_key, &v, BPF_ANY);
}

/*
 * xdp_sni_inspect — tail call program registered in xdp_dispatcher[0].
 *
 * Processes sni_pending[sni_idx] from pkt_scratch.  On an SNI mismatch (return
 * value -1 from match_sni_in_packet), increments sni_idx and tail-calls itself
 * (slot 0) to check the next pending rule.  This allows all L4-matching SNI
 * rules to be evaluated in order even though bpf_tail_call is one-way.
 *
 * Up to MAX_L4_RULES=8 chained calls, well within the Linux limit of 33.
 *
 * Semantics per rule:
 *   - sni_result ==  1  → SNI matches: apply action
 *   - sni_result ==  0  → not TLS / no SNI extension / truncated: SNI cannot
 *                         be proven, so the SNI-conditioned rule does not
 *                         match — skip to next pending rule
 *   - sni_result == -1  → different SNI: skip, advance to next pending rule
 */
SEC("xdp")
int xdp_sni_inspect(struct xdp_md *ctx) {
  __u32 zero = 0;
  struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_scratch, &zero);
  if (!meta)
    return XDP_PASS;

  /* Look up global stats once here so all return paths can update counters
   * and pass gs to MAYBE_FIB_FORWARD. */
  __u32 sni_ifindex = ctx->ingress_ifindex % MAX_INTERFACES;
  struct global_stats *sni_gs =
      bpf_map_lookup_elem(&global_stats, &sni_ifindex);

  if (meta->sni_idx >= meta->sni_count) {
    /* All SNI rules exhausted without a match — pass through.  Seed the
     * verdict cache so subsequent packets on this flow fast-path at L4 entry,
     * but ONLY if at least one rule's parser observed a real ClientHello on
     * this packet (sni_seen).  Otherwise this is a pre-handshake segment
     * (TCP SYN, ACK, etc.) and caching PASS here would poison the cache
     * before the real CH arrives. */
    __u64 sni_now = bpf_ktime_get_ns();
    if (meta->sni_seen)
      xdp_sni_write_verdict(&meta->flow, ACTION_PASS, sni_now,
                            ctx->ingress_ifindex);
    record_proc_time_at(sni_gs, meta->t0, sni_now);
    FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, 0, ACTION_PASS, XDP_PASS);
  }

  /* Mask idx so the verifier sees a bounded offset into sni_pending[].
   * MAX_L4_RULES = 8 = 2^3, mask = 7. */
  __u8 idx = meta->sni_idx;
  idx &= (MAX_L4_RULES - 1);

  __u64 rule_id = meta->sni_pending[idx].rule_id;

  struct sni_rule_entry *sni = bpf_map_lookup_elem(&sni_rules, &rule_id);

  void *data = (void *)(long)ctx->data;
  const void *data_end = (void *)(long)ctx->data_end;

  if (!sni || sni->sni_match_type == SNI_MATCH_NONE)
    goto next_rule;

  {
    int sni_result = match_sni_in_packet(data, data_end, meta->l4_off, sni);
    if (sni_result != 0)
      meta->sni_seen = 1; /* parser walked a real ClientHello on this packet */
    if (sni_result != 1)
      goto next_rule; /* no SNI / different SNI — try next pending rule */

    /* SNI matched: iterate all actions of the rule in priority order,
     * mirroring process_rule_actions() for non-SNI rules. */
    __u64 sni_now = bpf_ktime_get_ns();
    update_rule_stats(rule_id, meta->pkt_len, sni_now);
    struct global_stats *gs = sni_gs;

    __u32 final_verdict = XDP_PASS;
    __u32 final_action = ACTION_PASS;
    __u8 should_log = 0;
    __u8 stop_actions = 0;
    __u8 num_actions = meta->sni_pending[idx].num_actions;
    if (num_actions > MAX_ACTIONS_PER_RULE)
      num_actions = MAX_ACTIONS_PER_RULE;

#pragma unroll
    for (__u8 ai = 0; ai < MAX_ACTIONS_PER_RULE; ai++) {
      if (stop_actions || ai >= num_actions)
        break;
      __u32 a = meta->sni_pending[idx].actions[ai].action;
      switch (a) {
      case ACTION_DROP:
        final_verdict = XDP_DROP;
        final_action = ACTION_DROP;
        stop_actions = 1;
        break;
      case ACTION_LOG: {
        __u64 param = meta->sni_pending[idx].actions[ai].param;
        if (param > 0) {
          struct rule_stats *rs = bpf_map_lookup_elem(&rule_stats, &rule_id);
          if (rs) {
            __u64 old_ts = rs->last_log_ns;
            if (sni_now - old_ts < param)
              break;
            if (!__sync_bool_compare_and_swap(&rs->last_log_ns, old_ts, sni_now))
              break;
          }
        }
        should_log = 1;
        break;
      }
      case ACTION_PASS:
      default:
        break;
#ifdef SURICATA_IPS
      case ACTION_INSPECT: {
        __u32 cfg_key = 0;
        const struct inspect_config *cfg =
            bpf_map_lookup_elem(&inspect_config, &cfg_key);
        if (!cfg || cfg->mode == INSPECT_MODE_DISABLED)
          break;
        struct flow_inspect_key fi_key = {};
        flow_inspect_key_from_flow(&fi_key, &meta->flow);
        __u64 expiry = sni_now + INSPECT_CLONE_TTL_NS;
        bpf_map_update_elem(&flows_to_inspect, &fi_key, &expiry, BPF_ANY);
        struct flow_verdict_key fv_key = {};
        flow_verdict_key_from_flow(&fv_key, &meta->flow, ctx->ingress_ifindex);
        struct flow_verdict pass_v = {};
        pass_v.action = ACTION_PASS;
        pass_v.expires_ns = sni_now + INSPECT_PASS_VERDICT_TTL_NS;
        bpf_map_update_elem(&flow_verdict_cache, &fv_key, &pass_v, BPF_NOEXIST);
        break;
      }
#endif /* SURICATA_IPS */
      }
    }

    if (should_log) {
      struct policy_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
      if (evt) {
        evt->timestamp_ns = sni_now;
        evt->rule_id = rule_id;
        evt->action = ACTION_LOG;
        evt->ifindex = ctx->ingress_ifindex;
        __builtin_memcpy(&evt->flow, &meta->flow, sizeof(meta->flow));
        evt->pkt_len = meta->pkt_len;
        /* PolicyAction enum, not XDP return code — see xdp/actions.h */
        evt->verdict = final_action;
        evt->sni_len = sni->sni_len;
        if (sni->sni_len > 0 && sni->sni_len <= MAX_SNI_LEN) {
#pragma clang loop unroll(disable)
          for (__u8 i = 0; i < MAX_SNI_LEN; i++)
            evt->sni[i] = (i < sni->sni_len) ? sni->sni_pattern[i] : 0;
        }
        bpf_ringbuf_submit(evt, 0);
      }
    }

    update_action_stats(gs, final_action);

    if (final_verdict == XDP_DROP) {
      xdp_sni_write_verdict(&meta->flow, ACTION_DROP, sni_now,
                            ctx->ingress_ifindex);
      record_proc_time_at(gs, meta->t0, sni_now);
      FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, rule_id, ACTION_DROP, XDP_DROP);
    }
    goto next_rule;
  }

next_rule:
  meta->sni_idx++;
  if (meta->sni_idx < meta->sni_count)
    bpf_tail_call(ctx, &xdp_dispatcher, XDP_DISPATCHER_SNI_SLOT);
  /* Either all rules exhausted or tail call slot not loaded — pass through.
   * Seed the verdict cache only if at least one rule's parser proved this
   * packet carries a real ClientHello (see comment at the top of the function
   * for why pre-CH segments must not poison the cache). */
  {
    __u64 sni_now = bpf_ktime_get_ns();
    if (meta->sni_seen)
      xdp_sni_write_verdict(&meta->flow, ACTION_PASS, sni_now,
                            ctx->ingress_ifindex);
    record_proc_time_at(sni_gs, meta->t0, sni_now);
  }
  FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, 0, ACTION_PASS, XDP_PASS);
}

/*
 * xdp_quic_initial_inspect — tail call program registered in
 * xdp_dispatcher[XDP_DISPATCHER_QUIC_SLOT].
 *
 * Invoked from xdp_policy_main when a UDP packet matches a rule with an SNI
 * criterion.  Performs cheap header-only validation (long header form, fixed
 * bit, supported QUIC version, Initial packet type, plausible DCID length),
 * then if it looks like a QUIC Initial:
 *   - emits a quic_inspect_event to the quic_inspect_events ringbuf carrying
 *     the 5-tuple, version, DCID, and up to QUIC_INSPECT_PAYLOAD_MAX bytes of
 *     raw UDP payload so userspace can derive Initial keys and parse the
 *     ClientHello off the fast path;
 *   - seeds a short PASS verdict in flow_verdict_cache so subsequent packets
 *     for this flow short-circuit at xdp_policy_main entry while userspace
 *     finishes inspection.
 *
 * This program does NOT decrypt.  Misclassification (e.g. non-Initial that
 * passes the pre-checks) is harmless — userspace will fail to decrypt and
 * discard the event.  Up to 1–2 leaked Initial packets per flow before the
 * verdict takes effect is acceptable (handshake is typically 5+ packets).
 */
SEC("xdp")
int xdp_quic_initial_inspect(struct xdp_md *ctx) {
  __u32 zero = 0;
  struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_scratch, &zero);
  if (!meta)
    return XDP_PASS;

  /* For the processing-time histogram at pass_through (replaces the old
   * standalone histogram map lookup — net-neutral cost). */
  __u32 q_ifindex = ctx->ingress_ifindex % MAX_INTERFACES;
  struct global_stats *q_gs = bpf_map_lookup_elem(&global_stats, &q_ifindex);

  void *data = (void *)(long)ctx->data;
  const void *data_end = (void *)(long)ctx->data_end;

  /* Bound l4_off so the verifier sees a constrained packet offset. */
  __u16 l4_off = meta->l4_off;
  if (l4_off > 512)
    goto pass_through;

  /* UDP header is 8 bytes; QUIC payload starts at l4_off + 8. */
  __u32 q_off = (__u32)l4_off + 8;

  /* Need ≥ 7 bytes: first byte + 4-byte version + DCID-len byte + ≥1 DCID. */
  if ((void *)((__u8 *)data + q_off + 7) > data_end)
    goto pass_through;

  __u8 *q = (__u8 *)data + q_off;
  __u8 first = q[0];

  /* Long Header (bit 7) and Fixed Bit (bit 6) must both be set. */
  if ((first & 0xC0) != 0xC0)
    goto pass_through;

  __u32 version = ((__u32)q[1] << 24) | ((__u32)q[2] << 16) |
                  ((__u32)q[3] << 8) | q[4];

  /* Long packet type lives in bits 4-5 (the rest of the high nibble after the
   * form/fixed bits).  Initial = 0b00 in QUIC v1, Initial = 0b01 in QUIC v2. */
  __u8 long_type = (first >> 4) & 0x03;
  if (version == QUIC_VERSION_V1) {
    if (long_type != 0x00)
      goto pass_through;
  } else if (version == QUIC_VERSION_V2) {
    if (long_type != 0x01)
      goto pass_through;
  } else {
    /* Unknown version (or Version Negotiation 0x00000000) — userspace would
     * not know how to derive Initial keys. */
    goto pass_through;
  }

  __u8 dcid_len = q[5];
  if (dcid_len == 0 || dcid_len > QUIC_INSPECT_MAX_DCID_LEN)
    goto pass_through;

  /* Bounds-check the DCID bytes against packet end. */
  if ((void *)(q + 6 + dcid_len) > data_end)
    goto pass_through;

  /* Reserve a ringbuf event.  If ringbuf is full we still seed the verdict
   * and pass — losing one Initial is fine since QUIC will retransmit. */
  struct quic_inspect_event *evt =
      bpf_ringbuf_reserve(&quic_inspect_events, sizeof(*evt), 0);
  if (evt) {
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->ifindex = ctx->ingress_ifindex;
    evt->version = version;
    __builtin_memcpy(&evt->flow, &meta->flow, sizeof(meta->flow));
    evt->pkt_len = meta->pkt_len;
    evt->payload_off = (__u16)q_off;
    evt->dcid_len = dcid_len;

    /* DCID lives at payload[6..6+dcid_len] in the captured payload below.
     * Copying it here would require per-iteration packet bounds checks the
     * verifier can't easily prove; userspace extracts it from `payload`. */
    __builtin_memset(evt->dcid, 0, sizeof(evt->dcid));

    /* Compute available payload bytes (from start of QUIC header to end of
     * packet) and clamp to QUIC_INSPECT_PAYLOAD_MAX so the verifier sees a
     * bounded length for bpf_xdp_load_bytes. */
    __u32 avail = (meta->pkt_len > q_off) ? (meta->pkt_len - q_off) : 0;
    __u32 copy_len = avail;
    if (copy_len > QUIC_INSPECT_PAYLOAD_MAX)
      copy_len = QUIC_INSPECT_PAYLOAD_MAX;
    evt->payload_len = (__u16)copy_len;

    /* bpf_xdp_load_bytes rejects calls where the verifier can't prove
     * size > 0.  Two pitfalls to defeat:
     *   1. The compiler keeps the original register alive across `+r` asm
     *      barriers, so a barrier alone doesn't separate cl from copy_len.
     *      Round-trip through a volatile stack slot to force a real load.
     *   2. The compiler merges `cl > 0 && cl <= MAX` into a single
     *      `(cl - 1) > MAX-1` check, which doesn't narrow cl's tnum.  Keep
     *      the two compares separate so each one directly narrows cl. */
    volatile __u32 cl_slot = copy_len;
    __u32 cl = cl_slot;
    if (cl == 0)
      goto skip_payload_load;
    if (cl > QUIC_INSPECT_PAYLOAD_MAX)
      goto skip_payload_load;
    bpf_xdp_load_bytes(ctx, q_off, evt->payload, cl);
  skip_payload_load:;

    bpf_ringbuf_submit(evt, 0);
  }

  /* Intentionally no flow_verdict_cache seed here.  Modern Firefox/Chrome
   * spread the ClientHello across multiple Initial packets, often with
   * deliberately gappy/out-of-order CRYPTO frames; userspace needs to see
   * every Initial in the burst to reassemble.  Seeding even a short PASS
   * would short-circuit packets 2..N at the main entry and starve the
   * reassembly.  The verdict is written by userspace once the SNI is
   * extracted (or once it's clear no SNI is coming); until then we pay one
   * tail-call per packet, which is bounded (a handshake is <100 packets). */

pass_through:
  record_proc_time(q_gs, meta->t0);
  FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, 0, ACTION_PASS, XDP_PASS);
}

/*
 * Check the flow verdict cache for a cached PASS/DROP decision.
 *
 * Returns the XDP verdict (XDP_PASS / XDP_DROP) on a live cache hit, having
 * already updated the relevant counters and recorded timing, or -1 when there
 * is no usable cached decision and the caller should continue to policy lookup.
 *
 * On a hit, *rule_id_out is set to the verdict's originating rule_id (0 for
 * default / SNI / IPS verdicts) so the caller can attribute the packet in the
 * flow cache tail call; untouched on a miss.
 */
static __always_inline int
check_flow_verdict_cache(struct global_stats *stats,
                         const struct flow_verdict_key *fv_key, __u32 pkt_len,
                         __u64 t0, __u64 *rule_id_out) {
  struct flow_verdict *fv = bpf_map_lookup_elem(&flow_verdict_cache, fv_key);
  if (!fv)
    return -1;

  __u64 now = bpf_ktime_get_ns();
  if (fv->expires_ns != 0 && now >= fv->expires_ns)
    return -1;

  if (fv->action == ACTION_DROP) {
    __sync_fetch_and_add(&fv->packets, 1);
    __sync_fetch_and_add(&fv->bytes, pkt_len);
    fv->last_seen_ns = now;
    update_action_stats(stats, ACTION_DROP);
    if (stats) {
      stats->verdict_drop_packets++;
      stats->verdict_drop_bytes += pkt_len;
    }
    /* A rule-derived verdict (rule_id != 0) counts as a policy match on every
     * packet, mirroring the cache-miss LPM path, so policy_matches stays
     * consistent with policy_drops/policy_pass (which already count per packet
     * here).  rule_id is 0 for default / SNI / IPS verdicts — no rule matched,
     * so no bump.  Per-rule packet/byte counters are NOT bumped here: userspace
     * harvests the per-flow counters above into rule_stats (verdict_harvest.rs),
     * keeping the rule_stats HASH lookup and its shared atomic adds off the
     * per-packet fast path. */
    if (fv->rule_id && stats)
      stats->policy_matches++;
    *rule_id_out = fv->rule_id;
    /* Reuse 'now' already read above — avoids an extra clock call */
    record_proc_time_at(stats, t0, now);
    return XDP_DROP;
  } else if (fv->action == ACTION_PASS) {
    /* Cached PASS verdict: flow previously inspected and not flagged.
     * Pass through immediately, skipping the policy lookup. */
    __sync_fetch_and_add(&fv->packets, 1);
    __sync_fetch_and_add(&fv->bytes, pkt_len);
    fv->last_seen_ns = now;
    update_action_stats(stats, ACTION_PASS);
    if (stats) {
      stats->verdict_pass_packets++;
      stats->verdict_pass_bytes += pkt_len;
    }
    if (fv->rule_id && stats)
      stats->policy_matches++;
    *rule_id_out = fv->rule_id;
    record_proc_time_at(stats, t0, now);
    return XDP_PASS;
  }

  return -1;
}

/*
 * Build the flow_verdict_key and check the verdict cache.
 */
static __always_inline int
xdp_flow_verdict_cache_check(struct global_stats *stats,
                             const struct flow_key *flow, __u32 ifindex,
                             __u32 pkt_len, __u64 t0, __u64 *rule_id_out) {
  struct flow_verdict_key fv_key = {};
  flow_verdict_key_from_flow(&fv_key, flow, ifindex);
  return check_flow_verdict_cache(stats, &fv_key, pkt_len, t0, rule_id_out);
}

/*
 * Apply the L4 rules in a matched dst-prefix entry.
 *
 * rules[] is sorted by priority.  Non-SNI rules are evaluated immediately;
 * SNI rules are queued into meta->sni_pending[] (meta->sni_count is bumped)
 * for the chained tail-call inspection path.  Scanning stops at the first
 * non-SNI rule that DROPs.  *fc_rule_id is set to the first matching rule
 * (overridden by a DROP rule).
 *
 * Returns the immediate verdict: XDP_DROP if a non-SNI rule dropped, else
 * XDP_PASS (the caller still consults meta->sni_count for the SNI tail call).
 */
static __always_inline __u32
xdp_apply_l4_rules(struct xdp_md *ctx, struct global_stats *stats,
                   struct dst_lpm_value *policy, struct flow_key *flow_key,
                   __u64 t0, __u32 pkt_len, const __u8 *pkt_src_mac,
                   const __u8 *pkt_dst_mac, struct pkt_meta *meta,
                   __u64 *fc_rule_id, __u8 *cacheable) {
  __u8 cnt = policy->count;
  if (cnt > MAX_L4_RULES)
    cnt = MAX_L4_RULES;

  __u32 final_verdict = XDP_PASS;
  __u8 dropped = 0;

  for (int r = 0; r < MAX_L4_RULES; r++) {
    if (!dropped && (__u8)r < cnt) {
      struct l4_rule *rule = &policy->rules[r];
      if (match_l4(flow_key, rule) &&
          match_quic_version(flow_key->flags, rule->quic_version) &&
          check_mac_rule_xdp(pkt_src_mac, pkt_dst_mac, rule->mac_match_flags,
                             rule->rule_id)) {
        if (rule->sni_match_type == SNI_MATCH_NONE) {
          /* Non-SNI rule: apply immediately */
          update_rule_stats(rule->rule_id, pkt_len, t0);
          if (*fc_rule_id == 0)
            *fc_rule_id = rule->rule_id;
          __u32 v =
              process_rule_actions(ctx, stats, rule, flow_key, t0, cacheable);
          if (v == XDP_DROP) {
            *fc_rule_id = rule->rule_id; /* override with the DROP rule */
            dropped = 1;
            final_verdict = XDP_DROP;
          }
        } else {
          /* SNI rule: queue for tail-call chain */
          if (meta && meta->sni_count < MAX_L4_RULES) {
            __u8 si = meta->sni_count;
            /* Mask index so the verifier sees a bounded offset.
             * MAX_L4_RULES = 8 = 2^3. */
            __asm__ volatile("" : "+r"(si));
            si &= (MAX_L4_RULES - 1);
            meta->sni_pending[si].rule_id = rule->rule_id;
            meta->sni_pending[si].num_actions = rule->num_actions;
#pragma unroll
            for (__u8 ai = 0; ai < MAX_ACTIONS_PER_RULE; ai++)
              meta->sni_pending[si].actions[ai] = rule->actions[ai];
            meta->sni_count++;
          }
        }
      }
    }
  }

  return final_verdict;
}

/*
 * Populate pkt_scratch with the flow metadata the SNI inspection tail call
 * needs.  Called on the cold SNI path only (sni_count preserved from the rule
 * loop); see the lazy-population note at the call site.
 */
static __always_inline void
xdp_fill_sni_meta(struct pkt_meta *meta, const struct flow_key *flow_key,
                  __u32 pkt_len, int l4_off, __u64 t0, int l3_off,
                  __u16 eth_proto) {
  __builtin_memcpy(&meta->flow, flow_key, sizeof(*flow_key));
  meta->pkt_len = pkt_len;
  meta->l4_off = (__u16)l4_off;
  meta->sni_idx = 0;
  meta->sni_seen = 0;
  meta->t0 = t0;
  meta->l3_off = (__u16)l3_off;
  meta->eth_proto = eth_proto;
}

SEC("xdp")
int xdp_policy_main(struct xdp_md *ctx) {
  struct flow_key flow_key;
  struct dst_lpm_value *policy;
  __u32 pkt_len = ctx->data_end - ctx->data;
  __u32 zero = 0;
  __u16 eth_proto = 0;
  void *data = (void *)(long)ctx->data;
  const void *data_end = (void *)(long)ctx->data_end;
  __u64 t0 = bpf_ktime_get_ns();
  __u64 fc_rule_id = 0; /* rule_id for flow cache: set to the first matching rule */

  /* Count ALL ingress packets (including non-IP, BUM, malformed) */
  __u32 ifindex = ctx->ingress_ifindex % MAX_INTERFACES;
  struct global_stats *stats = bpf_map_lookup_elem(&global_stats, &ifindex);
  /* Unreachable at runtime: PERCPU_ARRAY lookup with an in-bounds key (the
   * modulo above) never fails.  The early return teaches the verifier stats
   * is non-NULL, so every downstream `if (stats)` prunes instead of forking
   * verifier states that are carried across the inlined LPM walk (a NULL /
   * non-NULL map-value pointer held live across the program doubles its
   * exploration and risks the 1M processed-insn limit). */
  if (!stats)
    return XDP_PASS;
  stats->rx_packets++;
  stats->rx_bytes += pkt_len;

  /* Check Ethernet header for BUM traffic classification and MAC matching */
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    if (stats)
      stats->parse_errors++;
    record_proc_time(stats, t0);
    return XDP_PASS;
  }

  /* Copy MACs to stack arrays so they can be passed to __noinline subprograms.
   * PTR_TO_PACKET (eth->h_source/h_dest) cannot cross subprogram boundaries;
   * PTR_TO_STACK can.  eth bounds are already validated above. */
  __u8 pkt_src_mac[6];
  __u8 pkt_dst_mac[6];
  __builtin_memcpy(pkt_src_mac, eth->h_source, sizeof(pkt_src_mac));
  __builtin_memcpy(pkt_dst_mac, eth->h_dest, sizeof(pkt_dst_mac));

  /* Get the ethertype */
  int l3_off = get_ethertype(data, data_end, &eth_proto);
  if (eth_proto == 0 || l3_off == 0) {
    /* Failed to parse ethertype - treat as parse error */
    if (stats)
      stats->parse_errors++;
    record_proc_time(stats, t0);
    return XDP_PASS;
  }

  /* Classify L3 protocol (buckets: 0=IPv4, 1=IPv6, 2=ARP, 3=MPLS, 4=Other) */
  update_l3_proto_stats(stats, eth_proto, pkt_len);

  /* Parse packet to extract flow key.
   * Returns >= 0 (L4 offset) on success, PARSE_NONFIRST_FRAG (-2) for a
   * non-first IP fragment, or -1 on a genuine parse error. */
  int l4_off = parse_packet(ctx, &flow_key, l3_off, eth_proto);

  if (l4_off == PARSE_NONFIRST_FRAG) {
    /* Non-first IP fragment: src/dst IP and protocol are valid, but there is
     * no L4 header so sport/dport are 0.  Count it and let the policy lookup
     * proceed — rules without port constraints will still match. */
    if (stats)
      stats->fragments++;
    l4_off = 0;
  } else if (l4_off < 0) {
    if (stats) {
      if (eth_proto == ETH_P_IP || eth_proto == ETH_P_IPV6) {
        /* Valid IP ethertype but failed to parse L4 — malformed IP packet */
        stats->parse_errors++;
      } else if (is_bum_traffic(eth)) {
        stats->bum_packets++;
      } else {
        stats->non_ip_unicast++;
      }
    }

    /* Track ethertype for non-IP traffic */
    if (eth_proto != ETH_P_IP && eth_proto != ETH_P_IPV6) {
      update_ethertype_stats(ctx->ingress_ifindex, eth_proto);
      /* Track per-(mac, ethertype) sender stats for all non-IP traffic */
      update_nonip_sender_stats(ctx->ingress_ifindex, pkt_src_mac, eth_proto);
    }

    record_proc_time(stats, t0);
    return XDP_PASS;
  }

  /* Update per-IP-protocol stats (flow_key.protocol is valid from here) */
  update_l4_proto_stats(stats, flow_key.protocol, pkt_len);

  /* Update QUIC stats if this packet looks like QUIC */
  if (flow_key.flags & FLOW_FLAG_QUIC)
    update_quic_stats(stats, flow_key.flags, pkt_len);

  /* uRPF (unicast Reverse Path Forwarding) check.  Runs before policy and the
   * verdict cache so source-spoofed packets are dropped as cheaply as possible.
   * No-op (single map lookup) unless uRPF is enabled on this ingress interface.
   * Drops are accounted in global_stats by xdp_urpf_check itself. */
  if (xdp_urpf_check(ctx, stats, eth_proto, l3_off, pkt_len)) {
    // todo: we should probably have 2 classes of drop, POLICY_DROP and URPF_DROP.
    update_action_stats(stats, ACTION_DROP);
    record_proc_time(stats, t0);
    return XDP_DROP;
  }

  /* Check flow verdict cache.  Writers are the Suricata EVE consumer (IPS
   * DROP verdicts), the QUIC SNI inspector, and any future flow-verdict
   * source.  A hit short-circuits the policy lookup at XDP line rate. */
  __u64 fv_rule_id = 0;
  int cached_verdict = xdp_flow_verdict_cache_check(
      stats, &flow_key, ctx->ingress_ifindex, pkt_len, t0, &fv_rule_id);
  /* Timing already recorded by check_flow_verdict_cache on a hit (which
   * reuses its expiry-check timestamp, avoiding a second ktime call);
   * recording again here would double-count the packet in the histogram.
   *
   * A hit must still exit through FLOW_CACHE_TAIL_CALL: returning the verdict
   * directly here would skip per-flow IPFIX accounting AND the FIB-forwarding
   * chain for every post-first packet of a flow (xdp_flow_cache_update chains
   * to xdp_fib_dispatch for PASS verdicts), stranding cached-PASS traffic in
   * the kernel slow path exactly when the cache is supposed to make it fast. */
  if (cached_verdict >= 0)
    FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, fv_rule_id,
                         cached_verdict == XDP_DROP ? ACTION_DROP : ACTION_PASS,
                         cached_verdict);

  /* Lookup policy (two-level LPM: src prefix → dst prefix → L4 rules).
   * Scoped per-interface by ctx->ingress_ifindex. */
  policy = lookup_policy_v2(&flow_key, ctx->ingress_ifindex);

  if (policy) {
    /* Update rule match counter */
    if (stats)
      stats->policy_matches++;

    /* Grab the pkt_scratch slot and reset only sni_count so the rule loop
     * below can queue SNI rules into sni_pending[].  The full flow metadata
     * (flow key, offsets, timestamps) is consumed solely by the SNI
     * inspection tail call, so it is populated lazily just before that tail
     * call fires (see below).  This keeps the common no-SNI path — the vast
     * majority of packets — free of the 40-byte flow memcpy and the scalar
     * field writes, which FLOW_CACHE_TAIL_CALL would overwrite anyway. */
    struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_scratch, &zero);
    /* Unreachable at runtime (PERCPU_ARRAY, key 0) — early return teaches the
     * verifier meta is non-NULL so the rule loop's meta checks prune. */
    if (!meta)
      return XDP_PASS;
    meta->sni_count = 0;

    /* Cleared by xdp_apply_l4_rules if any matched rule carries a LOG / INSPECT
     * / TAIL_CALL action; gates the policy verdict seed below. */
    __u8 cacheable = 1;
    __u32 final_verdict = xdp_apply_l4_rules(ctx, stats, policy, &flow_key, t0,
                                             pkt_len, pkt_src_mac, pkt_dst_mac,
                                             meta, &fc_rule_id, &cacheable);
    __u8 dropped = (final_verdict == XDP_DROP);

    /* If any SNI rules were queued (and no DROP already), tail-call to the
     * inspection program.  Branch by L4 protocol so the same `sni` rule field
     * triggers TLS-ClientHello matching on TCP and QUIC-Initial detection on
     * UDP.  All queued rules share the packet's protocol (match_l4 enforced
     * it), so we only need to inspect flow_key.protocol once. */
    if (!dropped && meta && meta->sni_count > 0) {
      if (stats)
        stats->tail_calls++;
      /* Now that we know an SNI inspection tail call is happening, populate the
       * flow metadata the inspection program needs.  sni_count is preserved
       * (set by the rule loop above); the rest is written here on the cold
       * SNI path only. */
      xdp_fill_sni_meta(meta, &flow_key, pkt_len, l4_off, t0, l3_off,
                        eth_proto);
      /* Timing is recorded by the inspection tail-call program at its terminal
       * returns so that the full inspection path is included in the histogram. */
      if (flow_key.protocol == PROTO_UDP)
        bpf_tail_call(ctx, &xdp_dispatcher, XDP_DISPATCHER_QUIC_SLOT);
      else
        bpf_tail_call(ctx, &xdp_dispatcher, XDP_DISPATCHER_SNI_SLOT);
      /* Tail call slot not loaded — fail open */
      record_proc_time(stats, t0);
      update_action_stats(stats, ACTION_PASS);
      FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, fc_rule_id, ACTION_PASS, XDP_PASS);
    }

    record_proc_time(stats, t0);
    /* Seed the policy verdict cache so every subsequent packet on this 5-tuple
     * short-circuits at the verdict-cache check above instead of re-walking the
     * two-level LPM trie.  Only for cacheable flows (pure PASS/DROP); LOG /
     * INSPECT / SNI flows are excluded so they keep re-evaluating. */
    if (cacheable)
      xdp_policy_write_verdict(&flow_key, dropped ? ACTION_DROP : ACTION_PASS,
                               fc_rule_id, t0, ctx->ingress_ifindex);
    if (final_verdict == XDP_PASS)
      goto fib_and_pass;
    FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, fc_rule_id, ACTION_DROP, final_verdict);

  } else {
    /* No matching rule - use per-interface default action */
    __u32 ifidx = ctx->ingress_ifindex;
    __u32 *def_action = bpf_map_lookup_elem(&default_action, &ifidx);
    __u32 action = def_action ? *def_action : ACTION_PASS;
    update_action_stats(stats, action);

    /* Seed the default verdict (rule_id 0) so unmatched flows also skip the LPM
     * walk on subsequent packets.  Flushed on any rule change. */
    xdp_policy_write_verdict(&flow_key,
                             action == ACTION_DROP ? ACTION_DROP : ACTION_PASS,
                             0, t0, ctx->ingress_ifindex);

    /* Return appropriate XDP verdict */
    record_proc_time(stats, t0);
    switch (action) {
    case ACTION_DROP:
      FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, 0, ACTION_DROP, XDP_DROP);
    case ACTION_PASS:
    case ACTION_LOG:
    default:
      goto fib_and_pass;
    }
  }
  /* Single FIB-forwarding exit: tail-call xdp_fib_dispatch if enabled.
   * Using a tail call keeps xdp_policy_main within the BPF verifier instruction
   * budget (1M processed instructions) while the FIB logic lives in its own
   * program with a separate budget. */
fib_and_pass:
  FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, fc_rule_id, ACTION_PASS, XDP_PASS);
}

/*
 * xdp_fib_dispatch — FIB forwarding program for transit traffic.
 *
 * Registered in xdp_dispatcher[XDP_DISPATCHER_FIB_SLOT].  Called via tail call
 * from xdp_policy_main and xdp_sni_inspect when FIB forwarding is enabled and
 * the packet was not dropped by policy.
 *
 * Re-parses the Ethernet header to obtain eth_proto and l3_off, then delegates
 * to xdp_fib_forward() which performs bpf_fib_lookup(), L2 header rewrite, TTL
 * decrement, and bpf_redirect().  Falls back to XDP_PASS on any failure.
 */
SEC("xdp")
int xdp_fib_dispatch(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  __u16 eth_proto = 0;
  int l3_off = get_ethertype(data, data_end, &eth_proto);
  if (eth_proto == 0 || l3_off == 0)
    return XDP_PASS;

  __u32 ifindex = ctx->ingress_ifindex % MAX_INTERFACES;
  struct global_stats *gs = bpf_map_lookup_elem(&global_stats, &ifindex);
  __u32 pkt_len = (__u32)((long)data_end - (long)data);

  return xdp_fib_forward(ctx, gs, eth_proto, l3_off, pkt_len);
}

#ifdef SURICATA_IPS
/*
 * Return 1 if this ingress flow is currently marked for Suricata inspection
 * (inspection mode enabled, present in flows_to_inspect, and unexpired).
 *
 * Used by xdp_flow_cache_update to keep inspected flows off the FIB redirect
 * path: bpf_redirect bypasses the kernel stack and with it TC ingress, where
 * tc_policy_ingress clones marked flows to the Suricata mirror interface.
 * Such flows must take XDP_PASS while their inspection window is open.
 *
 * __noinline so the flow_inspect_key lives in this subprogram's frame and the
 * config branches re-converge at the call boundary (same reasoning as
 * xdp_mark_flow_for_inspect).  Cold: two map lookups, and the second only
 * when inspection mode is enabled node-wide.
 */
static __noinline int xdp_flow_under_inspection(const struct flow_key *flow) {
  __u32 cfg_key = 0;
  const struct inspect_config *cfg =
      bpf_map_lookup_elem(&inspect_config, &cfg_key);
  if (!cfg || cfg->mode == INSPECT_MODE_DISABLED)
    return 0;

  struct flow_inspect_key fi_key = {};
  flow_inspect_key_from_flow(&fi_key, flow);
  const __u64 *expiry = bpf_map_lookup_elem(&flows_to_inspect, &fi_key);
  if (!expiry)
    return 0;
  return *expiry == 0 || bpf_ktime_get_ns() < *expiry;
}
#endif /* SURICATA_IPS */

/*
 * xdp_flow_cache_update — flow cache accounting program.
 *
 * Registered in xdp_dispatcher[XDP_DISPATCHER_FLOW_CACHE_SLOT].
 * Tail-called by xdp_policy_main and xdp_sni_inspect (via FLOW_CACHE_TAIL_CALL)
 * with the final verdict and flow metadata stored in pkt_scratch.
 *
 * Updates the per-flow accounting entry in flow_cache (if enabled), then for
 * PASS verdicts chains on to xdp_fib_dispatch via FIB_TAIL_CALL so the full
 * policy_main → flow_cache_update → fib_dispatch chain completes correctly.
 * Flows under Suricata inspection are exempted from the FIB chain (see
 * xdp_flow_under_inspection above).
 */
SEC("xdp")
int xdp_flow_cache_update(struct xdp_md *ctx) {
  __u32 zero = 0;
  struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_scratch, &zero);
  if (!meta)
    return XDP_PASS;

  __u32 verdict = meta->fc_verdict;

  struct flow_cache_config *cfg =
      bpf_map_lookup_elem(&flow_cache_config_map, &zero);
  if (cfg && cfg->enabled == FLOW_CACHE_ENABLED) {
    struct flow_cache_entry *fe = bpf_map_lookup_elem(&flow_cache, &meta->flow);
    if (fe) {
      __sync_fetch_and_add(&fe->packets, 1);
      __sync_fetch_and_add(&fe->bytes, meta->pkt_len);
      fe->last_seen_ns = bpf_ktime_get_ns();
      fe->action = meta->fc_action;
    } else {
      struct flow_cache_entry new_fe = {};
      __u64 now = bpf_ktime_get_ns();
      new_fe.first_seen_ns = now;
      new_fe.last_seen_ns = now;
      new_fe.packets = 1;
      new_fe.bytes = meta->pkt_len;
      new_fe.rule_id = meta->fc_rule_id;
      new_fe.action = meta->fc_action;
      bpf_map_update_elem(&flow_cache, &meta->flow, &new_fe, BPF_ANY);
    }
  }

  /* For PASS verdicts, chain on to FIB forwarding if enabled. */
  if (verdict == XDP_PASS) {
#ifdef SURICATA_IPS
    /* An XDP FIB redirect would bypass TC ingress and starve Suricata of the
     * flow it is supposed to be inspecting — keep marked flows on the kernel
     * path (slow, but correct) until their inspection window closes. */
    if (xdp_flow_under_inspection(&meta->flow))
      return XDP_PASS;
#endif /* SURICATA_IPS */
    FIB_TAIL_CALL(ctx);
  }
  return verdict;
}
