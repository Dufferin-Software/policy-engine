// SPDX-License-Identifier: GPL-2.0-only
/*
 * TC Policy Engine - Egress TC program with LPM-based policy matching
 *
 * Mirrors xdp_policy.bpf.c for egress traffic using TC (Traffic Control).
 * Uses separate maps prefixed with tc_ to allow independent ingress/egress
 * rules.
 */

#include "../include/bpf_helpers.h"
#include "../include/policy_common.h"
#include "../include/vmlinux_subset.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Per-rule statistics map (egress)
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_POLICY_RULES);
  __type(key, __u64); /* rule_id */
  __type(value, struct rule_stats);
} tc_rule_stats SEC(".maps");

/*
 * Global per-CPU statistics (egress)
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, __u32);
  __type(value, struct global_stats);
} tc_global_stats SEC(".maps");

/*
 * Tail call program array for dispatcher (egress)
 */
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, MAX_DISPATCHER_PROGS);
  __type(key, __u32);
  __type(value, __u32);
} tc_dispatcher SEC(".maps");

/*
 * Ring buffer for events (egress)
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* 256 KB */
} tc_events SEC(".maps");

/*
 * Ring buffer for QUIC Initial inspection events (TC egress).
 * Mirrors quic_inspect_events in xdp_policy.bpf.c.  Separate map so the
 * egress side has its own producer/consumer pair.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024); /* 1 MB */
} tc_quic_inspect_events SEC(".maps");

/*
 * Flow verdict cache for egress.  Generic primitive shared by the Suricata
 * IPS path, the QUIC SNI inspector (userspace), and the in-kernel TCP SNI
 * inspector tc_sni_inspect (PASS/DROP after walking matched rule actions).
 * Always compiled in.
 *
 * LRU_HASH (not plain HASH): the plain L4 fast path seeds a verdict for every
 * flow with a 12 h TTL, so the table must self-evict under flow-count pressure
 * rather than fill and reject inserts.  See flow_verdict_cache in
 * src/bpf/xdp/xdp_policy.bpf.c for the full rationale.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_FLOW_VERDICTS);
  __type(key, struct flow_verdict_key);
  __type(value, struct flow_verdict);
} tc_flow_verdict_cache SEC(".maps");

#ifdef SURICATA_IPS
/*
 * Inspect configuration (used by both TC egress and TC ingress)
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct inspect_config);
} tc_inspect_config SEC(".maps");

/*
 * Per-interface XDP feature config (FIB forwarding / uRPF / inspect enable).
 * Owned and pinned by the XDP skeleton; this skeleton reuses the pin (same
 * mechanism as flows_to_inspect below) so the TC egress ACTION_INSPECT arms
 * can honour the per-interface inspect_enabled flag.  Keyed by ifindex.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, __u32);
  __type(value, struct fib_config);
} fib_config_map SEC(".maps");

/*
 * Flows to inspect: shared with XDP skeleton via BPF filesystem pinning.
 * XDP writes an entry on each INSPECT rule match; TC ingress reads it to
 * decide which flows to clone to pe-inspect0 for Suricata inspection.
 * Value is the expiry timestamp in nanoseconds.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_FLOWS_TO_INSPECT);
  __type(key, struct flow_inspect_key);
  __type(value, __u64); /* expiry timestamp in ns */
} flows_to_inspect SEC(".maps");
#endif /* SURICATA_IPS */

/*
 * Scratch space for per-packet metadata (used by tail call chain).
 * Mirrors struct pkt_meta in xdp_policy.bpf.c; kept separate because TC and
 * XDP use independent PERCPU_ARRAY maps.
 */
struct tc_pkt_meta {
  struct flow_key flow; /* 40 bytes */
  __u32 pkt_len;        /* 4  bytes */
  __u16 l4_off;         /* 2  bytes */
  __u8 sni_count;       /* 1  byte  — number of valid entries in sni_pending */
  __u8 sni_idx;         /* 1  byte  — next entry for tc_sni_inspect to check */
  __u8 sni_seen;        /* 1  byte  — non-zero once match_sni_in_packet parsed a
                                       ClientHello (sni_result != 0).  Gates the
                                       no-match PASS verdict write so TCP SYNs
                                       and other non-TLS segments don't poison
                                       the cache before the real CH arrives. */
  __u8 _sni_pad[5];     /* explicit padding so the layout is obvious — t0 below
                           is 8-byte aligned regardless of compiler choice */
  __u64
      t0;                                             /* 8  bytes — packet start timestamp for processing-time histogram */
  struct sni_pending_entry sni_pending[MAX_L4_RULES]; /* 8 × 80 = 640 bytes */
  /* Flow cache tail call fields — written by TC_FLOW_CACHE_TAIL_CALL, read by tc_flow_cache_update */
  __u32 fc_verdict; /* TC return code to pass through */
  __u32 fc_action;  /* ACTION_PASS / ACTION_DROP / etc. */
  __u64 fc_rule_id; /* matched rule id (or 0) */
}; /* 200 bytes total */

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct tc_pkt_meta);
} tc_pkt_scratch SEC(".maps");

/*
 * SNI rules map (egress): keyed by rule_id, contains the TLS SNI pattern.
 * Written by userspace when a TC egress rule with SNI criteria is installed.
 * Read exclusively by tc_sni_inspect (tail call slot 0).
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_POLICY_RULES);
  __type(key, __u64); /* rule_id */
  __type(value, struct sni_rule_entry);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_sni_rules SEC(".maps");

/*
 * MAC rule sidecar map (TC egress mirror of XDP mac_rules).
 * Keyed by rule_id (u64); value is struct mac_rule_entry.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_POLICY_RULES);
  __type(key, __u64); /* rule_id */
  __type(value, struct mac_rule_entry);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_mac_rules SEC(".maps");

/*
 * MAC sidecar check helper for TC egress — mirrors check_mac_rule_xdp.
 * Marked __noinline to keep the rule-scan loop in tc_policy_egress within the
 * ±32767 instruction branch-range limit.
 * pkt_src/pkt_dst must be PTR_TO_STACK (local arrays, not raw packet pointers).
 */
static __noinline __u8 check_mac_rule_tc(const __u8 *pkt_src,
                                         const __u8 *pkt_dst,
                                         __u8 mac_match_flags,
                                         __u64 rule_id) {
  if (!mac_match_flags)
    return 1;
  struct mac_rule_entry *me = bpf_map_lookup_elem(&tc_mac_rules, &rule_id);
  if (!me)
    return 0;
  return match_mac(pkt_src, pkt_dst, mac_match_flags, me);
}

/*
 * Default action when no rule matches (configurable from userspace)
 */
/*
 * Per-interface default action when no rule matches (configurable from userspace).
 * Keyed by egress ifindex → u32 action (ACTION_PASS / ACTION_DROP).
 * Absent entry → ACTION_PASS.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_INTERFACES);
  __type(key, __u32);
  __type(value, __u32);
} tc_default_action SEC(".maps");

/*
 * Two-level LPM: source prefix tries (egress, IPv4 and IPv6).
 */
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, struct src_lpm_key_v4);
  __type(value, struct src_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_src_lpm_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, struct src_lpm_key_v6);
  __type(value, struct src_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_src_lpm_v6 SEC(".maps");

/*
 * Inner dst LPM trie prototypes (egress, IPv4 and IPv6).
 */
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_DST_ENTRIES_PER_GROUP);
  __type(key, struct lpm_key_v4);
  __type(value, struct dst_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_dst_lpm_v4_inner SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, MAX_DST_ENTRIES_PER_GROUP);
  __type(key, struct lpm_key_v6);
  __type(value, struct dst_lpm_value);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} tc_dst_lpm_v6_inner SEC(".maps");

/*
 * HASH_OF_MAPS: src_group_id → inner dst LPM trie (egress, IPv4 and IPv6).
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, __u32);
  __array(values, tc_dst_lpm_v4_inner);
} tc_src_groups_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_SRC_GROUPS);
  __type(key, __u32);
  __array(values, tc_dst_lpm_v6_inner);
} tc_src_groups_v6 SEC(".maps");

/*
 * Processing-time histogram (log2 ns buckets 0-63, egress)
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 64);
  __type(key, __u32);
  __type(value, __u64);
} tc_processing_time_hist SEC(".maps");

/*
 * Per-IP-protocol packet/byte counters (egress, indexed by protocol 0-255)
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 256);
  __type(key, __u32);
  __type(value, struct proto_stats);
} tc_per_proto_stats SEC(".maps");

/*
 * Per-L3-protocol packet/byte counters (egress).
 * Buckets: 0=IPv4, 1=IPv6, 2=ARP, 3=MPLS, 4=Other
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 5);
  __type(key, __u32);
  __type(value, struct proto_stats);
} tc_per_l3_stats SEC(".maps");

/*
 * Flow cache configuration — enables/disables per-flow accounting for IPFIX
 * (egress direction). Written by userspace; read on every processed packet.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct flow_cache_config);
} tc_flow_cache_config_map SEC(".maps");

/*
 * Per-flow accounting cache for IPFIX export (egress direction).
 * LRU_HASH auto-evicts the least-recently-used entry when full.
 * Key: struct flow_key (5-tuple). Value: struct flow_cache_entry.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct flow_key);
  __type(value, struct flow_cache_entry);
} tc_flow_cache SEC(".maps");

/* Record elapsed ns into the egress log2 histogram (reads clock internally) */
#define TC_RECORD_TIMING(t0)                                             \
  do {                                                                   \
    __u64 __delta = bpf_ktime_get_ns() - (t0);                           \
    __u32 __slot = log2_u64(__delta);                                    \
    if (__slot > 63)                                                     \
      __slot = 63;                                                       \
    __u64 *__h = bpf_map_lookup_elem(&tc_processing_time_hist, &__slot); \
    if (__h)                                                             \
      (*__h)++;                                                          \
  } while (0)

/* Record elapsed ns using a pre-fetched 'now' — avoids an extra
 * bpf_ktime_get_ns() call on paths that already read the clock. */
#define TC_RECORD_TIMING_AT(t0, now)                                     \
  do {                                                                   \
    __u64 __delta = (now) - (t0);                                        \
    __u32 __slot = log2_u64(__delta);                                    \
    if (__slot > 63)                                                     \
      __slot = 63;                                                       \
    __u64 *__h = bpf_map_lookup_elem(&tc_processing_time_hist, &__slot); \
    if (__h)                                                             \
      (*__h)++;                                                          \
  } while (0)

/*
 * TC_FLOW_CACHE_TAIL_CALL — tail-call tc_flow_cache_update with flow metadata.
 *
 * Mirrors FLOW_CACHE_TAIL_CALL in xdp_policy.bpf.c; uses tc_pkt_scratch and
 * tc_dispatcher. TC does not chain to FIB forwarding (TC-only program).
 *
 * Fail-open: if the tail call slot is not loaded the bpf_tail_call is a no-op
 * and execution continues with the plain `return (_verdict)` below.
 */
#define TC_FLOW_CACHE_TAIL_CALL(_ctx, _fk, _len, _rid, _act, _verdict)      \
  do {                                                                      \
    __u32 _fc_key = 0;                                                      \
    struct tc_pkt_meta *_fcm =                                              \
        bpf_map_lookup_elem(&tc_pkt_scratch, &_fc_key);                     \
    if (_fcm) {                                                             \
      __builtin_memcpy(&_fcm->flow, (_fk), sizeof(struct flow_key));        \
      _fcm->pkt_len = (_len);                                               \
      _fcm->fc_rule_id = (_rid);                                            \
      _fcm->fc_action = (_act);                                             \
      _fcm->fc_verdict = (_verdict);                                        \
      bpf_tail_call((_ctx), &tc_dispatcher, TC_DISPATCHER_FLOW_CACHE_SLOT); \
    }                                                                       \
    return (_verdict);                                                      \
  } while (0)

// clang-format off
#include "parse.h"
#include "stats.h"
#include "events.h"
#include "actions.h"
#include "lookup.h"
// clang-format on

#ifdef SURICATA_IPS
/*
 * Clone this egress packet to the Suricata mirror interface if its flow is
 * marked for inspection.
 *
 * flows_to_inspect is keyed by the ingress direction (src=server, dst=client),
 * so the parsed egress 5-tuple is reversed for the lookup.  Cloning outgoing
 * client→server packets too gives Suricata the full bidirectional stream and
 * lets request-based rules (e.g. http.host) fire before the server responds.
 *
 * Marked __noinline: the inspect-config and expiry branches would otherwise
 * fork verifier states ahead of the (huge) inlined LPM walk in
 * tc_policy_egress; as a subprogram the states re-converge at the call
 * boundary.  Cold path — only flows already under inspection reach the map
 * lookup, and the extra BPF-to-BPF call is dwarfed by the clone itself.
 */
static __noinline void tc_clone_inspected_flow(struct __sk_buff *ctx,
                                               const struct flow_key *flow) {
  __u32 zero = 0;
  const struct inspect_config *icfg =
      bpf_map_lookup_elem(&tc_inspect_config, &zero);
  if (!icfg || icfg->mode == INSPECT_MODE_DISABLED ||
      icfg->mirror_ifindex == 0)
    return;

  struct flow_inspect_key fi_key = {};
  flow_inspect_key_from_flow_reversed(&fi_key, flow);

  const __u64 *expiry = bpf_map_lookup_elem(&flows_to_inspect, &fi_key);
  if (!expiry)
    return;

  __u64 now = bpf_ktime_get_ns();
  if (*expiry == 0 || now < *expiry)
    bpf_clone_redirect(ctx, icfg->mirror_ifindex, 0);
}
#endif /* SURICATA_IPS */

/*
 * Build a tc_flow_verdict_cache key from a parsed flow_key.  Shared by the
 * verdict-cache lookup in tc_policy_egress and the verdict writer below so the
 * two stay in sync on field layout (address family, addresses, ports, proto).
 */
static __always_inline void
tc_flow_verdict_key_from_flow(struct flow_verdict_key *fv_key,
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

/*
 * Seed tc_flow_verdict_cache from the plain policy fast path (the two-level LPM
 * result — L3 prefix + L4 port/proto — or the default action; no SNI / IPS).
 * Mirrors xdp_policy_write_verdict for egress: the first packet of a flow walks
 * the trie; the resulting PASS/DROP is cached so subsequent packets
 * short-circuit at the verdict-cache check in tc_policy_egress.  These verdicts
 * never expire on time (POLICY_VERDICT_EXPIRES_NS == 0): flushed on rule change,
 * reclaimed by LRU under pressure.  rule_id (0 for the default path) keeps
 * rule_stats accurate on cache hits.  Callers must only invoke this for
 * cacheable (pure PASS/DROP) flows.  Defined here (before tc_policy_egress)
 * since the main program calls it.
 */
static __noinline void
tc_policy_write_verdict(const struct flow_key *flow, __u32 action,
                        __u64 rule_id, __u64 now_ns, __u32 ifindex) {
  struct flow_verdict_key fv_key = {};
  tc_flow_verdict_key_from_flow(&fv_key, flow, ifindex);

  struct flow_verdict v = {};
  v.action = action;
  v.rule_id = rule_id;
  v.timestamp_ns = now_ns;
  v.expires_ns = POLICY_VERDICT_EXPIRES_NS;
  bpf_map_update_elem(&tc_flow_verdict_cache, &fv_key, &v, BPF_ANY);
}

/*
 * Check the flow verdict cache for a cached PASS/DROP decision.
 *
 * Returns the TC verdict (TC_ACT_OK / TC_ACT_SHOT) on a live cache hit, having
 * already updated the relevant counters and recorded timing, or -1 when there
 * is no usable cached decision and the caller should continue to policy lookup.
 */
static __always_inline int
tc_check_flow_verdict_cache(struct global_stats *gs,
                            const struct flow_verdict_key *fv_key,
                            __u32 pkt_len, __u64 t0) {
  struct flow_verdict *fv = bpf_map_lookup_elem(&tc_flow_verdict_cache, fv_key);
  if (!fv)
    return -1;

  __u64 now = bpf_ktime_get_ns();
  if (fv->expires_ns != 0 && now >= fv->expires_ns)
    return -1;

  if (fv->action == ACTION_DROP) {
    __sync_fetch_and_add(&fv->packets, 1);
    __sync_fetch_and_add(&fv->bytes, pkt_len);
    update_action_stats(gs, ACTION_DROP);
    if (gs) {
      gs->verdict_drop_packets++;
      gs->verdict_drop_bytes += pkt_len;
    }
    /* A rule-derived verdict (rule_id != 0) counts as a policy match on every
     * packet, mirroring the cache-miss LPM path, so policy_matches stays
     * consistent with policy_drops/policy_pass (which already count per packet
     * here).  Also keep per-rule stats accurate.  rule_id is 0 for default /
     * SNI / IPS verdicts — no rule matched, so no bump. */
    if (fv->rule_id) {
      tc_update_rule_stats(fv->rule_id, pkt_len, now);
      if (gs)
        gs->policy_matches++;
    }
    /* Reuse 'now' already read above — avoids an extra clock call */
    TC_RECORD_TIMING_AT(t0, now);
    return TC_ACT_SHOT;
  } else if (fv->action == ACTION_PASS) {
    /* Cached PASS verdict: flow previously inspected, pass through. */
    __sync_fetch_and_add(&fv->packets, 1);
    __sync_fetch_and_add(&fv->bytes, pkt_len);
    update_action_stats(gs, ACTION_PASS);
    if (gs) {
      gs->verdict_pass_packets++;
      gs->verdict_pass_bytes += pkt_len;
    }
    if (fv->rule_id) {
      tc_update_rule_stats(fv->rule_id, pkt_len, now);
      if (gs)
        gs->policy_matches++;
    }
    TC_RECORD_TIMING_AT(t0, now);
    return TC_ACT_OK;
  }

  return -1;
}

/*
 * Build the flow_verdict_key and check the verdict cache (egress).
 *
 * Marked __noinline so the 64-byte key lives in this subprogram's frame
 * instead of tc_policy_egress's: main's frame plus its deepest callee must
 * fit the 512-byte combined stack limit, and main is the frame every callee
 * stacks onto.  The lookup/branch state also re-converges at the call
 * boundary instead of forking across the LPM walk.
 */
static __noinline int
tc_flow_verdict_cache_check(struct global_stats *gs,
                            const struct flow_key *flow, __u32 ifindex,
                            __u32 pkt_len, __u64 t0) {
  struct flow_verdict_key fv_key = {};
  tc_flow_verdict_key_from_flow(&fv_key, flow, ifindex);
  return tc_check_flow_verdict_cache(gs, &fv_key, pkt_len, t0);
}

/*
 * Apply the L4 rules in a matched dst-prefix entry (egress).
 *
 * rules[] is sorted by priority.  Non-SNI rules are evaluated immediately;
 * SNI rules are queued into meta->sni_pending[] (meta->sni_count is bumped)
 * for the chained tail-call inspection path.  Scanning stops at the first
 * non-SNI rule that DROPs.  *fc_rule_id is set to the first matching rule
 * (overridden by a DROP rule).
 *
 * Returns the immediate verdict: TC_ACT_SHOT if a non-SNI rule dropped, else
 * TC_ACT_OK (the caller still consults meta->sni_count for the SNI tail call).
 */
static __always_inline int
tc_apply_l4_rules(struct __sk_buff *ctx, struct global_stats *gs,
                  struct dst_lpm_value *policy, struct flow_key *flow_key,
                  __u64 t0, __u32 pkt_len, const __u8 *pkt_src_mac,
                  const __u8 *pkt_dst_mac, struct tc_pkt_meta *meta,
                  __u64 *fc_rule_id, __u8 *cacheable) {
  __u8 cnt = policy->count;
  if (cnt > MAX_L4_RULES)
    cnt = MAX_L4_RULES;

  int final_verdict = TC_ACT_OK;
  __u8 dropped = 0;

  for (int r = 0; r < MAX_L4_RULES; r++) {
    if (!dropped && (__u8)r < cnt) {
      struct l4_rule *rule = &policy->rules[r];
      if (match_l4(flow_key, rule) &&
          match_quic_version(flow_key->flags, rule->quic_version) &&
          check_mac_rule_tc(pkt_src_mac, pkt_dst_mac, rule->mac_match_flags,
                            rule->rule_id)) {
        if (rule->sni_match_type == SNI_MATCH_NONE) {
          tc_update_rule_stats(rule->rule_id, pkt_len, t0);
          if (*fc_rule_id == 0)
            *fc_rule_id = rule->rule_id;
          int v =
              tc_process_rule_actions(ctx, gs, rule, flow_key, t0, cacheable);
          if (v == TC_ACT_SHOT) {
            *fc_rule_id = rule->rule_id; /* override with DROP rule */
            dropped = 1;
            final_verdict = TC_ACT_SHOT;
          }
        } else {
          if (meta && meta->sni_count < MAX_L4_RULES) {
            __u8 si = meta->sni_count;
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
 * Populate tc_pkt_scratch with the flow metadata the SNI inspection tail call
 * needs.  Called on the cold SNI path only (sni_count preserved from the rule
 * loop); see the lazy-population note at the call site.
 */
static __always_inline void
tc_fill_sni_meta(struct tc_pkt_meta *meta, const struct flow_key *flow_key,
                 __u32 pkt_len, int l4_off, __u64 t0) {
  __builtin_memcpy(&meta->flow, flow_key, sizeof(*flow_key));
  meta->pkt_len = pkt_len;
  meta->l4_off = (__u16)l4_off;
  meta->sni_idx = 0;
  meta->sni_seen = 0;
  meta->t0 = t0;
}

SEC("tc")
int tc_policy_egress(struct __sk_buff *ctx) {
  struct flow_key flow_key;
  struct dst_lpm_value *policy;
  __u32 pkt_len = ctx->len;
  __u32 zero = 0;
  __u64 t0 = bpf_ktime_get_ns();
  __u64 tc_fc_rule_id = 0; /* rule_id for flow cache: first matching rule */

  /* Hoist the stats pointer — one lookup for the whole path.  The inspect
   * config is deliberately NOT hoisted: a map-value-or-NULL pointer held live
   * across the whole program forks the verifier state ahead of the (huge)
   * inlined LPM walk and doubles its exploration, which is what pushed
   * tc_policy_egress past the 1M processed-insn limit.  The SURICATA_IPS
   * consumers look it up locally instead (see tc_clone_inspected_flow and
   * the ACTION_INSPECT case in tc/actions.h, mirroring the XDP side). */
  __u32 gs_key = ctx->ifindex % MAX_INTERFACES;
  struct global_stats *gs = bpf_map_lookup_elem(&tc_global_stats, &gs_key);
  /* Unreachable at runtime: PERCPU_ARRAY lookup with an in-bounds key (the
   * modulo above) never fails.  The early return teaches the verifier gs is
   * non-NULL, so every downstream `if (gs)` prunes instead of forking states
   * that are carried across the inlined LPM walk. */
  if (!gs)
    return TC_ACT_OK;

  /* Count ALL egress packets (including non-IP) */
  gs->tx_packets++;
  gs->tx_bytes += pkt_len;

  /* Extract source/destination MAC for per-rule L2 matching */
  __u8 pkt_src_mac[6] = {};
  __u8 pkt_dst_mac[6] = {};
  {
    void *_mac_data = (void *)(long)ctx->data;
    const void *_mac_data_end = (void *)(long)ctx->data_end;
    struct ethhdr *_eth = _mac_data;
    if ((void *)(_eth + 1) <= _mac_data_end) {
      __builtin_memcpy(pkt_src_mac, _eth->h_source, 6);
      __builtin_memcpy(pkt_dst_mac, _eth->h_dest, 6);
    }
  }

  /* Classify L3 protocol (buckets: 0=IPv4, 1=IPv6, 2=ARP, 3=MPLS, 4=Other) */
  {
    void *data = (void *)(long)ctx->data;
    const void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) <= data_end) {
      __u16 eth_proto = bpf_ntohs(eth->h_proto);
      /* Look through one level of VLAN tag */
      if (eth_proto == ETH_P_8021Q) {
        struct {
          __be16 tci;
          __be16 inner;
        } *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) <= data_end)
          eth_proto = bpf_ntohs(vlan->inner);
      }
      tc_update_l3_proto_stats(eth_proto, pkt_len);
    }
  }

  /* Parse packet to extract flow key.
   * Returns >= 0 (L4 offset) on success, PARSE_NONFIRST_FRAG (-2) for a
   * non-first IP fragment, or -1 on a genuine parse error / non-IP traffic. */
  int l4_off = tc_parse_packet(ctx, &flow_key);

  if (l4_off == PARSE_NONFIRST_FRAG) {
    /* Non-first IP fragment: src/dst IP and protocol are valid, no L4 header.
     * Count it and let the policy lookup proceed with IP/protocol-only
     * matching. */
    if (gs)
      gs->fragments++;
    l4_off = 0;
  } else if (l4_off < 0) {
    /* Non-IP traffic or malformed packet on egress — pass through */
    TC_RECORD_TIMING(t0);
    return TC_ACT_OK;
  }

  /* Update per-IP-protocol stats (flow_key.protocol valid from here) */
  tc_update_ip_proto_stats(flow_key.protocol, pkt_len);

  /* Check flow verdict cache.  Writers are the Suricata EVE consumer and the
   * QUIC SNI inspector; a hit short-circuits the policy lookup. */
  {
    int cached_verdict =
        tc_flow_verdict_cache_check(gs, &flow_key, ctx->ifindex, pkt_len, t0);
    if (cached_verdict >= 0)
      return cached_verdict;
  }

#ifdef SURICATA_IPS
  /* Clone egress packets belonging to flows being inspected on ingress. */
  tc_clone_inspected_flow(ctx, &flow_key);
#endif /* SURICATA_IPS */

  /* Lookup policy (two-level LPM: src prefix → dst prefix → L4 rules).
   * Scoped per-interface by skb->ifindex (TC egress interface). */
  policy = tc_lookup_policy_v2(&flow_key, ctx->ifindex);

  if (policy) {
    /* Update rule match counter */
    if (gs)
      gs->policy_matches++;

    /* Grab the tc_pkt_scratch slot and reset only sni_count so the rule loop
     * below can queue SNI rules into sni_pending[].  The full flow metadata is
     * consumed solely by the SNI inspection tail call, so it is populated
     * lazily just before that tail call fires (see below).  This keeps the
     * common no-SNI path — the vast majority of packets — free of the 40-byte
     * flow memcpy and the scalar field writes, which TC_FLOW_CACHE_TAIL_CALL
     * would overwrite anyway. */
    struct tc_pkt_meta *meta = bpf_map_lookup_elem(&tc_pkt_scratch, &zero);
    /* Unreachable at runtime (PERCPU_ARRAY, key 0) — early return teaches the
     * verifier meta is non-NULL so the rule loop's meta checks prune. */
    if (!meta)
      return TC_ACT_OK;
    meta->sni_count = 0;

    /* Cleared by tc_apply_l4_rules if any matched rule carries a LOG / INSPECT
     * / TAIL_CALL action; gates the policy verdict seed below. */
    __u8 cacheable = 1;
    int final_verdict = tc_apply_l4_rules(ctx, gs, policy, &flow_key, t0,
                                          pkt_len, pkt_src_mac, pkt_dst_mac,
                                          meta, &tc_fc_rule_id, &cacheable);
    __u8 dropped = (final_verdict == TC_ACT_SHOT);

    if (!dropped && meta && meta->sni_count > 0) {
      if (gs)
        gs->tail_calls++;
      /* Now that we know an SNI inspection tail call is happening, populate the
       * flow metadata the inspection program needs.  sni_count is preserved
       * (set by the rule loop above); the rest is written here on the cold
       * SNI path only. */
      tc_fill_sni_meta(meta, &flow_key, pkt_len, l4_off, t0);
      /* Branch by L4 protocol so the same `sni` rule field triggers TLS-
       * ClientHello matching on TCP and QUIC-Initial detection on UDP.
       * Timing is recorded by the inspection tail-call program. */
      if (flow_key.protocol == PROTO_UDP)
        bpf_tail_call(ctx, &tc_dispatcher, TC_DISPATCHER_QUIC_SLOT);
      else
        bpf_tail_call(ctx, &tc_dispatcher, TC_DISPATCHER_SNI_SLOT);
      /* Tail call slot not loaded — fail open */
      TC_RECORD_TIMING(t0);
      update_action_stats(gs, ACTION_PASS);
      TC_FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, tc_fc_rule_id, ACTION_PASS, TC_ACT_OK);
    }

    TC_RECORD_TIMING(t0);
    /* Seed the policy verdict cache so subsequent packets on this 5-tuple
     * short-circuit at the verdict-cache check instead of re-walking the
     * two-level LPM trie.  Only for cacheable flows (pure PASS/DROP). */
    if (cacheable)
      tc_policy_write_verdict(&flow_key, dropped ? ACTION_DROP : ACTION_PASS,
                              tc_fc_rule_id, t0, ctx->ifindex);
    TC_FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, tc_fc_rule_id,
                            final_verdict == TC_ACT_SHOT ? ACTION_DROP : ACTION_PASS,
                            final_verdict);

  } else {
    /* No matching rule - use per-interface default action */
    __u32 ifidx = ctx->ifindex;
    __u32 *def_action = bpf_map_lookup_elem(&tc_default_action, &ifidx);
    __u32 action = def_action ? *def_action : ACTION_PASS;
    update_action_stats(gs, action);

    /* Seed the default verdict (rule_id 0) so unmatched flows skip the LPM walk
     * on subsequent packets.  Flushed on any rule change. */
    tc_policy_write_verdict(&flow_key,
                            action == ACTION_DROP ? ACTION_DROP : ACTION_PASS, 0,
                            t0, ctx->ifindex);

    TC_RECORD_TIMING(t0);
    switch (action) {
    case ACTION_DROP:
      TC_FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, 0, ACTION_DROP, TC_ACT_SHOT);
    case ACTION_PASS:
    case ACTION_LOG:
    default:
      TC_FLOW_CACHE_TAIL_CALL(ctx, &flow_key, pkt_len, 0, ACTION_PASS, TC_ACT_OK);
    }
  }
}

/*
 * Seed tc_flow_verdict_cache with the action selected by tc_sni_inspect after
 * walking a matched rule's actions[] (or PASS on the no-match-after-all-rules-
 * exhausted path).  TC egress uses the canonical egress 5-tuple (client→server)
 * as the key, mirroring the read path in tc_policy_egress's verdict-cache
 * check.  Subsequent packets short-circuit there without re-running the SNI
 * tail call.
 */
static __always_inline void
tc_sni_write_verdict(const struct flow_key *flow, __u32 action, __u64 now_ns,
                     __u32 ifindex) {
  struct flow_verdict_key fv_key = {};
  tc_flow_verdict_key_from_flow(&fv_key, flow, ifindex);

  struct flow_verdict v = {};
  v.action = action;
  v.expires_ns = now_ns + SNI_VERDICT_TTL_NS;
  bpf_map_update_elem(&tc_flow_verdict_cache, &fv_key, &v, BPF_ANY);
}

/*
 * tc_sni_inspect — tail call program registered in tc_dispatcher[0].
 *
 * Mirrors xdp_sni_inspect for egress traffic.  Processes sni_pending[sni_idx]
 * from tc_pkt_scratch; on SNI mismatch increments sni_idx and tail-calls itself
 * to check the next pending rule (chained, up to MAX_L4_RULES=8 invocations).
 */
SEC("tc")
int tc_sni_inspect(struct __sk_buff *ctx) {
  __u32 zero = 0;
  struct tc_pkt_meta *meta = bpf_map_lookup_elem(&tc_pkt_scratch, &zero);
  if (!meta)
    return TC_ACT_OK;
  if (meta->sni_idx >= meta->sni_count) {
    /* All SNI rules exhausted without a match — pass through.  Seed the
     * verdict cache so subsequent packets on this flow fast-path at L4 entry,
     * but ONLY if at least one rule's parser observed a real ClientHello on
     * this packet (sni_seen).  Otherwise this is a pre-handshake segment
     * (TCP SYN, ACK, etc.) and caching PASS here would poison the cache
     * before the real CH arrives. */
    __u64 sni_now = bpf_ktime_get_ns();
    if (meta->sni_seen)
      tc_sni_write_verdict(&meta->flow, ACTION_PASS, sni_now, ctx->ifindex);
    TC_RECORD_TIMING_AT(meta->t0, sni_now);
    TC_FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, 0, ACTION_PASS, TC_ACT_OK);
  }

  __u8 idx = meta->sni_idx;
  idx &= (MAX_L4_RULES - 1);

  __u64 rule_id = meta->sni_pending[idx].rule_id;

  struct sni_rule_entry *sni = bpf_map_lookup_elem(&tc_sni_rules, &rule_id);

  /* TSO/GSO super-skbs (common on egress for large TLS ClientHellos —
   * Brave + post-quantum key share + ECH pushes the CH to ~2 KB) keep most
   * payload bytes in paged fragments; ctx->data..data_end only spans the
   * linear header region.  match_sni_in_packet() uses direct packet access
   * and will bail at the first read past the linear region, leaving SNI
   * undetected for any segment whose CH spills past the headers.  Pull
   * enough data into the linear region to cover a realistic ClientHello
   * before reading ctx->data.  Cap at SNI_PULL_MAX so the verifier sees a
   * bounded scalar; the parser itself enforces 0x3000 anyway. */
  __u32 want = ctx->len;
  if (want > SNI_PULL_MAX)
    want = SNI_PULL_MAX;
  if (want > 0)
    (void)bpf_skb_pull_data(ctx, want);

  void *data = (void *)(long)ctx->data;
  const void *data_end = (void *)(long)ctx->data_end;

  __u32 gs_key = ctx->ifindex % MAX_INTERFACES;
  struct global_stats *gs = bpf_map_lookup_elem(&tc_global_stats, &gs_key);

  if (!sni || sni->sni_match_type == SNI_MATCH_NONE)
    goto next_rule;

  {
    int sni_result = match_sni_in_packet(data, data_end, meta->l4_off, sni);
    if (sni_result != 0)
      meta->sni_seen = 1; /* parser walked a real ClientHello on this packet */
    if (sni_result != 1)
      goto next_rule; /* no SNI / different SNI — try next pending rule */

    /* SNI matched: iterate all actions in priority order, mirroring
     * tc_process_rule_actions() for non-SNI rules. */
    __u64 sni_now = bpf_ktime_get_ns();
    tc_update_rule_stats(rule_id, meta->pkt_len, sni_now);

    __u32 final_verdict = TC_ACT_OK;
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
        final_verdict = TC_ACT_SHOT;
        final_action = ACTION_DROP;
        stop_actions = 1;
        break;
      case ACTION_LOG: {
        __u64 param = meta->sni_pending[idx].actions[ai].param;
        if (param > 0) {
          struct rule_stats *rs =
              bpf_map_lookup_elem(&tc_rule_stats, &rule_id);
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
        __u32 icfg_key = 0;
        struct inspect_config *icfg =
            bpf_map_lookup_elem(&tc_inspect_config, &icfg_key);
        if (!icfg || icfg->mode == INSPECT_MODE_DISABLED)
          break;
        /* Per-interface gate — mirrors the ACTION_INSPECT arm in
         * tc/actions.h: only mark flows on inspect-enabled interfaces. */
        __u32 if_key = ctx->ifindex;
        const struct fib_config *fc =
            bpf_map_lookup_elem(&fib_config_map, &if_key);
        if (!fc || fc->inspect_enabled != INSPECT_IF_ENABLED)
          break;
        struct flow_inspect_key fi_key = {};
        flow_inspect_key_from_flow_reversed(&fi_key, &meta->flow);
        __u64 expiry = sni_now + INSPECT_CLONE_TTL_NS;
        bpf_map_update_elem(&flows_to_inspect, &fi_key, &expiry, BPF_ANY);
        if (icfg->mirror_ifindex != 0)
          bpf_clone_redirect(ctx, icfg->mirror_ifindex, 0);
        break;
      }
#endif /* SURICATA_IPS */
      }
    }

    if (should_log) {
      struct policy_event *evt =
          bpf_ringbuf_reserve(&tc_events, sizeof(*evt), 0);
      if (evt) {
        evt->timestamp_ns = sni_now;
        evt->rule_id = rule_id;
        evt->action = ACTION_LOG;
        evt->ifindex = ctx->ifindex;
        __builtin_memcpy(&evt->flow, &meta->flow, sizeof(meta->flow));
        evt->pkt_len = meta->pkt_len;
        /* PolicyAction enum, not TC return code — see tc/actions.h */
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

    if (final_verdict == TC_ACT_SHOT) {
      tc_sni_write_verdict(&meta->flow, ACTION_DROP, sni_now, ctx->ifindex);
      TC_RECORD_TIMING_AT(meta->t0, sni_now);
      TC_FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, rule_id, ACTION_DROP, TC_ACT_SHOT);
    }
    goto next_rule;
  }

next_rule:
  meta->sni_idx++;
  if (meta->sni_idx < meta->sni_count)
    bpf_tail_call(ctx, &tc_dispatcher, TC_DISPATCHER_SNI_SLOT);
  /* Either all rules exhausted or tail call slot not loaded — pass through.
   * Seed the verdict cache only if at least one rule's parser proved this
   * packet carries a real ClientHello (see comment at the top of the function
   * for why pre-CH segments must not poison the cache). */
  {
    __u64 sni_now = bpf_ktime_get_ns();
    if (meta->sni_seen)
      tc_sni_write_verdict(&meta->flow, ACTION_PASS, sni_now, ctx->ifindex);
    TC_RECORD_TIMING_AT(meta->t0, sni_now);
  }
  TC_FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, 0, ACTION_PASS, TC_ACT_OK);
}

/*
 * tc_quic_initial_inspect — tail call program registered in
 * tc_dispatcher[TC_DISPATCHER_QUIC_SLOT].
 *
 * Egress mirror of xdp_quic_initial_inspect.  See that program's comment for
 * the design rationale; the only differences are (a) ringbuf is
 * tc_quic_inspect_events, (b) packet copy uses bpf_skb_load_bytes, and (c)
 * verdict-cache seeding flips src/dst to match the canonical ingress
 * orientation used by all other writers (the policy engine stores verdicts
 * by ingress 5-tuple regardless of which path observed the flow).
 */
SEC("tc")
int tc_quic_initial_inspect(struct __sk_buff *ctx) {
  __u32 zero = 0;
  struct tc_pkt_meta *meta = bpf_map_lookup_elem(&tc_pkt_scratch, &zero);
  if (!meta)
    return TC_ACT_OK;

  void *data = (void *)(long)ctx->data;
  const void *data_end = (void *)(long)ctx->data_end;

  __u16 l4_off = meta->l4_off;
  if (l4_off > 512)
    goto pass_through;

  __u32 q_off = (__u32)l4_off + 8;

  if ((void *)((__u8 *)data + q_off + 7) > data_end)
    goto pass_through;

  __u8 *q = (__u8 *)data + q_off;
  __u8 first = q[0];

  if ((first & 0xC0) != 0xC0)
    goto pass_through;

  __u32 version = ((__u32)q[1] << 24) | ((__u32)q[2] << 16) |
                  ((__u32)q[3] << 8) | q[4];

  __u8 long_type = (first >> 4) & 0x03;
  if (version == QUIC_VERSION_V1) {
    if (long_type != 0x00)
      goto pass_through;
  } else if (version == QUIC_VERSION_V2) {
    if (long_type != 0x01)
      goto pass_through;
  } else {
    goto pass_through;
  }

  __u8 dcid_len = q[5];
  if (dcid_len == 0 || dcid_len > QUIC_INSPECT_MAX_DCID_LEN)
    goto pass_through;

  if ((void *)(q + 6 + dcid_len) > data_end)
    goto pass_through;

  struct quic_inspect_event *evt =
      bpf_ringbuf_reserve(&tc_quic_inspect_events, sizeof(*evt), 0);
  if (evt) {
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->ifindex = ctx->ifindex;
    evt->version = version;
    __builtin_memcpy(&evt->flow, &meta->flow, sizeof(meta->flow));
    evt->pkt_len = meta->pkt_len;
    evt->payload_off = (__u16)q_off;
    evt->dcid_len = dcid_len;

    /* DCID lives at payload[6..6+dcid_len] in the captured payload below;
     * userspace extracts it from there.  See xdp_quic_initial_inspect. */
    __builtin_memset(evt->dcid, 0, sizeof(evt->dcid));

    __u32 avail = (meta->pkt_len > q_off) ? (meta->pkt_len - q_off) : 0;
    __u32 copy_len = avail;
    if (copy_len > QUIC_INSPECT_PAYLOAD_MAX)
      copy_len = QUIC_INSPECT_PAYLOAD_MAX;
    evt->payload_len = (__u16)copy_len;

    /* See xdp_quic_initial_inspect: volatile round-trip plus two separate
     * bounds compares are required so the verifier sees umin >= 1. */
    volatile __u32 cl_slot = copy_len;
    __u32 cl = cl_slot;
    if (cl == 0)
      goto skip_payload_load;
    if (cl > QUIC_INSPECT_PAYLOAD_MAX)
      goto skip_payload_load;
    bpf_skb_load_bytes(ctx, q_off, evt->payload, cl);
  skip_payload_load:;

    bpf_ringbuf_submit(evt, 0);
  }

  /* See xdp_quic_initial_inspect: no flow_verdict_cache seed here, because
   * a deliberately-fragmented ClientHello needs every Initial in the burst
   * to reach userspace for reassembly.  Userspace writes the verdict once
   * inspection completes. */

pass_through:
  TC_RECORD_TIMING(meta->t0);
  TC_FLOW_CACHE_TAIL_CALL(ctx, &meta->flow, meta->pkt_len, 0, ACTION_PASS, TC_ACT_OK);
}

/*
 * tc_flow_cache_update — flow cache accounting program (egress).
 *
 * Registered in tc_dispatcher[TC_DISPATCHER_FLOW_CACHE_SLOT].
 * Tail-called by tc_policy_egress and tc_sni_inspect (via TC_FLOW_CACHE_TAIL_CALL)
 * with the final verdict and flow metadata stored in tc_pkt_scratch.
 *
 * Updates tc_flow_cache if enabled, then returns the stored verdict.
 * TC does not chain to FIB forwarding (ingress-only feature).
 */
SEC("tc")
int tc_flow_cache_update(struct __sk_buff *ctx) {
  __u32 zero = 0;
  struct tc_pkt_meta *meta = bpf_map_lookup_elem(&tc_pkt_scratch, &zero);
  if (!meta)
    return TC_ACT_OK;

  __u32 verdict = meta->fc_verdict;

  struct flow_cache_config *cfg =
      bpf_map_lookup_elem(&tc_flow_cache_config_map, &zero);
  if (cfg && cfg->enabled == FLOW_CACHE_ENABLED) {
    struct flow_cache_entry *fe = bpf_map_lookup_elem(&tc_flow_cache, &meta->flow);
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
      bpf_map_update_elem(&tc_flow_cache, &meta->flow, &new_fe, BPF_ANY);
    }
  }

  return verdict;
}

/*
 * TC ingress program: clones INSPECT-marked flows to Suricata.
 *
 * Only compiled when SURICATA_IPS is defined.  Without Suricata support the
 * ingress clone path is not needed.
 */
#ifdef SURICATA_IPS
SEC("tc")
int tc_policy_ingress(struct __sk_buff *ctx) {
  __u32 cfg_key = 0;
  struct inspect_config *cfg =
      bpf_map_lookup_elem(&tc_inspect_config, &cfg_key);
  if (!cfg || cfg->mode == INSPECT_MODE_DISABLED || cfg->mirror_ifindex == 0)
    return TC_ACT_OK;

  struct flow_key flow_key;
  int l4_off = tc_parse_packet(ctx, &flow_key);
  /* Non-IP traffic or genuine parse error — pass through unmodified */
  if (l4_off < 0 && l4_off != PARSE_NONFIRST_FRAG)
    return TC_ACT_OK;

  /* Build the (ifindex-less) flows_to_inspect key for the clone lookup */
  struct flow_inspect_key fi_key = {};
  flow_inspect_key_from_flow(&fi_key, &flow_key);

  /* Check if this flow should be cloned to Suricata */
  const __u64 *expiry = bpf_map_lookup_elem(&flows_to_inspect, &fi_key);
  if (!expiry)
    return TC_ACT_OK;

  /* Remove expired entries to keep the map tidy */
  __u64 now = bpf_ktime_get_ns();
  if (*expiry != 0 && now >= *expiry) {
    bpf_map_delete_elem(&flows_to_inspect, &fi_key);
    return TC_ACT_OK;
  }

  /* Clone the packet to pe-inspect0 (Suricata receives it on pe-inspect1).
   * BPF_F_INGRESS=0: the clone is sent as an egress packet out pe-inspect0;
   * the veth driver delivers it as ingress on the peer (pe-inspect1) where
   * Suricata's AF-packet socket is bound.
   * The original sk_buff is unmodified and continues to the application. */
  bpf_clone_redirect(ctx, cfg->mirror_ifindex, 0);

  return TC_ACT_OK;
}
#endif /* SURICATA_IPS */
