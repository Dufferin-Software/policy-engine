/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Dufferin Software <support@dufferinsw.com> */

#pragma once

#ifdef SURICATA_IPS
/*
 * ACTION_INSPECT body, outlined from process_rule_actions as two flat
 * __noinline helpers.
 *
 * Outlined for two reasons: (a) the fi_key / fv_key / pass_v stack buffers
 * otherwise land in xdp_policy_main's frame (via the unrolled action loop),
 * and main's frame plus its deepest callee must fit the 512-byte combined
 * stack limit; (b) the inspect-config branches fork verifier states that
 * re-converge at the call boundary instead of being carried through the rest
 * of the rule loop.  Two sibling helpers rather than one (or a nested chain)
 * so no single frame stacked on main holds all three structs at once.
 * INSPECT is off the hot path (first packet of a flow only), so the extra
 * BPF-to-BPF calls are irrelevant.
 *
 * xdp_mark_flow_for_inspect marks the flow for TC ingress cloning to
 * Suricata.  flows_to_inspect is keyed by the ifindex-less flow_inspect_key
 * (shared with the TC skeleton).  TC ingress reads flows_to_inspect and
 * calls bpf_clone_redirect to mirror each packet on this flow to pe-inspect0
 * while the original continues to the application.  Suricata receives the
 * full TCP stream on pe-inspect1 (the veth peer) and fires alerts via EVE
 * JSON.  The EveConsumer writes DROP verdicts to flow_verdict_cache; the
 * next packet on this flow is then dropped at the XDP verdict-cache check.
 *
 * Inspection requires both the node-global mode (inspect_config) and the
 * per-interface enable flag (fib_config_map[ingress ifindex].inspect_enabled)
 * — packets arriving on interfaces without the flag are never marked, so
 * their flows never reach Suricata.  Both lookups live in this cold outlined
 * helper, off the per-packet hot path.
 *
 * Returns 1 if inspection is enabled (caller must then also write the
 * temporary PASS verdict via xdp_write_inspect_pass_verdict), 0 if disabled.
 */
static __noinline int xdp_mark_flow_for_inspect(struct global_stats *gs,
                                                const struct flow_key *flow_key,
                                                __u64 now_ns, __u32 ifindex) {
  __u32 cfg_key = 0;
  const struct inspect_config *cfg =
      bpf_map_lookup_elem(&inspect_config, &cfg_key);
  if (!cfg || cfg->mode == INSPECT_MODE_DISABLED)
    return 0;

  const struct fib_config *fc = fib_config_lookup(&fib_config_map, ifindex);
  if (!fc || fc->inspect_enabled != INSPECT_IF_ENABLED)
    return 0;

  if (gs)
    gs->inspect_redirects++;

  struct flow_inspect_key fi_key = {};
  flow_inspect_key_from_flow(&fi_key, flow_key);
  __u64 expiry = now_ns + INSPECT_CLONE_TTL_NS;
  bpf_map_update_elem(&flows_to_inspect, &fi_key, &expiry, BPF_ANY);
  return 1;
}

/*
 * Write a temporary PASS verdict so the EveConsumer can overwrite it
 * with DROP when Suricata alerts.  BPF_NOEXIST prevents overwriting an
 * existing DROP verdict if an alert arrived between packets.
 * Uses now_ns (CLOCK_MONOTONIC) — userspace must also use
 * CLOCK_MONOTONIC when writing or comparing expires_ns.
 */
static __noinline void
xdp_write_inspect_pass_verdict(const struct flow_key *flow_key, __u32 ifindex,
                               __u64 now_ns) {
  struct flow_verdict_key fv_key = {};
  flow_verdict_key_from_flow(&fv_key, flow_key, ifindex);

  struct flow_verdict pass_v = {};
  pass_v.action = ACTION_PASS;
  pass_v.expires_ns = now_ns + INSPECT_PASS_VERDICT_TTL_NS;
  bpf_map_update_elem(&flow_verdict_cache, &fv_key, &pass_v, BPF_NOEXIST);
}
#endif /* SURICATA_IPS */

/*
 * Process all actions for a matched rule in priority order
 * Returns the final XDP verdict (drop or pass).
 *
 * *cacheable is cleared to 0 if this rule carries any action that must run on
 * every packet (LOG — per-packet emission / rate-limit windows; INSPECT — IPS
 * mirroring with its own short verdict TTL; TAIL_CALL).  The caller only seeds
 * the policy verdict cache when *cacheable is still set after all matched
 * rules, so pure PASS/DROP flows get the fast path while LOG/INSPECT flows keep
 * re-evaluating.  Caller initialises *cacheable = 1.
 */
static __always_inline __u32 process_rule_actions(
    struct xdp_md *ctx, struct global_stats *gs, struct l4_rule *policy,
    struct flow_key *flow_key, __u64 now_ns, __u8 *cacheable) {
  __u32 final_verdict = XDP_PASS;
  __u32 should_log = 0;
  __u8 stop_actions = 0;

/* Process actions in priority order */
#pragma unroll
  for (__u8 i = 0; i < MAX_ACTIONS_PER_RULE; i++) {
    if (stop_actions || i >= policy->num_actions)
      break;

    __u32 action = policy->actions[i].action;

    switch (action) {
    case ACTION_DROP:
      final_verdict = XDP_DROP;
      stop_actions = 1; /* DROP stops further action processing */
      break;
    case ACTION_LOG: {
      /* A LOG rule must be re-evaluated per packet (event emission and
       * rate-limit windows), so its flow cannot be served from the cache. */
      *cacheable = 0;
      __u64 param = policy->actions[i].param; /* rate-limit interval in ns */
      if (param > 0) {
        /* Rate limiting via rule_stats.last_log_ns (no extra map needed).
         * update_rule_stats() is always called before process_rule_actions()
         * so the entry exists by the time we reach here.
         * Use the caller-provided now_ns to avoid an extra clock read.
         * Use an atomic CAS to update last_log_ns so that concurrent CPUs
         * processing a burst of packets only emit one event per window. */
        struct rule_stats *rs =
            bpf_map_lookup_elem(&rule_stats, &policy->rule_id);
        if (rs) {
          __u64 old_ts = rs->last_log_ns;
          if (now_ns - old_ts < param)
            break; /* still within rate-limit window */
          /* Only proceed if we win the race — CAS old→now_ns */
          if (!__sync_bool_compare_and_swap(&rs->last_log_ns, old_ts, now_ns))
            break; /* another CPU already claimed this window */
        }
      }
      should_log = 1;
      break;
    }
    case ACTION_PASS:
      /* Pass doesn't override a drop decision */
      if (final_verdict != XDP_DROP)
        final_verdict = XDP_PASS;
      break;
    case ACTION_TAIL_CALL:
      *cacheable = 0;
      if (policy->tail_call_idx < MAX_DISPATCHER_PROGS) {
        if (gs)
          gs->tail_calls++;

        bpf_tail_call(ctx, &xdp_dispatcher, policy->tail_call_idx);
      }
      break;
#ifdef SURICATA_IPS
    case ACTION_INSPECT: {
      /* INSPECT manages its own short PASS verdict (INSPECT_PASS_VERDICT_TTL_NS)
       * and is overwritten with a DROP by the EVE consumer; never seed a
       * non-expiring policy verdict over it. */
      *cacheable = 0;
      if (xdp_mark_flow_for_inspect(gs, flow_key, now_ns,
                                    ctx->ingress_ifindex))
        xdp_write_inspect_pass_verdict(flow_key, ctx->ingress_ifindex, now_ns);
      if (final_verdict != XDP_DROP)
        final_verdict = XDP_PASS;
      break;
    }
#endif /* SURICATA_IPS */
    }
  }

  /* Emit event if logging was requested */
  if (should_log) {
    /* evt->verdict is decoded as a PolicyAction enum in userspace, NOT an
     * XDP return code.  XDP_PASS (2) numerically collides with
     * PolicyAction::Log (2), so passing final_verdict directly would render
     * PASSes as "LOG" in the event stream.  Translate to the action enum. */
    __u32 final_action =
        (final_verdict == XDP_DROP) ? ACTION_DROP : ACTION_PASS;
    emit_event(ctx, flow_key, policy->rule_id, ACTION_LOG, final_action, NULL,
               0, now_ns);
  }

  /* Update action stats once here — single accounting location for all matched
   * rules.  inspect_redirects is already incremented in the INSPECT case above;
   * only pass/drop needs to be recorded here. */
  if (gs) {
    if (final_verdict == XDP_DROP)
      gs->policy_drops++;
    else
      gs->policy_pass++;
  }

  return final_verdict;
}
