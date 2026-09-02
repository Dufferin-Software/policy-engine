/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com> */

#pragma once

/*
 * Process all actions for a matched rule in priority order
 * Returns the final TC verdict (TC_ACT_SHOT or TC_ACT_OK).
 *
 * *cacheable is cleared to 0 if this rule carries any action that must run on
 * every packet (LOG / INSPECT / TAIL_CALL); the caller only seeds the
 * policy verdict cache when *cacheable survives all matched rules.  Mirrors
 * process_rule_actions in src/bpf/xdp/actions.h.  Caller initialises it to 1.
 */
static __always_inline int tc_process_rule_actions(
    struct __sk_buff *ctx, struct global_stats *gs, struct l4_rule *policy,
    struct flow_key *flow_key, __u64 now_ns, __u8 *cacheable) {
  int final_verdict = TC_ACT_OK;
  __u32 should_log = 0;
  __u8 stop_actions = 0;

#pragma unroll
  for (__u8 i = 0; i < MAX_ACTIONS_PER_RULE; i++) {
    if (stop_actions || i >= policy->num_actions)
      break;

    __u32 action = policy->actions[i].action;

    switch (action) {
    case ACTION_DROP:
      final_verdict = TC_ACT_SHOT;
      stop_actions = 1; /* DROP stops further action processing */
      break;
    case ACTION_LOG: {
      /* LOG rules must re-evaluate per packet — not cacheable. */
      *cacheable = 0;
      __u64 param = policy->actions[i].param; /* rate-limit interval in ns */
      if (param > 0) {
        /* Rate limiting via tc_rule_stats.last_log_ns (no extra map needed).
         * Use the caller-provided now_ns to avoid an extra clock read.
         * Use an atomic CAS to update last_log_ns so that concurrent CPUs
         * processing a burst of packets only emit one event per window. */
        struct rule_stats *rs =
            bpf_map_lookup_elem(&tc_rule_stats, &policy->rule_id);
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
      if (final_verdict != TC_ACT_SHOT)
        final_verdict = TC_ACT_OK;
      break;
    case ACTION_TAIL_CALL:
      *cacheable = 0;
      if (policy->tail_call_idx < MAX_DISPATCHER_PROGS) {
        if (gs)
          gs->tail_calls++;

        bpf_tail_call(ctx, &tc_dispatcher, policy->tail_call_idx);
      }
      break;
#ifdef SURICATA_IPS
    case ACTION_INSPECT: {
      /* INSPECT manages its own verdict lifecycle (IPS) — not policy-cacheable. */
      *cacheable = 0;
      /* Egress INSPECT: mirror this flow to Suricata.
       *
       * The egress direction is client→server.  flows_to_inspect stores keys
       * in the ingress (server→client) direction so that tc_policy_ingress can
       * clone server→client responses.  We add the REVERSED key here.
       *
       * We also clone the current packet directly so Suricata sees the TLS
       * ClientHello (and any other first egress packets) immediately.
       *
       * tc_policy_egress already checks flows_to_inspect with the reversed key
       * before the policy lookup, so subsequent egress packets are also cloned
       * automatically without triggering the policy engine again.
       *
       * The inspect config is looked up here rather than hoisted by the
       * caller: a map-value-or-NULL pointer held live across the main
       * program's LPM walk forks verifier states and blows the processed-insn
       * budget (see the note in tc_policy_egress).  INSPECT rules are rare,
       * so the extra lookup is off the hot path. */
      __u32 icfg_key = 0;
      const struct inspect_config *icfg =
          bpf_map_lookup_elem(&tc_inspect_config, &icfg_key);
      if (!icfg || icfg->mode == INSPECT_MODE_DISABLED)
        break;

      /* Per-interface gate: only mark flows on interfaces with inspection
       * enabled (fib_config_map is the XDP-owned per-interface config,
       * shared into this skeleton via pin reuse). */
      const struct fib_config *fc =
          fib_config_lookup(&fib_config_map, ctx->ifindex);
      if (!fc || fc->inspect_enabled != INSPECT_IF_ENABLED)
        break;

      if (gs)
        gs->inspect_redirects++;

      /* Reversed (server→client) ifindex-less key for flows_to_inspect */
      struct flow_inspect_key fi_key = {};
      flow_inspect_key_from_flow_reversed(&fi_key, flow_key);

      /* Single clock read for the expiry timestamp */
      __u64 expiry = bpf_ktime_get_ns() + INSPECT_CLONE_TTL_NS;
      bpf_map_update_elem(&flows_to_inspect, &fi_key, &expiry, BPF_ANY);

      /* Clone this egress packet to the mirror interface now */
      if (icfg->mirror_ifindex != 0)
        bpf_clone_redirect(ctx, icfg->mirror_ifindex, 0);

      break;
    }
#endif /* SURICATA_IPS */
    }
  }

  if (should_log) {
    /* evt->verdict is decoded as a PolicyAction enum in userspace, NOT a
     * TC return code.  TC_ACT_SHOT (2) numerically collides with
     * PolicyAction::Log (2), so passing final_verdict directly would render
     * DROPs as "LOG" in the event stream.  Translate to the action enum. */
    __u32 final_action =
        (final_verdict == TC_ACT_SHOT) ? ACTION_DROP : ACTION_PASS;
    tc_emit_event(ctx, flow_key, policy->rule_id, ACTION_LOG, final_action,
                  NULL, 0, now_ns);
  }

  /* Update action stats once here — single accounting location for all matched
   * rules.  inspect_redirects is already incremented in the INSPECT case above;
   * only pass/drop needs to be recorded here. */
  update_action_stats(gs, final_verdict == TC_ACT_SHOT ? ACTION_DROP
                                                       : ACTION_PASS);

  return final_verdict;
}
