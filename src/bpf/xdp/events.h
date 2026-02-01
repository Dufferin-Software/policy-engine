/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Dufferin Software <support@dufferinsw.com> */

#pragma once

/*
 * Send event to userspace via ring buffer
 */
static __always_inline void emit_event(const struct xdp_md *ctx,
                                       struct flow_key *flow, __u64 rule_id,
                                       __u32 action, __u32 verdict, __u8 *sni,
                                       __u8 sni_len, __u64 now_ns) {
  struct policy_event *evt;

  evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
  if (!evt)
    return;

  evt->timestamp_ns = now_ns;
  evt->rule_id = rule_id;
  evt->action = action;
  evt->ifindex = ctx->ingress_ifindex;
  __builtin_memcpy(&evt->flow, flow, sizeof(*flow));
  evt->pkt_len = (ctx->data_end - ctx->data);
  evt->verdict = verdict;

  /* SNI is copied by the caller if needed; just initialize the length field */
  evt->sni_len = sni_len;
  /* If SNI pointer is not NULL, assume the caller has already populated
   * evt->sni before calling this function (to work around BPF verifier
   * limitations with variable-length memcpy). */

  bpf_ringbuf_submit(evt, 0);
}
