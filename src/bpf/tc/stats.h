/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com> */

#pragma once

/*
 * Update per-rule statistics (egress)
 */
static __always_inline void tc_update_rule_stats(__u64 rule_id, __u32 pkt_len,
                                                 __u64 now_ns) {
  struct rule_stats *stats = bpf_map_lookup_elem(&tc_rule_stats, &rule_id);
  if (stats) {
    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, pkt_len);
    stats->last_seen_ns = now_ns;
  } else {
    struct rule_stats new_stats = {
        .packets = 1,
        .bytes = pkt_len,
        .last_seen_ns = now_ns,
    };
    bpf_map_update_elem(&tc_rule_stats, &rule_id, &new_stats, BPF_NOEXIST);
  }
}
