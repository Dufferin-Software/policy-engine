/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com> */

#pragma once

/*
 * Update ethertype statistics
 */
static __always_inline void update_ethertype_stats(__u32 ifindex,
                                                   __u16 ethertype) {
  /* Create composite key: (ifindex << 16) | ethertype */
  __u32 key = ((ifindex % MAX_INTERFACES) << 16) | ethertype;

  /* PERCPU_HASH: each CPU has its own copy — no atomic needed */
  __u64 *count = bpf_map_lookup_elem(&ethertype_stats, &key);
  if (count) {
    (*count)++;
  } else {
    __u64 one = 1;
    bpf_map_update_elem(&ethertype_stats, &key, &one, BPF_NOEXIST);
  }
}

/*
 * Update non-IP sender statistics.
 * Called for every non-IP ethertype (ARP, LLDP, unknown L2, etc.).
 * Tracks packet counts per (ifindex, src_mac, ethertype) so userspace can
 * answer "which MAC is responsible for ethertype 0x8F83?".
 *
 * LRU_HASH: all CPUs share entries; use __sync_fetch_and_add for the counter.
 */
static __always_inline void update_nonip_sender_stats(__u32 ifindex,
                                                      const __u8 *src_mac,
                                                      __u16 ethertype) {
  struct nonip_sender_key key = {};
  key.ifindex = ifindex;
  __builtin_memcpy(key.mac, src_mac, 6);
  key.ethertype = ethertype;

  struct nonip_sender_stats *stats = bpf_map_lookup_elem(&nonip_senders, &key);
  if (stats) {
    __sync_fetch_and_add(&stats->packets, 1);
  } else {
    struct nonip_sender_stats new_stats = {.packets = 1};
    bpf_map_update_elem(&nonip_senders, &key, &new_stats, BPF_ANY);
  }
}

/*
 * Update per-rule statistics.
 * now_ns: caller-provided CLOCK_MONOTONIC timestamp — avoids an extra
 * bpf_ktime_get_ns() call on paths that already hold a recent timestamp.
 */
static __always_inline void update_rule_stats(__u64 rule_id, __u32 pkt_len,
                                              __u64 now_ns) {
  struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &rule_id);
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
    bpf_map_update_elem(&rule_stats, &rule_id, &new_stats, BPF_NOEXIST);
  }
}
