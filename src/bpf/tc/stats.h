/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Dufferin Software <support@dufferinsw.com> */

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

/*
 * Update per-L3-protocol statistics, bucketed by ethertype
 * (0=IPv4, 1=IPv6, 2=ARP, 3=MPLS, 4=Other).
 */
static __always_inline void tc_update_l3_proto_stats(__u16 eth_proto,
                                                     __u32 pkt_len) {
  __u32 l3_key = 4;
  if (eth_proto == ETH_P_IP)
    l3_key = 0;
  else if (eth_proto == ETH_P_IPV6)
    l3_key = 1;
  else if (eth_proto == ETH_P_ARP)
    l3_key = 2;
  else if (eth_proto == ETHERTYPE_MPLS || eth_proto == ETHERTYPE_MPLS_MC)
    l3_key = 3;
  struct proto_stats *l3ps = bpf_map_lookup_elem(&tc_per_l3_stats, &l3_key);
  if (l3ps) {
    l3ps->packets++;
    l3ps->bytes += pkt_len;
  }
}

/*
 * Update per-IP-protocol statistics, keyed by L4 protocol number
 * (e.g. TCP=6, UDP=17, ICMP=1).
 */
static __always_inline void tc_update_ip_proto_stats(__u32 protocol,
                                                     __u32 pkt_len) {
  struct proto_stats *ps = bpf_map_lookup_elem(&tc_per_proto_stats, &protocol);
  if (ps) {
    ps->packets++;
    ps->bytes += pkt_len;
  }
}
