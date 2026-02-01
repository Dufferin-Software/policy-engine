/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Dufferin Software <support@dufferinsw.com> */

#pragma once

/*
 * Parse packet and extract 5-tuple flow key.
 * Handles Ethernet framing (including single VLAN tag) then delegates L3/L4
 * parsing to the shared parse_l3l4() helper in policy_common.h.
 * Returns L4 header byte offset on success, -1 on error.
 */
static __always_inline int tc_parse_packet(const struct __sk_buff *ctx,
                                           struct flow_key *key) {
  void *data = (void *)(long)ctx->data;
  const void *data_end = (void *)(long)ctx->data_end;

  __builtin_memset(key, 0, sizeof(*key));

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return -1;

  __u16 eth_proto = bpf_ntohs(eth->h_proto);
  /* Track L3 offset as a plain scalar — pointer subtraction of pkt() registers
   * triggers <<= 32 which the BPF verifier rejects. */
  int l3_off = (__s32)sizeof(struct ethhdr); /* 14 */

  /* Handle VLAN tag */
  if (eth_proto == ETH_P_8021Q) {
    struct {
      __be16 tci;
      __be16 inner_proto;
    } *vlan = (void *)((__u8 *)data + l3_off);

    if ((void *)(vlan + 1) > data_end)
      return -1;

    eth_proto = bpf_ntohs(vlan->inner_proto);
    l3_off += (__s32)sizeof(*vlan); /* 18 */
  }

  return parse_l3l4(data, data_end, l3_off, eth_proto, key);
}
