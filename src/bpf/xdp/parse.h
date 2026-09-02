/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com> */

#pragma once

/*
 * Parse packet and extract 5-tuple flow key.
 * Returns L4 header byte offset from start of packet on success, -1 on error.
 */
static __always_inline int parse_packet(const struct xdp_md *ctx,
                                        struct flow_key *key, int l3_off,
                                        __u16 eth_proto) {
  void *data = (void *)(long)ctx->data;
  const void *data_end = (void *)(long)ctx->data_end;
  __builtin_memset(key, 0, sizeof(*key));
  /* Use data (void *) not ctx->data (__u32): loading ctx->data gives a pkt()
   * register and (ctx->data + l3_off) forces a <<= 32 zero-extension that the
   * BPF verifier rejects on packet pointers. */
  return parse_l3l4(data, data_end, l3_off, eth_proto, key);
}

/*
 * Extract real ethertype from packet, handling VLAN tags
 * Returns the inner protocol type (after stripping VLAN tags)
 */
static __always_inline int get_ethertype(void *data, const void *data_end,
                                         __u16 *eth_proto) {
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return 0;

  *eth_proto = bpf_ntohs(eth->h_proto);
  __u32 off = sizeof(struct ethhdr); /* 14 */

  /* Handle VLAN tags (single or QinQ) */
  if (*eth_proto == ETH_P_8021Q || *eth_proto == ETH_P_8021AD) {
    struct {
      __be16 tci;
      __be16 inner_proto;
    } *vlan = (void *)((__u8 *)data + off);

    if ((void *)(vlan + 1) > data_end)
      return 0;

    *eth_proto = bpf_ntohs(vlan->inner_proto);
    off += sizeof(*vlan); /* 18 */

    /* Check for QinQ (double VLAN tag) */
    if (*eth_proto == ETH_P_8021Q) {
      vlan = (void *)((__u8 *)data + off);
      if ((void *)(vlan + 1) > data_end)
        return 0;
      *eth_proto = bpf_ntohs(vlan->inner_proto);
      off += sizeof(*vlan); /* 22 */
    }
  }

  return (__s32)off;
}

/*
 * Check if destination MAC is broadcast (ff:ff:ff:ff:ff:ff) or multicast (bit 0
 * of first byte set) Returns 1 for BUM traffic, 0 for unicast
 */
static __always_inline int is_bum_traffic(struct ethhdr *eth) {
  /* Bit 0 of the first octet is the multicast bit.  It is set for all
   * multicast addresses AND for broadcast (ff:ff:ff:ff:ff:ff), so a
   * single test covers both cases. */
  return eth->h_dest[0] & 0x01;
}
