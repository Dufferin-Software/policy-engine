/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * XDP FIB forwarding helper.
 *
 * xdp_fib_forward() is called at XDP_PASS return sites when FIB forwarding is
 * enabled.  It performs a kernel FIB + neighbour lookup via bpf_fib_lookup(),
 * rewrites the Ethernet src/dst MACs, decrements TTL/hop-limit, and redirects
 * the packet to the next-hop outgoing interface.
 *
 * Fail-open design: any failure (unresolved neighbour, no route, TTL=1,
 * fragmentation needed, unsupported ethertype, …) falls back to XDP_PASS so
 * the kernel routing stack handles the packet normally.
 */

#pragma once

/*
 * xdp_fib_forward - attempt FIB lookup and L2 rewrite, then redirect.
 *
 * @ctx:       XDP context
 * @gs:        Per-interface global_stats pointer (may be NULL — stats skipped)
 * @eth_proto: Ethertype after VLAN stripping (ETH_P_IP or ETH_P_IPV6)
 * @l3_off:    Byte offset from start of packet to the IP/IPv6 header
 * @pkt_len:   Total packet length (ctx->data_end - ctx->data)
 *
 * Returns XDP_REDIRECT on success, XDP_PASS on any failure.
 *
 * The caller must have already parsed and validated the Ethernet + L3 headers
 * (eth_proto and l3_off come from get_ethertype / parse_packet).
 *
 * After bpf_fib_lookup() the packet data/data_end pointers are re-read from
 * ctx to refresh the verifier's bounds (some kernel versions invalidate prior
 * proofs after certain helpers).
 */
/*
 * xdp_fib_forward is a BPF subprogram (not inlined) so it is verified once
 * and called from multiple sites without multiplying the verifier instruction
 * count.  __noinline / __attribute__((noinline)) triggers BPF-to-BPF call
 * semantics; the verifier checks the subprogram independently.
 */
static __attribute__((noinline)) int xdp_fib_forward(struct xdp_md *ctx,
                                                     struct global_stats *gs,
                                                     __u16 eth_proto,
                                                     int l3_off,
                                                     __u32 pkt_len) {
  struct bpf_fib_lookup fib_params = {};
  int rc;

  /*
   * When l3_off is loaded from a percpu scratch map (e.g. in xdp_sni_inspect),
   * the BPF verifier sees it as an unconstrained u16 scalar (var_off=0xffff).
   * The asm barrier prevents the compiler from optimising away the AND, making
   * it a real instruction so the verifier narrows the tnum to (0x0; 0x3fff)
   * before the packet pointer arithmetic below.
   */
  {
    __u32 _safe = (__u32)l3_off;
    __asm__ volatile("" : "+r"(_safe));
    _safe &= 0x3fff;
    l3_off = (int)_safe;
  }

  if (eth_proto == ETH_P_IP) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *iph = (struct iphdr *)((char *)data + l3_off);
    if ((void *)(iph + 1) > data_end)
      goto fallback;
    /* TTL <= 1: must let kernel send ICMP TTL Exceeded */
    if (iph->ttl <= 1)
      goto fallback;

    fib_params.family = AF_INET;
    fib_params.tos = iph->tos;
    fib_params.l4_protocol = iph->protocol;
    fib_params.tot_len = bpf_ntohs(iph->tot_len);
    fib_params.ipv4_src = iph->saddr;
    fib_params.ipv4_dst = iph->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

  } else if (eth_proto == ETH_P_IPV6) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ip6h = (struct ipv6hdr *)((char *)data + l3_off);
    if ((void *)(ip6h + 1) > data_end)
      goto fallback;
    /* hop_limit <= 1: must let kernel send ICMPv6 Time Exceeded */
    if (ip6h->hop_limit <= 1)
      goto fallback;

    fib_params.family = AF_INET6;
    fib_params.flowinfo = 0; /* flow label unused for basic FIB lookup */
    fib_params.l4_protocol = ip6h->nexthdr;
    fib_params.tot_len = bpf_ntohs(ip6h->payload_len);
    __builtin_memcpy(fib_params.ipv6_src, &ip6h->saddr, 16);
    __builtin_memcpy(fib_params.ipv6_dst, &ip6h->daddr, 16);
    fib_params.ifindex = ctx->ingress_ifindex;

  } else {
    /* Non-IP traffic: not forwarded via FIB */
    return XDP_PASS;
  }

  rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
  if (rc != BPF_FIB_LKUP_RET_SUCCESS)
    goto fallback;

  /* Re-read data/data_end after the helper call to refresh verifier bounds */
  {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Rewrite Ethernet src/dst MACs */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
      goto fallback;
    __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

    if (eth_proto == ETH_P_IP) {
      struct iphdr *iph = (struct iphdr *)((char *)data + l3_off);
      if ((void *)(iph + 1) > data_end)
        goto fallback;
      /* Decrement TTL and update checksum incrementally.
       *
       * The 16-bit word at offset 8-9 of the IP header (TTL|Protocol)
       * decreases by 0x0100 (NBO), so the checksum must increase by 0x0100
       * (NBO) with ones'-complement carry handling.
       *
       * On a little-endian host bpf_htons(0x0100) = 0x0001, which is exactly
       * +1 applied to the LE representation of the NBO checksum field — the
       * same formula used by the Linux kernel's ip_decrease_ttl().
       */
      iph->ttl--;
      __u32 c = (__u32)iph->check + (__u32)bpf_htons(0x0100);
      iph->check = (__sum16)(c + (c >= 0xFFFF));

    } else { /* ETH_P_IPV6 */
      struct ipv6hdr *ip6h = (struct ipv6hdr *)((char *)data + l3_off);
      if ((void *)(ip6h + 1) > data_end)
        goto fallback;
      /* Decrement hop limit; IPv6 has no header checksum */
      ip6h->hop_limit--;
    }
  }

  if (gs) {
    gs->fib_forwarded_packets++;
    gs->fib_forwarded_bytes += pkt_len;
  }
  return bpf_redirect(fib_params.ifindex, 0);

fallback:
  if (gs)
    gs->fib_fallback_packets++;
  return XDP_PASS;
}
