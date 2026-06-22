/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * XDP unicast Reverse Path Forwarding (uRPF) helper.
 *
 * xdp_urpf_check() is called early in xdp_policy_main — after the IP header has
 * been parsed but before the policy lookup — when uRPF is enabled on the
 * ingress interface.  It performs a reverse FIB lookup on the packet's *source*
 * address and decides whether the packet should be dropped as spoofed:
 *
 *   loose  — drop only when no route to the source exists via any interface.
 *   strict — drop unless the best route back to the source exits via the same
 *            interface the packet arrived on.
 *
 * uRPF is an ingress (XDP) feature only; the TC egress path never calls this.
 *
 * Performance: when uRPF is disabled on the interface (the common case) this is
 * a single hash-map lookup that misses or reads URPF_DISABLED and returns
 * immediately.  Only enabled interfaces pay for the bpf_fib_lookup().
 */

#pragma once

/*
 * xdp_urpf_check - reverse-path check for the packet's source address.
 *
 * @ctx:       XDP context
 * @gs:        Per-interface global_stats pointer (may be NULL — stats skipped)
 * @eth_proto: Ethertype after VLAN stripping (ETH_P_IP or ETH_P_IPV6)
 * @l3_off:    Byte offset from start of packet to the IP/IPv6 header
 * @pkt_len:   Total packet length (for the drop byte counter)
 *
 * Returns 1 if the packet FAILS the reverse-path check and must be dropped,
 * 0 to continue normal processing (uRPF disabled, check passed, non-IP, or a
 * malformed header that the normal path will handle).
 *
 * Inlined into xdp_policy_main at its single call site so the compiler can
 * reuse the data/data_end pointers and register state already established
 * there, avoiding a BPF-to-BPF call on the per-packet fast path.
 */

/*
 * uRPF exemptions.
 *
 * Reverse-path filtering is a *unicast* check: it is only meaningful for
 * packets that would be unicast-forwarded and that carry a routable unicast
 * source.  These helpers identify traffic that must bypass the check so uRPF
 * does not break neighbour discovery, address autoconfiguration, or the
 * local multicast/broadcast control plane.  They are __always_inline and run
 * only when uRPF is enabled on the interface, so they add nothing to the
 * disabled fast path.  Both src/dst pointers reference the (already
 * bounds-checked) L3 header, so the byte reads are in-bounds.
 *
 * Note: multicast/broadcast *sources* are deliberately NOT exempted — a packet
 * claiming such a source is a martian and dropping it is correct anti-spoofing.
 * Only the destination is checked for multicast/broadcast.
 */

/*
 * IPv6: exempt link-local source (fe80::/10) or multicast destination
 * (ff00::/8).  Covers NDP, SLAAC/DAD (the unspecified :: source is sent to a
 * solicited-node multicast address), MLD, and RS/RA.
 */
static __always_inline int urpf_exempt_v6(const __u8 *src16, const __u8 *dst16) {
  if (src16[0] == 0xfe && (src16[1] & 0xc0) == 0x80) /* fe80::/10 source */
    return 1;
  if (dst16[0] == 0xff) /* ff00::/8 multicast destination */
    return 1;
  return 0;
}

/*
 * IPv4: exempt the analogues of the IPv6 control/non-unicast cases.
 *   - 0.0.0.0 source            — DHCP/BOOTP client (DISCOVER/REQUEST) and
 *                                 other unspecified-source traffic.
 *   - 169.254.0.0/16 source     — RFC 3927 link-local (APIPA).
 *   - 255.255.255.255 dest      — limited broadcast (DHCP/BOOTP, local bcast).
 *   - 224.0.0.0/4 dest          — multicast; unicast RPF does not apply.
 * src4/dst4 reference the IPv4 header's network-order address fields, so the
 * byte indices are the network octets (src4[0] is the most-significant octet).
 */
static __always_inline int urpf_exempt_v4(const __u8 *src4, const __u8 *dst4) {
  if (src4[0] == 0 && src4[1] == 0 && src4[2] == 0 && src4[3] == 0)
    return 1; /* 0.0.0.0 source */
  if (src4[0] == 169 && src4[1] == 254)
    return 1; /* 169.254.0.0/16 source */
  if (dst4[0] == 255 && dst4[1] == 255 && dst4[2] == 255 && dst4[3] == 255)
    return 1; /* 255.255.255.255 destination */
  if ((dst4[0] & 0xf0) == 0xe0)
    return 1; /* 224.0.0.0/4 multicast destination */
  return 0;
}

static __always_inline int xdp_urpf_check(struct xdp_md *ctx,
                                          struct global_stats *gs,
                                          __u16 eth_proto,
                                          int l3_off,
                                          __u32 pkt_len) {
  __u32 key = ctx->ingress_ifindex;
  const struct fib_config *cfg = bpf_map_lookup_elem(&fib_config_map, &key);
  if (!cfg)
    return 0;
  __u32 mode = cfg->urpf_mode;
  if (mode != URPF_LOOSE && mode != URPF_STRICT)
    return 0;

  /*
   * Narrow l3_off for the verifier (see fib.h for the same idiom): the asm
   * barrier forces a real AND so the tnum is constrained before the packet
   * pointer arithmetic below.
   */
  {
    __u32 _safe = (__u32)l3_off;
    __asm__ volatile("" : "+r"(_safe));
    _safe &= 0x3fff;
    l3_off = (int)_safe;
  }

  struct bpf_fib_lookup fib_params = {};
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  /*
   * Set the ingress interface. For the full lookup (flags = 0) below this is
   * the input interface (flowi4_iif); bpf_fib_lookup() also uses it up front to
   * fetch the device for its forwarding check, so it must be a real ifindex —
   * a zero ifindex resolves to no device and the helper returns -ENODEV. On
   * success the helper overwrites this field with the egress interface used to
   * reach the source, which the strict check below compares against ingress.
   */
  fib_params.ifindex = ctx->ingress_ifindex;

  if (eth_proto == ETH_P_IP) {
    struct iphdr *iph = (struct iphdr *)((char *)data + l3_off);
    if ((void *)(iph + 1) > data_end)
      return 0; /* malformed — let the normal path classify it */

    /* Exempt DHCP/BOOTP, link-local, broadcast, and multicast (see helper). */
    if (urpf_exempt_v4((const __u8 *)&iph->saddr, (const __u8 *)&iph->daddr))
      return 0;

    /* Reverse lookup: ask the FIB for the route TO the packet's SOURCE. */
    fib_params.family = AF_INET;
    fib_params.ipv4_dst = iph->saddr;
  } else if (eth_proto == ETH_P_IPV6) {
    struct ipv6hdr *ip6h = (struct ipv6hdr *)((char *)data + l3_off);
    if ((void *)(ip6h + 1) > data_end)
      return 0;

    /* Exempt NDP / SLAAC-DAD / MLD / RS-RA control traffic (see helper). */
    if (urpf_exempt_v6((const __u8 *)&ip6h->saddr, (const __u8 *)&ip6h->daddr))
      return 0;

    fib_params.family = AF_INET6;
    __builtin_memcpy(fib_params.ipv6_dst, &ip6h->saddr, 16);
  } else {
    return 0; /* non-IP: uRPF not applicable */
  }

  /*
   * Full forwarding lookup (flags = 0): iif = ctx->ingress_ifindex, oif = 0
   * (unconstrained), honouring policy-routing (ip rule) tables. This asks "a
   * packet arriving on the ingress interface destined to the source — where
   * does it route?", i.e. the reverse path. The egress interface the helper
   * fills in feeds the strict check. NOTE: bpf_fib_lookup() requires forwarding
   * enabled on the ingress interface (its IN_DEV_FORWARD check is not gated by
   * the flag); a non-forwarding interface returns FWD_DISABLED, which we treat
   * as fail-open below.
   */
  int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

  /*
   * Classify the result. uRPF must DROP only when the FIB *positively* proves
   * there is no legitimate return path to the claimed source (genuine
   * spoofing). Anything that merely means "couldn't evaluate" — forwarding
   * disabled on the interface, a negative errno (e.g. -ENODEV), an unsupported
   * encap, fragmentation — fails OPEN: a routing/kernel quirk must never be
   * able to black-hole an interface and lock out management. This mirrors the
   * fail-open posture of the FIB-forward helper.
   */
  int pass;
  switch (rc) {
  case BPF_FIB_LKUP_RET_SUCCESS:
  case BPF_FIB_LKUP_RET_NO_NEIGH:
    /* A route to the source exists (NO_NEIGH = route found, ARP/NDP pending;
     * the egress ifindex is still filled in). uRPF validates the route, not
     * the neighbour. */
    pass = (mode == URPF_STRICT) ? (fib_params.ifindex == ctx->ingress_ifindex)
                                 : 1;
    break;
  case BPF_FIB_LKUP_RET_BLACKHOLE:
  case BPF_FIB_LKUP_RET_UNREACHABLE:
  case BPF_FIB_LKUP_RET_PROHIBIT:
  case BPF_FIB_LKUP_RET_NOT_FWDED:
    /* The FIB has no usable unicast path back to the source (or it resolves to
     * local delivery — a packet claiming one of our own addresses). Spoofed. */
    pass = 0;
    break;
  default:
    /* FWD_DISABLED, FRAG_NEEDED, UNSUPP_LWT, a negative errno, or any code we
     * don't recognise: the check could not be evaluated — fail open. */
    pass = 1;
    break;
  }

  if (pass)
    return 0;

  if (gs) {
    gs->urpf_drop_packets++;
    gs->urpf_drop_bytes += pkt_len;
  }
  return 1;
}
