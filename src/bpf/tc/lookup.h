/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com> */

#pragma once

/*
 * Two-level LPM policy lookup for egress (TC) — mirrors lookup_policy_v2.
 * Returns the first dst_lpm_value with any L4-matching rule; the caller scans
 * all rules[] to handle non-SNI rules immediately and queue SNI rules.  MAC
 * matching is handled by the caller via the tc_mac_rules sidecar map.
 */
static __always_inline struct dst_lpm_value *
tc_lookup_policy_v2(struct flow_key *key, __u32 ifindex) {
  if (key->af == AF_INET) {
    __u32 src_qplen = 32;

    for (int s = 0; s < MAX_LPM_ANCESTORS; s++) {
      struct src_lpm_key_v4 sk = {
          .prefixlen = 32 + src_qplen, .ifindex = ifindex, .addr = key->saddr4};
      const struct src_lpm_value *sv = bpf_map_lookup_elem(&tc_src_lpm_v4, &sk);
      if (!sv)
        break;

      __u32 sv_prefixlen = sv->src_prefixlen;
      __u32 gid = sv->src_group_id;

      void *inner = bpf_map_lookup_elem(&tc_src_groups_v4, &gid);
      if (inner) {
        __u32 dst_qplen = 32;

        for (int d = 0; d < MAX_LPM_ANCESTORS; d++) {
          struct lpm_key_v4 dk = {.prefixlen = dst_qplen, .addr = key->daddr4};
          struct dst_lpm_value *dv = bpf_map_lookup_elem(inner, &dk);
          if (!dv)
            break;

          __u32 dv_prefixlen = dv->dst_prefixlen;
          __u8 cnt = dv->count;
          if (cnt > MAX_L4_RULES)
            cnt = MAX_L4_RULES;

          __u8 any_match = 0;
          for (int r = 0; r < MAX_L4_RULES; r++) {
            if (!any_match && (__u8)r < cnt && match_l4(key, &dv->rules[r]))
              any_match = 1;
          }
          if (any_match)
            return dv;

          if (dv_prefixlen == 0)
            break;
          dst_qplen = dv_prefixlen - 1;
        }
      }

      if (sv_prefixlen == 0)
        break;
      src_qplen = sv_prefixlen - 1;
    }

  } else if (key->af == AF_INET6) {
    __u32 src_qplen = 128;

    for (int s = 0; s < MAX_LPM_ANCESTORS; s++) {
      struct src_lpm_key_v6 sk = {.prefixlen = 32 + src_qplen,
                                  .ifindex = ifindex};
      __builtin_memcpy(sk.addr, key->saddr6, 16);
      const struct src_lpm_value *sv = bpf_map_lookup_elem(&tc_src_lpm_v6, &sk);
      if (!sv)
        break;

      __u32 sv_prefixlen = sv->src_prefixlen;
      __u32 gid = sv->src_group_id;

      void *inner = bpf_map_lookup_elem(&tc_src_groups_v6, &gid);
      if (inner) {
        __u32 dst_qplen = 128;

        for (int d = 0; d < MAX_LPM_ANCESTORS; d++) {
          struct lpm_key_v6 dk = {.prefixlen = dst_qplen};
          __builtin_memcpy(dk.addr, key->daddr6, 16);
          struct dst_lpm_value *dv = bpf_map_lookup_elem(inner, &dk);
          if (!dv)
            break;

          __u32 dv_prefixlen = dv->dst_prefixlen;
          __u8 cnt = dv->count;
          if (cnt > MAX_L4_RULES)
            cnt = MAX_L4_RULES;

          __u8 any_match = 0;
          for (int r = 0; r < MAX_L4_RULES; r++) {
            if (!any_match && (__u8)r < cnt && match_l4(key, &dv->rules[r]))
              any_match = 1;
          }
          if (any_match)
            return dv;

          if (dv_prefixlen == 0)
            break;
          dst_qplen = dv_prefixlen - 1;
        }
      }

      if (sv_prefixlen == 0)
        break;
      src_qplen = sv_prefixlen - 1;
    }
  }

  return NULL;
}
