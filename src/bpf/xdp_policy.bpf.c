// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * XDP Policy Engine - Main XDP program with LPM-based policy matching
 * 
 * Supports CIDR prefix matching using BPF LPM trie maps for source IP.
 * More specific prefixes (longer prefix length) are matched first.
 */

#include "include/bpf_helpers.h"
#include "include/policy_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * LPM trie for IPv4 source address matching
 * Key: struct lpm_key_v4 (prefixlen + addr)
 * Value: struct lpm_policy_entry (includes dest match criteria + policy)
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, struct lpm_key_v4);
    __type(value, struct lpm_policy_entry);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_rules_v4 SEC(".maps");

/*
 * LPM trie for IPv6 source address matching
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, struct lpm_key_v6);
    __type(value, struct lpm_policy_entry);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_rules_v6 SEC(".maps");

/* 
 * Policy rules map - keyed by 5-tuple flow key (exact match fallback)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, struct flow_key);
    __type(value, struct policy_value);
} policy_rules SEC(".maps");

/*
 * Per-rule statistics map
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POLICY_RULES);
    __type(key, __u64);  /* rule_id */
    __type(value, struct rule_stats);
} rule_stats SEC(".maps");

/*
 * Global per-CPU statistics
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_INTERFACES);
    __type(key, __u32);
    __type(value, struct global_stats);
} global_stats SEC(".maps");

/*
 * Ethertype statistics map (per-interface, tracks counts per ethertype)
 * Key: (ifindex << 16) | ethertype
 * Value: packet count
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_INTERFACES * MAX_ETHERTYPE_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} ethertype_stats SEC(".maps");

/*
 * Tail call program array for dispatcher
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_DISPATCHER_PROGS);
    __type(key, __u32);
    __type(value, __u32);
} xdp_dispatcher SEC(".maps");

/*
 * Ring buffer for events
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

/*
 * Scratch space for per-packet metadata (used by tail call chain)
 */
struct pkt_meta {
    struct flow_key flow;
    __u32 pkt_len;
    __u64 matched_rule_id;
    __u32 action;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_meta);
} pkt_scratch SEC(".maps");

/*
 * Default action when no rule matches (configurable from userspace)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} default_action SEC(".maps");

/* 
 * Parse packet and extract 5-tuple flow key
 * Returns 0 on success, -1 on parse error
 */
static __always_inline int parse_packet(struct xdp_md *ctx, struct flow_key *key)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* Initialize key to zero */
    __builtin_memset(key, 0, sizeof(*key));
    
    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr = (void *)(eth + 1);
    
    /* Handle VLAN tags */
    if (eth_proto == ETH_P_8021Q) {
        struct {
            __be16 tci;
            __be16 inner_proto;
        } *vlan = l3_hdr;
        
        if ((void *)(vlan + 1) > data_end)
            return -1;
        
        eth_proto = bpf_ntohs(vlan->inner_proto);
        l3_hdr = (void *)(vlan + 1);
    }
    
    /* Parse L3 header */
    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph = l3_hdr;
        if ((void *)(iph + 1) > data_end)
            return -1;
        
        key->af = AF_INET;
        key->saddr4 = iph->saddr;
        key->daddr4 = iph->daddr;
        key->protocol = iph->protocol;
        
        /* Calculate L4 header offset */
        __u32 iph_len = iph->ihl * 4;
        if (iph_len < sizeof(*iph))
            return -1;
        
        void *l4_hdr = (void *)iph + iph_len;
        
        /* Parse L4 header for ports */
        if (key->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = l4_hdr;
            if ((void *)(tcph + 1) > data_end)
                return -1;
            key->sport = bpf_ntohs(tcph->source);
            key->dport = bpf_ntohs(tcph->dest);
        } else if (key->protocol == IPPROTO_UDP) {
            struct udphdr *udph = l4_hdr;
            if ((void *)(udph + 1) > data_end)
                return -1;
            key->sport = bpf_ntohs(udph->source);
            key->dport = bpf_ntohs(udph->dest);
        } else if (key->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmph = l4_hdr;
            if ((void *)(icmph + 1) > data_end)
                return -1;
            /* Use ICMP type/code as pseudo ports */
            key->sport = icmph->type;
            key->dport = icmph->code;
        }
        /* Other protocols: ports remain 0 */
        
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = l3_hdr;
        if ((void *)(ip6h + 1) > data_end)
            return -1;
        
        key->af = AF_INET6;
        __builtin_memcpy(key->saddr6, &ip6h->saddr, 16);
        __builtin_memcpy(key->daddr6, &ip6h->daddr, 16);
        key->protocol = ip6h->nexthdr;
        
        void *l4_hdr = (void *)(ip6h + 1);
        
        /* TODO: Handle extension headers properly */
        
        if (key->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = l4_hdr;
            if ((void *)(tcph + 1) > data_end)
                return -1;
            key->sport = bpf_ntohs(tcph->source);
            key->dport = bpf_ntohs(tcph->dest);
        } else if (key->protocol == IPPROTO_UDP) {
            struct udphdr *udph = l4_hdr;
            if ((void *)(udph + 1) > data_end)
                return -1;
            key->sport = bpf_ntohs(udph->source);
            key->dport = bpf_ntohs(udph->dest);
        } else if (key->protocol == IPPROTO_ICMPV6) {
            struct icmp6hdr *icmp6h = l4_hdr;
            if ((void *)(icmp6h + 1) > data_end)
                return -1;
            key->sport = icmp6h->icmp6_type;
            key->dport = icmp6h->icmp6_code;
        }
    } else {
        /* Non-IP traffic - pass through for now */
        return -1;
    }
    
    return 0;
}

/*
 * Update ethertype statistics
 */
static __always_inline void update_ethertype_stats(__u32 ifindex, __u16 ethertype)
{
    /* Create composite key: (ifindex << 16) | ethertype */
    __u32 key = ((ifindex % MAX_INTERFACES) << 16) | ethertype;
    
    __u64 *count = bpf_map_lookup_elem(&ethertype_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        /* Create new entry */
        __u64 one = 1;
        bpf_map_update_elem(&ethertype_stats, &key, &one, BPF_NOEXIST);
    }
}

/*
 * Update per-rule statistics
 */
static __always_inline void update_rule_stats(__u64 rule_id, __u32 pkt_len)
{
    struct rule_stats *stats = bpf_map_lookup_elem(&rule_stats, &rule_id);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
        stats->last_seen_ns = bpf_ktime_get_ns();
    } else {
        /* Create new stats entry */
        struct rule_stats new_stats = {
            .packets = 1,
            .bytes = pkt_len,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&rule_stats, &rule_id, &new_stats, BPF_NOEXIST);
    }
}

/*
 * Update global statistics
 */
static __always_inline void update_global_stats(__u32 ifindex, __u32 pkt_len, 
                                                 __u32 action)
{
    __u32 key = ifindex % MAX_INTERFACES;
    struct global_stats *stats = bpf_map_lookup_elem(&global_stats, &key);
    if (!stats)
        return;
    
    stats->rx_packets++;
    stats->rx_bytes += pkt_len;
    
    switch (action) {
    case ACTION_PASS:
    case ACTION_LOG:
        stats->policy_pass++;
        break;
    case ACTION_DROP:
        stats->policy_drops++;
        break;
    }
}

/*
 * Send event to userspace via ring buffer
 */
static __always_inline void emit_event(struct xdp_md *ctx,
                                       struct flow_key *flow,
                                       __u64 rule_id,
                                       __u32 action,
                                       __u32 verdict)
{
    struct policy_event *evt;
    
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return;
    
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->rule_id = rule_id;
    evt->action = action;
    evt->ifindex = ctx->ingress_ifindex;
    __builtin_memcpy(&evt->flow, flow, sizeof(*flow));
    evt->pkt_len = (ctx->data_end - ctx->data);
    evt->verdict = verdict;
    
    bpf_ringbuf_submit(evt, 0);
}

/*
 * Check if a destination address matches the policy entry
 * Returns 1 if match, 0 if no match
 */
static __always_inline int match_dest_addr(struct flow_key *pkt, 
                                            struct lpm_policy_entry *entry)
{
    if (entry->af == AF_INET) {
        /* For IPv4: if dst_prefixlen is 0, match any destination */
        if (entry->dst_prefixlen == 0)
            return 1;
        
        /* Apply mask and compare */
        __u32 mask = entry->dst_prefixlen == 32 ? 0xFFFFFFFF : 
                     ~((__u32)0xFFFFFFFF >> entry->dst_prefixlen);
        mask = bpf_htonl(mask);
        
        return (pkt->daddr4 & mask) == (entry->daddr4 & mask);
    } else {
        /* For IPv6: if dst_prefixlen is 0, match any destination */
        if (entry->dst_prefixlen == 0)
            return 1;
        
        /* Compare each 32-bit word, applying mask to the last partial word */
        __u32 full_words = entry->dst_prefixlen / 32;
        __u32 remaining_bits = entry->dst_prefixlen % 32;
        
        #pragma unroll
        for (__u32 i = 0; i < 4; i++) {
            if (i < full_words) {
                if (pkt->daddr6[i] != entry->daddr6[i])
                    return 0;
            } else if (i == full_words && remaining_bits > 0) {
                __u32 mask = ~((__u32)0xFFFFFFFF >> remaining_bits);
                mask = bpf_htonl(mask);
                if ((pkt->daddr6[i] & mask) != (entry->daddr6[i] & mask))
                    return 0;
            }
            /* Words beyond the prefix don't need to match */
        }
        return 1;
    }
}

/*
 * Check if ports and protocol match the policy entry
 * Returns 1 if match, 0 if no match
 */
static __always_inline int match_ports_proto(struct flow_key *pkt,
                                              struct lpm_policy_entry *entry)
{
    /* Protocol: 0 means any */
    if (entry->protocol != 0 && entry->protocol != pkt->protocol)
        return 0;
    
    /* Source port: 0 means any */
    if (entry->sport != 0 && entry->sport != pkt->sport)
        return 0;
    
    /* Destination port: 0 means any */
    if (entry->dport != 0 && entry->dport != pkt->dport)
        return 0;
    
    return 1;
}

/*
 * Copy policy from lpm_policy_entry to policy_value
 * (Used to return a consistent type from lookup)
 */
static __always_inline void copy_policy_from_lpm(struct policy_value *dst,
                                                  struct lpm_policy_entry *src)
{
    dst->flags = src->flags;
    dst->tail_call_idx = src->tail_call_idx;
    dst->rule_id = src->rule_id;
    dst->priority = src->priority;
    dst->num_actions = src->num_actions;
    dst->_pad1 = 0;
    dst->_pad2 = 0;
    
    #pragma unroll
    for (int i = 0; i < MAX_ACTIONS_PER_RULE; i++) {
        dst->actions[i] = src->actions[i];
    }
}

/*
 * Scratch space for policy value when returning from LPM lookup
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_value);
} policy_scratch SEC(".maps");

/*
 * Lookup policy for a flow using LPM matching on source IP
 * Performs longest prefix match on source, then verifies destination/ports
 */
static __always_inline struct policy_value *lookup_policy(struct flow_key *key)
{
    struct policy_value *val;
    struct lpm_policy_entry *lpm_entry = NULL;
    __u32 zero = 0;
    
    /* Try LPM lookup based on address family */
    if (key->af == AF_INET) {
        struct lpm_key_v4 lpm_key = {
            .prefixlen = 32,  /* Full address for lookup - LPM will match longest */
            .addr = key->saddr4,
        };
        lpm_entry = bpf_map_lookup_elem(&lpm_rules_v4, &lpm_key);
    } else if (key->af == AF_INET6) {
        struct lpm_key_v6 lpm_key = {
            .prefixlen = 128,  /* Full address for lookup */
        };
        __builtin_memcpy(lpm_key.addr, key->saddr6, 16);
        lpm_entry = bpf_map_lookup_elem(&lpm_rules_v6, &lpm_key);
    }
    
    /* Check if LPM entry matches additional criteria */
    if (lpm_entry && (lpm_entry->flags & POLICY_FLAG_ENABLED)) {
        /* Verify destination and port/protocol match */
        if (match_dest_addr(key, lpm_entry) && 
            match_ports_proto(key, lpm_entry)) {
            /* Convert lpm_policy_entry to policy_value for return */
            struct policy_value *scratch = bpf_map_lookup_elem(&policy_scratch, &zero);
            if (scratch) {
                copy_policy_from_lpm(scratch, lpm_entry);
                return scratch;
            }
        }
    }
    
    /* Fallback: Try exact 5-tuple match in hash map */
    val = bpf_map_lookup_elem(&policy_rules, key);
    if (val && (val->flags & POLICY_FLAG_ENABLED))
        return val;
    
    /* Try with wildcard source port */
    struct flow_key lookup_key;
    __builtin_memcpy(&lookup_key, key, sizeof(lookup_key));
    lookup_key.sport = 0;
    val = bpf_map_lookup_elem(&policy_rules, &lookup_key);
    if (val && (val->flags & POLICY_FLAG_ENABLED))
        return val;
    
    /* Try with wildcard dest port */
    __builtin_memcpy(&lookup_key, key, sizeof(lookup_key));
    lookup_key.dport = 0;
    val = bpf_map_lookup_elem(&policy_rules, &lookup_key);
    if (val && (val->flags & POLICY_FLAG_ENABLED))
        return val;
    
    /* Try with both ports wildcard */
    lookup_key.sport = 0;
    lookup_key.dport = 0;
    val = bpf_map_lookup_elem(&policy_rules, &lookup_key);
    if (val && (val->flags & POLICY_FLAG_ENABLED))
        return val;
    
    /* Try protocol-only match (all IPs wildcarded) */
    __builtin_memset(&lookup_key, 0, sizeof(lookup_key));
    lookup_key.protocol = key->protocol;
    lookup_key.af = key->af;
    val = bpf_map_lookup_elem(&policy_rules, &lookup_key);
    if (val && (val->flags & POLICY_FLAG_ENABLED))
        return val;
    
    return NULL;
}

/*
 * Process all actions for a matched rule in priority order
 * Returns the final XDP verdict (drop or pass)
 */
static __always_inline __u32 process_rule_actions(struct xdp_md *ctx,
                                                    struct policy_value *policy,
                                                    struct flow_key *flow_key)
{
    __u32 final_verdict = XDP_PASS;
    __u32 should_log = 0;
    
    /* Process actions embedded in policy_value in priority order */
    #pragma unroll
    for (__u8 i = 0; i < MAX_ACTIONS_PER_RULE; i++) {
        if (i >= policy->num_actions)
            break;
        
        __u32 action = policy->actions[i].action;
        
        switch (action) {
        case ACTION_DROP:
            final_verdict = XDP_DROP;
            break;
        case ACTION_LOG:
            should_log = 1;
            break;
        case ACTION_PASS:
            /* Pass doesn't override a drop decision */
            if (final_verdict != XDP_DROP)
                final_verdict = XDP_PASS;
            break;
        case ACTION_TAIL_CALL:
            if (policy->tail_call_idx < MAX_DISPATCHER_PROGS) {
                __u32 key = ctx->ingress_ifindex % MAX_INTERFACES;
                struct global_stats *stats = bpf_map_lookup_elem(&global_stats, &key);
                if (stats)
                    stats->tail_calls++;
                
                bpf_tail_call(ctx, &xdp_dispatcher, policy->tail_call_idx);
            }
            break;
        }
    }
    
    /* Emit event if logging was requested */
    if (should_log && (policy->flags & POLICY_FLAG_LOG)) {
        emit_event(ctx, flow_key, policy->rule_id, ACTION_LOG, final_verdict);
    }
    
    return final_verdict;
}

/*
 * Check if destination MAC is broadcast (ff:ff:ff:ff:ff:ff) or multicast (bit 0 of first byte set)
 * Returns 1 for BUM traffic, 0 for unicast
 */
static __always_inline int is_bum_traffic(struct ethhdr *eth)
{
    /* Check for broadcast: ff:ff:ff:ff:ff:ff */
    if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff &&
        eth->h_dest[2] == 0xff && eth->h_dest[3] == 0xff &&
        eth->h_dest[4] == 0xff && eth->h_dest[5] == 0xff)
        return 1;
    
    /* Check for multicast: bit 0 of first octet is set */
    if (eth->h_dest[0] & 0x01)
        return 1;
    
    return 0;
}

SEC("xdp")
int xdp_policy_main(struct xdp_md *ctx)
{
    struct flow_key flow_key;
    struct policy_value *policy;
    __u32 pkt_len = ctx->data_end - ctx->data;
    __u32 zero = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    /* Check Ethernet header for BUM traffic classification */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        __u32 key = ctx->ingress_ifindex % MAX_INTERFACES;
        struct global_stats *stats = bpf_map_lookup_elem(&global_stats, &key);
        if (stats)
            stats->parse_errors++;
        return XDP_PASS;
    }
    
    int bum = is_bum_traffic(eth);
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    /* Parse packet to extract flow key */
    if (parse_packet(ctx, &flow_key) < 0) {
        /* Non-IP traffic - classify as BUM or non-IP unicast and track ethertype */
        __u32 key = ctx->ingress_ifindex % MAX_INTERFACES;
        struct global_stats *stats = bpf_map_lookup_elem(&global_stats, &key);
        if (stats) {
            if (bum)
                stats->bum_packets++;
            else
                stats->non_ip_unicast++;
        }
        /* Track ethertype for non-IP traffic */
        update_ethertype_stats(ctx->ingress_ifindex, eth_proto);
        return XDP_PASS;
    }
    
    /* Lookup policy */
    policy = lookup_policy(&flow_key);
    
    if (policy) {
        /* Update rule statistics */
        update_rule_stats(policy->rule_id, pkt_len);
        
        /* Store metadata for potential tail calls */
        struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_scratch, &zero);
        if (meta) {
            __builtin_memcpy(&meta->flow, &flow_key, sizeof(flow_key));
            meta->pkt_len = pkt_len;
            meta->matched_rule_id = policy->rule_id;
            /* Use first action (if any) for compatibility */
            meta->action = policy->num_actions > 0 ? policy->actions[0].action : ACTION_PASS;
            meta->flags = policy->flags;
        }
        
        /* Update global stats based on first action */
        __u32 first_action = policy->num_actions > 0 ? policy->actions[0].action : ACTION_PASS;
        update_global_stats(ctx->ingress_ifindex, pkt_len, first_action);
        
        /* Process and execute all actions */
        __u32 verdict = process_rule_actions(ctx, policy, &flow_key);
        return verdict;
        
    } else {
        /* No matching rule - use default action */
        __u32 *def_action = bpf_map_lookup_elem(&default_action, &zero);
        __u32 action = def_action ? *def_action : ACTION_PASS;
        update_global_stats(ctx->ingress_ifindex, pkt_len, action);
        
        /* Return appropriate XDP verdict */
        switch (action) {
        case ACTION_DROP:
            return XDP_DROP;
        case ACTION_PASS:
        case ACTION_LOG:
        default:
            return XDP_PASS;
        }
    }
}

/*
 * NAT tail call program
 */
SEC("xdp")
int xdp_nat(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_scratch, &zero);
    
    if (meta) {
        /* Network Address Translation could be implemented here */
        bpf_printk("nat: rule=%llu len=%u\n", 
                   meta->matched_rule_id, meta->pkt_len);
    }
    
    return XDP_PASS;
}
