/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Common definitions shared between XDP/TC BPF programs and userspace
 */

#ifndef __POLICY_COMMON_H__
#define __POLICY_COMMON_H__

#include "vmlinux_subset.h"

/* Maximum number of policy rules */
#define MAX_POLICY_RULES 65536

/* Maximum number of tail call programs in the dispatcher */
#define MAX_DISPATCHER_PROGS 1

/* Maximum interfaces we track */
#define MAX_INTERFACES 256

/* Maximum actions per rule */
#define MAX_ACTIONS_PER_RULE 8

/* Policy rule flags */
#define POLICY_FLAG_ENABLED     (1 << 0)
#define POLICY_FLAG_LOG         (1 << 1)
#define POLICY_FLAG_BIDIRECTIONAL (1 << 2)
#define POLICY_FLAG_CONNTRACK   (1 << 3)

/* Protocol identifiers (matches IPPROTO_*) */
#define PROTO_ANY   0
#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP   17

/* Address family */
#define AF_INET     2
#define AF_INET6    10

/* Policy actions */
enum policy_action {
    ACTION_PASS = 0,       /* Allow packet through */
    ACTION_DROP = 1,       /* Drop packet silently */
    ACTION_LOG = 2,        /* Log and pass */
    ACTION_TAIL_CALL = 3,  /* Invoke tail call for further processing */
};

/* Dispatcher program slots */
enum dispatcher_slot {
    SLOT_NAT = 0,
};

/*
 * LPM (Longest Prefix Match) key for IPv4 addresses
 * Used with BPF_MAP_TYPE_LPM_TRIE
 * The prefixlen field must come first, followed by the data.
 */
struct lpm_key_v4 {
    __u32 prefixlen;    /* Prefix length in bits (0-32 for IPv4) */
    __u32 addr;         /* IPv4 address in network byte order */
} __attribute__((packed));

/*
 * LPM key for IPv6 addresses
 */
struct lpm_key_v6 {
    __u32 prefixlen;    /* Prefix length in bits (0-128 for IPv6) */
    __u32 addr[4];      /* IPv6 address (128 bits) in network byte order */
} __attribute__((packed));

/*
 * 5-tuple flow key for policy matching (kept for exact match fallback)
 * Supports both IPv4 and IPv6
 */
struct flow_key {
    union {
        __u32 saddr4;
        __u32 saddr6[4];
    };
    union {
        __u32 daddr4;
        __u32 daddr6[4];
    };
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 af;        /* Address family: AF_INET or AF_INET6 */
    __u16 pad;      /* Padding for alignment */
} __attribute__((packed));

/*
 * Action entry for a rule (embedded in policy_value)
 */
struct rule_action {
    __u32 action;       /* The action to take */
    __u8 priority;      /* Priority (lower = higher priority) */
    __u8 _pad1;
    __u16 _pad2;
} __attribute__((packed));

/*
 * Policy rule value with embedded action list
 */
struct policy_value {
    __u32 flags;                        /* Policy flags */
    __u32 tail_call_idx;                /* Tail call program index */
    __u64 rule_id;                      /* Unique rule identifier */
    __u32 priority;                     /* Rule priority (lower = higher priority) */
    __u8 num_actions;                   /* Number of actions in the list */
    __u8 _pad1;                         /* Padding */
    __u16 _pad2;                        /* Padding */
    struct rule_action actions[MAX_ACTIONS_PER_RULE]; /* Ordered action list */
} __attribute__((packed));

/*
 * Policy rule entry stored in LPM trie
 * Contains match criteria beyond the IP prefix and the policy value
 */
struct lpm_policy_entry {
    /* Additional match criteria (0 = any/wildcard) */
    __u16 sport;            /* Source port (0 = any) */
    __u16 dport;            /* Destination port (0 = any) */
    __u8 protocol;          /* Protocol number (0 = any) */
    __u8 src_prefixlen;     /* Original source prefix length for reference */
    __u8 dst_prefixlen;     /* Original dest prefix length for reference */
    __u8 _pad1;
    
    /* Destination prefix for secondary match (IPv4 in first 4 bytes, or full IPv6) */
    union {
        __u32 daddr4;
        __u32 daddr6[4];
    };
    __u8 af;                /* Address family */
    __u8 _pad2[3];
    
    /* Policy value */
    __u32 flags;                        /* Policy flags */
    __u32 tail_call_idx;                /* Tail call program index */
    __u64 rule_id;                      /* Unique rule identifier */
    __u32 priority;                     /* Rule priority (lower = higher priority) */
    __u8 num_actions;                   /* Number of actions in the list */
    __u8 _pad3;                         /* Padding */
    __u16 _pad4;                        /* Padding */
    struct rule_action actions[MAX_ACTIONS_PER_RULE]; /* Ordered action list */
} __attribute__((packed));

/*
 * Per-rule statistics
 */
struct rule_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;     /* Timestamp of last matching packet */
} __attribute__((packed));

/* Maximum number of ethertype counters to track */
#define MAX_ETHERTYPE_COUNTERS 16

/* Well-known ethertypes (in host byte order for comparison after ntohs) */
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_8021Q 0x8100
#define ETHERTYPE_IPV6  0x86DD
#define ETHERTYPE_LLDP  0x88CC
#define ETHERTYPE_MPLS  0x8847
#define ETHERTYPE_MPLS_MC 0x8848
#define ETHERTYPE_8021AD 0x88A8
#define ETHERTYPE_SLOW  0x8809  /* LACP, etc */

/*
 * Ethertype statistics entry
 */
struct ethertype_stats {
    __u16 ethertype;        /* Ethertype value */
    __u16 _pad;
    __u64 packets;          /* Packet count */
} __attribute__((packed));

/*
 * Global statistics per interface
 */
struct global_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 policy_matches;
    __u64 policy_drops;
    __u64 policy_pass;
    __u64 policy_redirects;
    __u64 parse_errors;
    __u64 tail_calls;
    __u64 bum_packets;      /* Broadcast/Unknown-unicast/Multicast (non-IP) */
    __u64 non_ip_unicast;   /* Non-IP unicast (e.g., ARP replies) */
} __attribute__((packed));

/*
 * Interface state tracking
 */
struct iface_state {
    __u32 ifindex;
    __u32 xdp_attached;     /* 1 if XDP program attached */
    __u32 tc_attached;      /* 1 if TC program attached */
    __u32 xdp_mode;         /* XDP attach mode: native, generic, offload */
    char ifname[16];        /* Interface name */
} __attribute__((packed));

/*
 * Event structure for ringbuf notifications
 */
struct policy_event {
    __u64 timestamp_ns;
    __u64 rule_id;
    __u32 action;
    __u32 ifindex;
    struct flow_key flow;
    __u32 pkt_len;
    __u32 verdict;
} __attribute__((packed));

/* XDP attach modes */
#define XDP_MODE_UNSPEC  0
#define XDP_MODE_NATIVE  1
#define XDP_MODE_GENERIC 2
#define XDP_MODE_OFFLOAD 3

/* 
 * Helper macros for flow key manipulation
 */
#define FLOW_KEY_INIT_V4(key, sip, dip, sp, dp, proto) \
    do { \
        __builtin_memset(&(key), 0, sizeof(key)); \
        (key).saddr4 = (sip); \
        (key).daddr4 = (dip); \
        (key).sport = (sp); \
        (key).dport = (dp); \
        (key).protocol = (proto); \
        (key).af = AF_INET; \
    } while(0)

#define FLOW_KEY_INIT_V6(key, sip, dip, sp, dp, proto) \
    do { \
        __builtin_memset(&(key), 0, sizeof(key)); \
        __builtin_memcpy((key).saddr6, (sip), 16); \
        __builtin_memcpy((key).daddr6, (dip), 16); \
        (key).sport = (sp); \
        (key).dport = (dp); \
        (key).protocol = (proto); \
        (key).af = AF_INET6; \
    } while(0)

#endif /* __POLICY_COMMON_H__ */
