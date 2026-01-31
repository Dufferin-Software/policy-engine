/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Minimal vmlinux.h subset for XDP/TC policy engine
 * This provides kernel type definitions needed for BPF programs
 */

#ifndef __VMLINUX_SUBSET_H__
#define __VMLINUX_SUBSET_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;

/* Boolean type */
typedef _Bool bool;
#define true 1
#define false 0

/* NULL pointer */
#define NULL ((void *)0)

/* Endianness detection - clang/BPF typically targets little endian */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD
#else
/* Default to little endian for x86 targets */
#define __LITTLE_ENDIAN_BITFIELD
#endif

/* Ethernet header */
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

/* IPv4 header */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 ihl:4,
         version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         ihl:4;
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

/* IPv6 header */
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 priority:4,
         version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version:4,
         priority:4;
#endif
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    struct in6_addr {
        union {
            __u8 u6_addr8[16];
            __be16 u6_addr16[8];
            __be32 u6_addr32[4];
        };
    } saddr;
    struct in6_addr daddr;
} __attribute__((packed));

/* TCP header */
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 res1:4,
          doff:4,
          fin:1,
          syn:1,
          rst:1,
          psh:1,
          ack:1,
          urg:1,
          ece:1,
          cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16 doff:4,
          res1:4,
          cwr:1,
          ece:1,
          urg:1,
          ack:1,
          psh:1,
          rst:1,
          syn:1,
          fin:1;
#endif
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

/* UDP header */
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

/* ICMP header */
struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
} __attribute__((packed));

/* ICMPv6 header */
struct icmp6hdr {
    __u8 icmp6_type;
    __u8 icmp6_code;
    __sum16 icmp6_cksum;
    union {
        __be32 un_data32[1];
        __be16 un_data16[2];
        __u8 un_data8[4];
    } icmp6_dataun;
} __attribute__((packed));

/* XDP context */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

/* TC/BPF context */
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
    /* ... more fields exist but these are the commonly used ones */
};

/* BPF spin lock */
struct bpf_spin_lock {
    __u32 val;
};

/* Ethernet protocol IDs */
#define ETH_P_IP      0x0800
#define ETH_P_IPV6    0x86DD
#define ETH_P_ARP     0x0806
#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_LLDP    0x88CC
#define ETH_P_MPLS_UC 0x8847
#define ETH_P_MPLS_MC 0x8848
#define ETH_P_SLOW    0x8809  /* LACP, etc */

/* IP protocol numbers */
#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17
#define IPPROTO_ICMPV6 58

/* XDP return codes */
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

/* TC return codes */
#define TC_ACT_UNSPEC    (-1)
#define TC_ACT_OK        0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT      2
#define TC_ACT_PIPE      3
#define TC_ACT_STOLEN    4
#define TC_ACT_QUEUED    5
#define TC_ACT_REPEAT    6
#define TC_ACT_REDIRECT  7

/* BPF map flags */
#define BPF_F_NO_PREALLOC (1U << 0)

/* Helper to get pointer from packet offset */
#define BPF_CORE_READ(dst, src) \
    bpf_probe_read_kernel(dst, sizeof(*(dst)), src)

#endif /* __VMLINUX_SUBSET_H__ */
