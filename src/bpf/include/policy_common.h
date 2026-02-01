/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common definitions shared between XDP/TC BPF programs and userspace
 */

#ifndef __POLICY_COMMON_H__
#define __POLICY_COMMON_H__

#include "vmlinux_subset.h"

/* Maximum number of policy rules */
#define MAX_POLICY_RULES 65536

/* Maximum TLS SNI pattern length */
#define MAX_SNI_LEN 128

/* SNI match types */
#define SNI_MATCH_NONE 0   /* No SNI matching */
#define SNI_MATCH_EXACT 1  /* Exact domain match */
#define SNI_MATCH_SUFFIX 2 /* Suffix wildcard match (*.example.com) */

/* Maximum number of tail call programs in the dispatcher */
#define MAX_DISPATCHER_PROGS 4

/* Well-known dispatcher tail call slots (same slot number for XDP and TC) */
#define XDP_DISPATCHER_SNI_SLOT 0        /* TLS SNI inspection program (XDP) */
#define XDP_DISPATCHER_FIB_SLOT 1        /* FIB forwarding program (XDP ingress only) */
#define XDP_DISPATCHER_FLOW_CACHE_SLOT 2 /* Flow cache update program (XDP) */
#define XDP_DISPATCHER_QUIC_SLOT 3       /* QUIC Initial packet detector (XDP) */
#define TC_DISPATCHER_SNI_SLOT 0         /* TLS SNI inspection program (TC) */
#define TC_DISPATCHER_FLOW_CACHE_SLOT 1  /* Flow cache update program (TC) */
#define TC_DISPATCHER_QUIC_SLOT 2        /* QUIC Initial packet detector (TC) */

/* Maximum number of TLS extensions to scan when searching for SNI */
#define MAX_TLS_EXTENSIONS 24

/* Upper bound (bytes) for bpf_skb_pull_data() in tc_sni_inspect.  Sized to
 * fit a realistic post-quantum TLS 1.3 ClientHello (X25519MLKEM768 key share
 * ~1.3 KB + ECH + PSK puts modern CHs at ~2-3 KB) with headroom.  The SNI
 * parser already bounds extension walks at 0x3000. */
#define SNI_PULL_MAX 4096

/* Policy flags */
#define POLICY_FLAG_INSPECT (1 << 1)

/* Flow key flags (stored in flow_key.flags) */
#define FLOW_FLAG_FRAGMENT (1 << 0) /* Packet is a non-first IP fragment */
#define FLOW_FLAG_QUIC (1 << 1)     /* UDP payload looks like QUIC */
#define FLOW_FLAG_QUIC_V1 (1 << 2)  /* QUIC version 1 (RFC 9000) */
#define FLOW_FLAG_QUIC_V2 (1 << 3)  /* QUIC version 2 (RFC 9369) */

/* QUIC version filter constants (stored in l4_rule.quic_version) */
#define QUIC_VERSION_ANY 0xFFFFFFFFU /* Match any QUIC version */
#define QUIC_VERSION_V1 0x00000001U  /* RFC 9000 QUIC v1 */
#define QUIC_VERSION_V2 0x6b3343cfU  /* RFC 9369 QUIC v2 */

/*
 * Return value from parse_packet / tc_parse_packet indicating a non-first
 * IP fragment.  The flow key contains valid src/dst addresses and protocol
 * but sport/dport are 0 (no L4 header present in non-first fragments).
 * Distinct from -1 (genuine parse error) so the caller can count fragments
 * separately and still apply IP/protocol-only policy matching.
 */
#define PARSE_NONFIRST_FRAG (-2)

/* Flow verdict cache.
 * Generic "decide once per flow, fast-path the rest" primitive.  Used by the
 * Suricata IPS path (cached DROP verdicts from EVE alerts), the QUIC SNI
 * inspector (cached verdicts after decrypting the Initial ClientHello), and
 * the in-kernel TCP SNI inspector (tc_sni_inspect / xdp_sni_inspect) after
 * walking the rule's action list.
 * Always compiled in so non-Suricata builds can still cache verdicts. */
#define MAX_FLOW_VERDICTS 65536

/* TTL for verdicts written by the in-kernel TCP SNI inspector and the QUIC
 * userspace consumer.  Sized to cover the bulk of a TCP TLS or QUIC session
 * so the L4 fast path drops/passes every subsequent packet without re-running
 * inspection.  Kept in sync with QUIC_VERDICT_TTL_NS in
 * src/server/event_stream.rs. */
#define SNI_VERDICT_TTL_NS 60000000000ULL

#ifdef SURICATA_IPS
/* Inspect mode */
#define INSPECT_MODE_DISABLED 0
#define INSPECT_MODE_IPS 1
#define INSPECT_MODE_IDS \
  2 /* IDS: clone to Suricata, alert-only, no DROP verdicts */

/* TTL for the temporary PASS verdict written by the INSPECT action.
 * When a packet is redirected to Suricata, a PASS verdict with this TTL is
 * cached so that subsequent packets on the same flow pass through without
 * being redirected on every arrival.  When the TTL expires, one packet per
 * flow is re-redirected to Suricata for a fresh inspection cycle.
 * If Suricata fires a DROP alert, the EveConsumer overwrites the PASS verdict
 * with a DROP verdict.  30 seconds is a reasonable default. */
#define INSPECT_PASS_VERDICT_TTL_NS 30000000000ULL

/* TTL for flows_to_inspect entries.
 * How long TC ingress keeps cloning a flow to Suricata after an INSPECT rule
 * match in XDP.  5 minutes is long enough to cover any typical TCP session and
 * gives Suricata time to reassemble and inspect the full application stream. */
#define INSPECT_CLONE_TTL_NS 300000000000ULL

/* Maximum number of flows tracked for TC ingress cloning */
#define MAX_FLOWS_TO_INSPECT 65536
#endif /* SURICATA_IPS */

/* Maximum interfaces we track */
#define MAX_INTERFACES 256

/* Maximum actions per rule */
#define MAX_ACTIONS_PER_RULE 4

/* Two-level LPM architecture (src prefix → dst prefix → L4 rules) */
#define MAX_SRC_GROUPS 4096           /* Max distinct source prefix groups */
#define MAX_DST_ENTRIES_PER_GROUP 512 /* Max entries per inner dst LPM trie */
#define MAX_L4_RULES 8                /* Max L4 rules per dst prefix entry */
#define MAX_LPM_ANCESTORS 6           /* Max ancestor walk depth per level */

/* Protocol identifiers (matches IPPROTO_*) */
#define PROTO_ANY 0
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

/* Address family */
#define AF_INET 2
#define AF_INET6 10

/* Policy actions */
enum policy_action {
  ACTION_PASS = 0,      /* Allow packet through */
  ACTION_DROP = 1,      /* Drop packet silently */
  ACTION_LOG = 2,       /* Log and pass */
  ACTION_TAIL_CALL = 3, /* Invoke tail call for further processing */
#ifdef SURICATA_IPS
  ACTION_INSPECT = 4, /* Mirror to Suricata for deep inspection */
#endif
};

/*
 * LPM (Longest Prefix Match) key for IPv4 addresses
 * Used with BPF_MAP_TYPE_LPM_TRIE
 * The prefixlen field must come first, followed by the data.
 */
struct lpm_key_v4 {
  __u32 prefixlen; /* Prefix length in bits (0-32 for IPv4) */
  __u32 addr;      /* IPv4 address in network byte order */
} __attribute__((packed));

/*
 * LPM key for IPv6 addresses
 */
struct lpm_key_v6 {
  __u32 prefixlen; /* Prefix length in bits (0-128 for IPv6) */
  __u32 addr[4];   /* IPv6 address (128 bits) in network byte order */
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
  __u8 af;     /* Address family: AF_INET or AF_INET6 */
  __u16 flags; /* FLOW_FLAG_* bitmask */
} __attribute__((packed));

/*
 * Action entry for a rule (embedded in policy_value)
 */
struct rule_action {
  __u32 action;  /* The action to take */
  __u8 priority; /* Priority (lower = higher priority) */
  __u8 _pad1;
  __u16 _pad2;
  __u64 param; /* Action parameter (e.g., rate-limit interval ns for LOG; 0 =
                  disabled) */
} __attribute__((packed));

/*
 * SNI rule entry stored in the sni_rules map (keyed by rule_id).
 * Looked up by xdp_sni_inspect to retrieve the actual pattern to match
 * against the TLS ClientHello SNI extension.
 */
struct sni_rule_entry {
  __u8 sni_match_type; /* SNI_MATCH_EXACT or SNI_MATCH_SUFFIX */
  __u8 sni_len;        /* Byte length of sni_pattern */
  __u8 _pad[2];
  char sni_pattern[MAX_SNI_LEN]; /* Lowercase domain pattern, null-terminated */
} __attribute__((packed));

/*
 * One pending SNI rule entry in the per-packet scratch space.
 * The main program fills an array of these when multiple L4-matching SNI rules
 * exist; xdp_sni_inspect / tc_sni_inspect processes them one at a time,
 * tail-calling itself (slot 0) on each mismatch until the list is exhausted.
 */
struct sni_pending_entry {
  __u64 rule_id;    /* Key for sni_rules / tc_sni_rules map lookup */
  __u8 num_actions; /* Valid entries in actions[] */
  __u8 _pad[7];
  /* Full action list, copied from the matching l4_rule.  The SNI inspect tail
   * call iterates all of these on an SNI match so multi-action rules
   * (e.g. LOG then DROP) behave identically to non-SNI rules. */
  struct rule_action actions[MAX_ACTIONS_PER_RULE];
}; /* 16 + 4*16 = 80 bytes */

/*
 * Flow verdict key (used in flow_verdict_cache hash map).
 * Generic 5-tuple keyed cache.  Written by any verdict source (Suricata EVE
 * consumer, QUIC SNI inspector, future inspectors); checked by XDP/TC at
 * packet entry for cached PASS/DROP decisions.
 */
struct flow_verdict_key {
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
  __u8 af;
  __u16 _pad;
} __attribute__((packed));

/*
 * Flow verdict value: cached decision with expiry and traffic counters.
 * packets/bytes are incremented atomically by XDP/TC on every verdict hit.
 */
struct flow_verdict {
  __u32 action; /* ACTION_PASS or ACTION_DROP */
  __u32 _pad;
  __u64 timestamp_ns; /* When verdict was set */
  __u64 expires_ns;   /* Auto-expire timestamp (0 = never) */
  __u64 packets;      /* Packets matched by this verdict */
  __u64 bytes;        /* Bytes matched by this verdict */
};

#ifdef SURICATA_IPS
/*
 * Inspect configuration (written by userspace, read by BPF)
 */
struct inspect_config {
  __u32 mode;           /* INSPECT_MODE_* */
  __u32 mirror_ifindex; /* ifindex of pe-inspect0 veth */
  __u32 _pad[2];
} __attribute__((packed));
#endif /* SURICATA_IPS */

/*
 * FIB forwarding configuration (written by userspace, read by XDP BPF).
 * Stored in a BPF_MAP_TYPE_ARRAY (key=0, max_entries=1).
 * When enabled, the XDP program attempts bpf_fib_lookup() for non-dropped
 * IP packets and redirects them directly to the next-hop interface, bypassing
 * the kernel routing stack.
 */
#define FIB_FORWARD_DISABLED 0
#define FIB_FORWARD_ENABLED 1

struct fib_config {
  __u32 mode;    /* FIB_FORWARD_DISABLED or FIB_FORWARD_ENABLED */
  __u32 _pad[3]; /* reserved */
} __attribute__((packed));

/*
 * Flow cache for IPFIX export (independent of Suricata IPS).
 * flow_cache_config is written by userspace to enable/disable per-flow
 * accounting. flow_cache_entry accumulates per-flow stats updated on
 * every packet processed by the XDP/TC programs.
 */
#define FLOW_CACHE_DISABLED 0
#define FLOW_CACHE_ENABLED 1

struct flow_cache_config {
  __u32 enabled; /* FLOW_CACHE_DISABLED or FLOW_CACHE_ENABLED */
  __u32 _pad[3];
} __attribute__((packed));

struct flow_cache_entry {
  __u64 first_seen_ns; /* bpf_ktime_get_ns() at first packet (CLOCK_MONOTONIC) */
  __u64 last_seen_ns;  /* bpf_ktime_get_ns() at most recent packet */
  __u64 packets;
  __u64 bytes;
  __u64 rule_id; /* matched rule id; 0 if no rule matched */
  __u32 action;  /* ACTION_PASS / ACTION_DROP / ACTION_INSPECT */
  __u32 _pad;
}; /* naturally aligned — no packing needed; 48 bytes */

/*
 * Per-rule statistics
 */
struct rule_stats {
  __u64 packets;
  __u64 bytes;
  __u64 last_seen_ns; /* Timestamp of last matching packet */
  __u64 last_log_ns;  /* Timestamp of last LOG event (for rate limiting) */
};

/* Maximum number of ethertype counters to track */
#define MAX_ETHERTYPE_COUNTERS 16

/* Well-known ethertypes (in host byte order for comparison after ntohs) */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_8021Q 0x8100
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_LLDP 0x88CC
#define ETHERTYPE_MPLS 0x8847
#define ETHERTYPE_MPLS_MC 0x8848
#define ETHERTYPE_8021AD 0x88A8
#define ETHERTYPE_SLOW 0x8809 /* LACP, etc */

/*
 * Ethertype statistics entry
 */
struct ethertype_stats {
  __u16 ethertype; /* Ethertype value */
  __u16 _pad;
  __u64 packets; /* Packet count */
} __attribute__((packed));

/*
 * Non-IP sender statistics — tracks per-source-MAC packet counts for every
 * non-IP ethertype (ARP, LLDP, unknown L2 protos, etc.).
 * Key: (ifindex, src_mac, ethertype) — one bucket per sender/ethertype pair.
 * Value: packet count.
 *
 * Map type is LRU_HASH so oldest entries are evicted automatically.
 * Max entries: 1024 (covers ~64 unique MACs × 16 ethertypes).
 */
struct nonip_sender_key {
  __u32 ifindex;
  __u8 mac[6];     /* Source MAC address */
  __u16 ethertype; /* Ethertype (host byte order, already converted by get_ethertype) */
};

struct nonip_sender_stats {
  __u64 packets;
};

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
  __u64 bum_packets;           /* Broadcast/Unknown-unicast/Multicast (non-IP) */
  __u64 non_ip_unicast;        /* Non-IP unicast (e.g., ARP replies) */
  __u64 inspect_redirects;     /* Packets mirrored to Suricata via INSPECT action */
  __u64 fragments;             /* Non-first IP fragments (no L4 header available) */
  __u64 verdict_pass_packets;  /* Flow verdict cache: packets that hit a PASS
                                  verdict */
  __u64 verdict_pass_bytes;    /* Flow verdict cache: bytes that hit a PASS verdict
                                */
  __u64 verdict_drop_packets;  /* Flow verdict cache: packets that hit a DROP
                                  verdict */
  __u64 verdict_drop_bytes;    /* Flow verdict cache: bytes that hit a DROP verdict
                                */
  __u64 fib_forwarded_packets; /* Packets forwarded via XDP FIB redirect */
  __u64 fib_forwarded_bytes;   /* Bytes forwarded via XDP FIB redirect */
  __u64 fib_fallback_packets;  /* FIB lookup attempted but fell back to XDP_PASS */
} __attribute__((packed));

/*
 * Per-protocol packet/byte counters (indexed by IP protocol number 0-255)
 */
struct proto_stats {
  __u64 packets;
  __u64 bytes;
} __attribute__((packed));

/*
 * Per-QUIC-version packet/byte counters.
 * Slots: 0=unused, 1=v1 (RFC 9000), 2=v2 (RFC 9369), 3=other QUIC
 */
struct quic_stats_val {
  __u64 packets;
  __u64 bytes;
};

/*
 * Integer log2 helper for histogram bucket assignment.
 * Returns floor(log2(v)), or 0 for v == 0.
 */
static __always_inline __u32 log2_u64(__u64 v) {
  __u32 r = 0;
  if (v >= (1ULL << 32)) {
    v >>= 32;
    r += 32;
  }
  if (v >= (1ULL << 16)) {
    v >>= 16;
    r += 16;
  }
  if (v >= (1ULL << 8)) {
    v >>= 8;
    r += 8;
  }
  if (v >= (1ULL << 4)) {
    v >>= 4;
    r += 4;
  }
  if (v >= (1ULL << 2)) {
    v >>= 2;
    r += 2;
  }
  if (v >= (1ULL << 1)) {
    r += 1;
  }
  return r;
}

/*
 * Interface state tracking
 */
struct iface_state {
  __u32 ifindex;
  __u32 xdp_attached; /* 1 if XDP program attached */
  __u32 tc_attached;  /* 1 if TC program attached */
  __u32 xdp_mode;     /* XDP attach mode: native, generic, offload */
  char ifname[16];    /* Interface name */
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
  __u8 sni[MAX_SNI_LEN]; /* SNI value if rule matched with SNI inspection */
  __u8 sni_len;          /* Length of SNI string (0 if no SNI) */
  __u8 _sni_pad[7];      /* Alignment padding */
} __attribute__((packed));

/*
 * QUIC Initial inspector output.
 *
 * Emitted by xdp_quic_initial_inspect / tc_quic_initial_inspect when a packet
 * passes the cheap long-header / version / Initial-type pre-checks.  The BPF
 * side does NOT decrypt — it forwards the 5-tuple, version, DCID, and a
 * bounded copy of the raw UDP payload to userspace, which performs the
 * Initial-key derivation and ClientHello SNI extraction off the fast path.
 *
 * QUIC_INSPECT_PAYLOAD_MAX is sized to the minimum RFC 9000 Initial datagram
 * (1200 bytes plus headroom for QUIC header) — sufficient for any ClientHello
 * that fits in a single Initial, and keeps ringbuf / per-CPU memory bounded.
 */
#define QUIC_INSPECT_PAYLOAD_MAX 1280
#define QUIC_INSPECT_MAX_DCID_LEN 20 /* RFC 9000: max DCID length */

struct quic_inspect_event {
  __u64 timestamp_ns;
  __u32 ifindex;
  __u32 version;        /* QUIC version */
  struct flow_key flow; /* 5-tuple (UDP) */
  __u32 pkt_len;        /* Full packet length on wire */
  __u16 payload_off;    /* Offset of UDP payload (QUIC header start) */
  __u16 payload_len;    /* Bytes captured in payload[] */
  __u8 dcid_len;        /* 1..QUIC_INSPECT_MAX_DCID_LEN */
  __u8 _pad[7];
  __u8 dcid[QUIC_INSPECT_MAX_DCID_LEN];
  __u8 payload[QUIC_INSPECT_PAYLOAD_MAX];
} __attribute__((packed));

/* XDP attach modes */
#define XDP_MODE_UNSPEC 0
#define XDP_MODE_NATIVE 1
#define XDP_MODE_GENERIC 2
#define XDP_MODE_OFFLOAD 3

/*
 * Helper macros for flow key manipulation
 */
#define FLOW_KEY_INIT_V4(key, sip, dip, sp, dp, proto) \
  do {                                                 \
    __builtin_memset(&(key), 0, sizeof(key));          \
    (key).saddr4 = (sip);                              \
    (key).daddr4 = (dip);                              \
    (key).sport = (sp);                                \
    (key).dport = (dp);                                \
    (key).protocol = (proto);                          \
    (key).af = AF_INET;                                \
  } while (0)

#define FLOW_KEY_INIT_V6(key, sip, dip, sp, dp, proto) \
  do {                                                 \
    __builtin_memset(&(key), 0, sizeof(key));          \
    __builtin_memcpy((key).saddr6, (sip), 16);         \
    __builtin_memcpy((key).daddr6, (dip), 16);         \
    (key).sport = (sp);                                \
    (key).dport = (dp);                                \
    (key).protocol = (proto);                          \
    (key).af = AF_INET6;                               \
  } while (0)

/*
 * Parse the TLS ClientHello in the TCP payload and match its SNI extension
 * against the given rule.
 *
 * Return values:
 *   1  — SNI found and matches the rule pattern (apply rule action)
 *   0  — packet is not a TLS ClientHello, has no SNI extension, or the packet
 *         is truncated before the SNI can be read (fail-closed: callers should
 *         apply the rule action — non-TLS traffic matching by IP/port gets the
 *         configured action without SNI exemption)
 *  -1  — SNI extension found but the hostname does not match the rule pattern
 *         (fail-open: a different site, callers should skip this rule)
 *
 * Uses a forward packet-pointer walk with an asm barrier (cur4 approach) for
 * the extension scan so the BPF verifier can track the readable-range (r)
 * field through all MAX_TLS_EXTENSIONS iterations without var_off growing too
 * wide.  The SNI match is performed in-place while sni_hdr is still a clean,
 * id-tracked packet pointer—avoiding the pointer-subtraction path that would
 * produce an unconstrained scalar offset and cause the verifier to reject
 * subsequent packet accesses.
 */
static __always_inline int
match_sni_in_packet(void *data, const void *data_end, __u16 l4_off,
                    const struct sni_rule_entry *rule) {
  /* Bound l4_off before using it as a variable packet offset.  Without this
   * the BPF verifier tracks var_off as the full __u16 range [0, 65535] and
   * fails to propagate packet-pointer range updates across sibling registers
   * after bounds checks. */
  if (l4_off > 512)
    return 0;
  __u32 off = l4_off;

  /* TCP header: read the doff bitfield via direct byte access to avoid the
   * struct tcphdr * pointer arithmetic that confuses the BPF verifier. */
  __u8 *tcp_start = (__u8 *)data + off;
  if ((void *)(tcp_start + 20) > data_end)
    return 0;
  __u8 doff_byte = tcp_start[12];
  __u32 tcp_hdr_len = ((doff_byte >> 4) & 0xf) * 4;
  if (tcp_hdr_len < 20 || tcp_hdr_len > 60)
    return 0;
  off += tcp_hdr_len;

  /* TLS Record header (5 bytes): content_type | version[2] | length[2] */
  if ((void *)((__u8 *)data + off + 5) > data_end)
    return 0;
  if (*((__u8 *)data + off) != 0x16) /* not a TLS Handshake record */
    return 0;
  off += 5;

  /* TLS Handshake header (4 bytes): type | length[3] */
  if ((void *)((__u8 *)data + off + 4) > data_end)
    return 0;
  if (*((__u8 *)data + off) != 0x01) /* not ClientHello */
    return 0;
  off += 4;

  /* ClientHello fixed prefix: legacy_version[2] + random[32] = 34 bytes */
  off += 34;

  /* session_id_length[1] + session_id[0..32] */
  if (off > 0x3000)
    return 0;
  if ((void *)((__u8 *)data + off + 1) > data_end)
    return 0;
  __u8 sil = *((__u8 *)data + off);
  if (sil > 32)
    return 0;
  off += 1 + sil;
  if (off > 0x3000)
    return 0;

  /* cipher_suites_length[2] + cipher_suites */
  if ((void *)((__u8 *)data + off + 2) > data_end)
    return 0;
  __u16 csl = ((__u16)(*((__u8 *)data + off)) << 8) | *((__u8 *)data + off + 1);
  if (csl < 2 || csl > 512)
    return 0;
  off += 2 + csl;
  if (off > 0x3000)
    return 0;

  /* compression_methods_length[1] + compression_methods */
  if ((void *)((__u8 *)data + off + 1) > data_end)
    return 0;
  __u8 cml = *((__u8 *)data + off);
  off += 1 + cml;
  if (off > 0x3000)
    return 0;

  /* extensions_length[2] */
  if ((void *)((__u8 *)data + off + 2) > data_end)
    return 0;
  __u16 ext_total =
      ((__u16)(*((__u8 *)data + off)) << 8) | *((__u8 *)data + off + 1);
  if (ext_total == 0)
    return 0;
  off += 2;

  __u32 ext_end = off + ext_total;
  if (ext_end > 0x4000)
    ext_end = 0x4000;

  /* Extension scan: integer accumulator + per-iteration packet pointer rebuild.
   *
   * Maintaining cur as a packet pointer accumulator (cur = cur4 + ext_len)
   * fails because:
   *   (a) adding a runtime variable to a pkt_ptr always resets r to 0, and
   *   (b) pkt_ptr vs pkt_ptr comparisons do not narrow the tnum (var_off),
   *       so var_off grows unboundedly across iterations.
   *
   * Instead, cur_off is kept as a scalar integer.  Scalar comparisons against
   * the constant 0x3000 DO narrow the tnum to (0x0;0x3fff) in the fall-through
   * path.  At each iteration we rebuild cur4 = data + cur_off + 4 from the
   * freshly-narrowed integer; this gives cur4 a bounded var_off so that the
   * verifier can propagate r after the bounds check.
   *
   * The asm barrier on cur4 forces the compiler to use the post-bounds-check
   * cur4 register for cur4[-N] accesses, not a pre-check alias.  After
   * cur4 <= data_end the shared id between cur4 and (cur4-4) gives r(cur4-4)=4,
   * making cur4[-4...-1] readable.  cur4[2..4] become readable after the
   * sni_hdr check (cur4+5 <= data_end => r(cur4) >= 5).
   */
  __u32 cur_off = off; /* scalar; var_off already narrowed by prior guards */
  const __u8 *elim = (__u8 *)data + ext_end;

#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_TLS_EXTENSIONS; i++) {
    /* Scalar comparisons narrow cur_off tnum to (0x0;0x3fff) in fall-through */
    if (cur_off + 4 > ext_end || cur_off > 0x3000)
      break;

    /* Rebuild packet pointer fresh from the tnum-narrowed integer.
     *
     * The compiler proves cur_off <= 0x3000 from the guard above and
     * eliminates any direct "& 0x3fff" as a no-op.  We must defeat that
     * optimisation so that a real AND instruction is emitted: the BPF
     * verifier narrows tnum only when it sees the AND opcode, not from
     * C-level range analysis.  The asm barrier makes the compiler treat
     * safe_off as having an unknown value, after which "&= 0x3fff" is
     * kept and the verifier sees tnum=(0x0;0x3fff). */
    __u32 safe_off = cur_off;
    __asm__ volatile("" : "+r"(safe_off));
    safe_off &= 0x3fff;
    __u8 *cur4 = (__u8 *)data + safe_off + 4;
    if ((void *)cur4 > data_end || cur4 > elim)
      break;
    __asm__("" : "+r"(cur4));

    __u16 ext_type = ((__u16)cur4[-4] << 8) | cur4[-3];
    __u16 ext_len = ((__u16)cur4[-2] << 8) | cur4[-1];

    if (ext_type == 0x0000) {
      /* SNI extension layout:
       *   list_len[2] | name_type[1] | name_len[2] | hostname[name_len]
       * cur4 points 4 bytes past the extension header start, so:
       *   cur4[2] = name_type, cur4[3..4] = name_len
       *   sni_hdr = cur4 + 5 = start of hostname bytes */
      __u8 *sni_hdr = cur4 + 5;
      /* sni_hdr bounds check also proves cur4[2..4] are readable (r(cur4)=5) */
      if ((void *)sni_hdr > data_end || sni_hdr > elim)
        break;
      if (cur4[2] != 0x00) /* name_type must be host_name (0) */
        break;
      __u16 hn_len = ((__u16)cur4[3] << 8) | cur4[4];
      if (hn_len == 0 || hn_len >= MAX_SNI_LEN)
        break;

      if (rule->sni_match_type == SNI_MATCH_EXACT) {
        /* Length mismatch → definitively a different hostname → -1 */
        if (hn_len != (__u32)rule->sni_len)
          return -1;
        /* Per-byte bounds check, mirroring the SUFFIX branch.  An earlier
         * version hoisted one bulk `sni_hdr + MAX_SNI_LEN <= data_end` check
         * here for verifier efficiency, but that required 128 bytes of
         * accessible data past the hostname even when hn_len was much
         * smaller — making short synthetic ClientHellos (and any real CH
         * whose payload ends shortly after the SNI extension) fail to
         * match.  Each iteration's bounds check (b+1 <= data_end) extends
         * r(sni_hdr) by 1, so subsequent iterations stay safe. */
#pragma unroll
        for (int j = 0; j < MAX_SNI_LEN; j++) {
          if ((__u32)j < hn_len) {
            __u8 *b = sni_hdr + j;
            if ((void *)(b + 1) > data_end)
              return 0;
            if ((char)(*b) != rule->sni_pattern[j])
              return -1;
          }
        }
        return 1;

      } else if (rule->sni_match_type == SNI_MATCH_SUFFIX) {
        /* hn must end with ".<pattern>": dot at position dot_pos = hn_len -
         * sni_len - 1, followed by sni_len bytes matching rule->sni_pattern. */
        __u32 sni_len = (__u32)rule->sni_len;
        /* Invalid rule config or hostname too short → no match → -1 */
        if (sni_len == 0 || sni_len >= MAX_SNI_LEN)
          return -1;
        if (hn_len <= sni_len + 1)
          return -1;
        __u32 dot_pos = hn_len - sni_len - 1;
        /* Explicit bound so the verifier sees umax(dot_pos) = MAX_SNI_LEN-1,
         * giving r(sni_hdr + dot_pos) = MAX_SNI_LEN - (MAX_SNI_LEN-1) = 1. */
        if (dot_pos >= MAX_SNI_LEN)
          return -1;
        /* Adding a runtime variable to a packet pointer always resets r to 0
         * in the BPF verifier, regardless of bounds.  Establish r >= 1 for
         * dot_ptr with an explicit bounds check before the first access. */
        __u8 *dot_ptr = sni_hdr + dot_pos;
        /* Packet truncated before we can read the dot → treat as parse error */
        if ((void *)(dot_ptr + 1) > data_end)
          return 0;
        /* No dot at expected position → different hostname structure → -1 */
        if ((char)dot_ptr[0] != '.')
          return -1;
        /* Suffix comparison loop.  dot_ptr starts with r=1.  Each iteration's
         * bounds check (b+1 <= data_end) extends r(dot_ptr) by 1, so the next
         * iteration's b = dot_ptr + 1 + j also passes its bounds check. */
#pragma unroll
        for (int j = 0; j < MAX_SNI_LEN; j++) {
          if ((__u32)j < sni_len) {
            __u8 *b = dot_ptr + 1 + j;
            /* Packet truncated during suffix read → parse error */
            if ((void *)(b + 1) > data_end)
              return 0;
            /* Byte mismatch → different suffix → -1 */
            if ((char)(*b) != rule->sni_pattern[j])
              return -1;
          }
        }
        return 1;
      }
      break;
    }

    if (ext_len > 0x3000)
      break;
    cur_off += 4 + ext_len;
    if (cur_off > ext_end || cur_off > 0x3000)
      break;
  }
  return 0;
}

/*
 * Source LPM trie key (two-level LPM), scoped per-interface.
 *
 * The LPM trie descends bit-by-bit from the MSB of the bytes following
 * `prefixlen`. Because `ifindex` sits before `addr` in memory, the trie first
 * exact-matches the 32-bit ifindex, then longest-prefix-matches on the address.
 *
 * `prefixlen` encoding: 32 (exact ifindex) + address prefix bits. So for v4
 * the valid range is 32..64; for v6 it is 32..160. Ancestor walks decrement
 * by 1 bit as today, but MUST NOT go below 32 — ifindex must always be exact.
 */
struct src_lpm_key_v4 {
  __u32 prefixlen; /* 32..64: 32 ifindex bits + 0..32 addr bits */
  __u32 ifindex;   /* host-order interface index (exact match) */
  __u32 addr;      /* IPv4 address in network byte order */
} __attribute__((packed));

struct src_lpm_key_v6 {
  __u32 prefixlen; /* 32..160: 32 ifindex bits + 0..128 addr bits */
  __u32 ifindex;   /* host-order interface index (exact match) */
  __u32 addr[4];   /* IPv6 address (128 bits) in network byte order */
} __attribute__((packed));

/*
 * Source LPM trie value (two-level LPM).
 * src_prefixlen records the stored prefix length so the BPF ancestor walk can
 * construct the next query: next_prefixlen = src_prefixlen - 1.
 *
 * src_prefixlen is stored WITHOUT the 32-bit ifindex offset — it is the
 * original address prefix length (0..32 for v4, 0..128 for v6).
 */
struct src_lpm_value {
  __u32 src_prefixlen; /* stored address prefix length (no ifindex offset) */
  __u32 src_group_id;  /* key into src_groups_v4/v6 HASH_OF_MAPS */
} __attribute__((packed));

/* MAC match flag bits for l4_rule.mac_match_flags */
#define MAC_MATCH_SRC (1 << 0) /* check source MAC against mac_rules sidecar map */
#define MAC_MATCH_DST (1 << 1) /* check dest MAC against mac_rules sidecar map */

/*
 * MAC rule entry stored in the mac_rules / tc_mac_rules map (keyed by rule_id).
 * Looked up when l4_rule.mac_match_flags != 0 to retrieve the MAC addresses
 * to match against the packet's Ethernet header.
 */
struct mac_rule_entry {
  __u8 src_mac[6]; /* Source MAC to match (all-zeros = any) */
  __u8 dst_mac[6]; /* Dest MAC to match (all-zeros = any) */
} __attribute__((packed));

/*
 * L4 match rule — terminal entry at the bottom of the two-level LPM lookup.
 * Contains match criteria (protocol, ports) and the ordered policy actions.
 * sni_match_type != SNI_MATCH_NONE triggers the SNI tail call path.
 * mac_match_flags != 0 triggers a sidecar mac_rules map lookup for L2 matching.
 *
 * Layout (96 bytes, packed):
 *   offset  0: sport, dport, protocol, sni_match_type, num_actions,
 *              mac_match_flags
 *   offset  8: rule_id
 *   offset 16: flags, tail_call_idx, quic_version, _pad2
 *   offset 32: actions[MAX_ACTIONS_PER_RULE]
 */
struct l4_rule {
  __u16 sport;                                      /* Source port (0 = any) */
  __u16 dport;                                      /* Destination port (0 = any) */
  __u8 protocol;                                    /* IP protocol (0 = any) */
  __u8 sni_match_type;                              /* SNI_MATCH_NONE / EXACT / SUFFIX */
  __u8 num_actions;                                 /* Number of valid entries in actions[] */
  __u8 mac_match_flags;                             /* MAC_MATCH_SRC | MAC_MATCH_DST; 0 = no L2 filter */
  __u64 rule_id;                                    /* Unique rule identifier */
  __u32 flags;                                      /* Policy flags (e.g. POLICY_FLAG_INSPECT) */
  __u32 tail_call_idx;                              /* Tail call program index */
  __u32 quic_version;                               /* QUIC version filter (0=off, QUIC_VERSION_* constants) */
  __u32 _pad2;                                      /* Reserved */
  struct rule_action actions[MAX_ACTIONS_PER_RULE]; /* offset 32 */
} __attribute__((packed));

/*
 * Destination LPM trie value (two-level LPM).
 * dst_prefixlen records the stored prefix length for the ancestor walk.
 * rules[] is sorted by priority ascending (lower priority number = first
 * match).
 */
struct dst_lpm_value {
  __u32 dst_prefixlen; /* stored prefix length of this entry */
  __u8 count;          /* number of valid rules (0..MAX_L4_RULES) */
  __u8 _pad[3];
  struct l4_rule rules[MAX_L4_RULES];
} __attribute__((packed));

/*
 * L4 match helper: returns 1 if the packet's L4 fields match the rule.
 * Protocol 0 and port 0 are wildcards ("any").
 */
static __always_inline int match_l4(const struct flow_key *pkt,
                                    const struct l4_rule *rule) {
  if (rule->protocol != 0 && rule->protocol != pkt->protocol)
    return 0;
  if (rule->sport != 0 && rule->sport != pkt->sport)
    return 0;
  if (rule->dport != 0 && rule->dport != pkt->dport)
    return 0;
  return 1;
}

/*
 * MAC match helper: returns 1 if the packet's L2 addresses satisfy the MAC
 * criteria stored in a mac_rule_entry sidecar map entry.
 *
 * mac_match_flags: MAC_MATCH_SRC | MAC_MATCH_DST bits from the l4_rule.
 * me:              pointer to the mac_rule_entry looked up by rule_id.
 *
 * An all-zeros MAC with the corresponding flag set is a wildcard that matches
 * any address.  Callers guard with `rule->mac_match_flags != 0` before
 * doing the sidecar map lookup, so the common no-MAC case has zero overhead.
 *
 * Marked __always_inline so it is inlined into the __noinline lookup_policy_v2
 * / tc_lookup_policy_v2 subprograms, where the pointer types are known.
 */
static __always_inline int match_mac(const __u8 *pkt_src, const __u8 *pkt_dst,
                                     __u8 mac_match_flags,
                                     const struct mac_rule_entry *me) {
  if (mac_match_flags & MAC_MATCH_SRC) {
    __u8 is_any = (me->src_mac[0] | me->src_mac[1] | me->src_mac[2] |
                   me->src_mac[3] | me->src_mac[4] | me->src_mac[5]) == 0;
    if (!is_any &&
        (me->src_mac[0] != pkt_src[0] || me->src_mac[1] != pkt_src[1] ||
         me->src_mac[2] != pkt_src[2] || me->src_mac[3] != pkt_src[3] ||
         me->src_mac[4] != pkt_src[4] || me->src_mac[5] != pkt_src[5]))
      return 0;
  }
  if (mac_match_flags & MAC_MATCH_DST) {
    __u8 is_any = (me->dst_mac[0] | me->dst_mac[1] | me->dst_mac[2] |
                   me->dst_mac[3] | me->dst_mac[4] | me->dst_mac[5]) == 0;
    if (!is_any &&
        (me->dst_mac[0] != pkt_dst[0] || me->dst_mac[1] != pkt_dst[1] ||
         me->dst_mac[2] != pkt_dst[2] || me->dst_mac[3] != pkt_dst[3] ||
         me->dst_mac[4] != pkt_dst[4] || me->dst_mac[5] != pkt_dst[5]))
      return 0;
  }
  return 1;
}

/*
 * Try to detect QUIC and set FLOW_FLAG_QUIC / FLOW_FLAG_QUIC_V1/V2 in *flags.
 * udp_payload_off: byte offset of the first UDP payload byte from data start.
 * Reads 5 bytes: 1 (first-byte header) + 4 (version field in Long Header).
 * Kept __always_inline so it is inlined into its caller's noinline frame and
 * avoids an extra BPF-to-BPF call on the UDP path.
 */
static __always_inline void parse_quic_flags(void *data, const void *data_end,
                                             __u32 udp_payload_off,
                                             __u16 *flags) {
  __u8 *p = (__u8 *)data + udp_payload_off;
  if ((void *)(p + 5) > data_end)
    return;

  __u8 first = p[0];

  /* Long Header: bit 7=1 (long), fixed bit 6=1 → mask 0xC0 matches 0xC0 */
  if ((first & 0xC0) == 0xC0) {
    __u32 version =
        ((__u32)p[1] << 24) | ((__u32)p[2] << 16) | ((__u32)p[3] << 8) | p[4];
    *flags |= FLOW_FLAG_QUIC;
    if (version == QUIC_VERSION_V1)
      *flags |= FLOW_FLAG_QUIC_V1;
    else if (version == QUIC_VERSION_V2)
      *flags |= FLOW_FLAG_QUIC_V2;
  } else if ((first & 0xC0) == 0x40) {
    /* Short Header (1-RTT): bit 7=0, fixed bit 6=1 — no version field */
    *flags |= FLOW_FLAG_QUIC;
  }
}

/*
 * Check whether the packet's QUIC version satisfies the rule's quic_version
 * filter.  Returns 1 if the rule matches, 0 if it does not.
 *
 * rule->quic_version == 0            → no QUIC filter (always matches)
 * rule->quic_version == QUIC_VERSION_ANY → packet must be QUIC (any version)
 * rule->quic_version == QUIC_VERSION_V1  → packet must be QUIC v1
 * rule->quic_version == QUIC_VERSION_V2  → packet must be QUIC v2
 */
static __always_inline int match_quic_version(__u16 pkt_flags,
                                              __u32 rule_quic_version) {
  if (rule_quic_version == 0)
    return 1; /* no QUIC filter — always matches */
  if (!(pkt_flags & FLOW_FLAG_QUIC))
    return 0; /* rule wants QUIC but packet is not QUIC */
  if (rule_quic_version == QUIC_VERSION_V1 && !(pkt_flags & FLOW_FLAG_QUIC_V1))
    return 0;
  if (rule_quic_version == QUIC_VERSION_V2 && !(pkt_flags & FLOW_FLAG_QUIC_V2))
    return 0;
  return 1;
}

/*
 * Parse L3 and L4 headers and populate the flow key.
 *
 * data / data_end : packet bounds (void * for BPF-to-BPF call compatibility).
 * l3_hdr          : pointer to the first byte of the L3 header.
 * l3_off          : scalar byte offset of l3_hdr from the packet start — used
 *                   to compute L4 offsets without pkt() pointer subtraction.
 * eth_proto       : EtherType of the L3 payload (ETH_P_IP or ETH_P_IPV6).
 * key             : flow key to populate; caller must zero it beforehand.
 *
 * Returns the byte offset of the L4 header on success, PARSE_NONFIRST_FRAG
 * for non-first fragments, or -1 on error / unsupported EtherType.
 *
 * __noinline keeps callers (parse_packet, tc_parse_packet) within the LLVM
 * BPF branch-offset limit.
 */
static __noinline int parse_l3l4(void *data, const void *data_end, int l3_off,
                                 __u16 eth_proto, struct flow_key *key) {
  void *l3_hdr = (__u8 *)data + l3_off;

  if (eth_proto == ETH_P_IP) {
    struct iphdr *iph = l3_hdr;
    if ((void *)(iph + 1) > data_end)
      return -1;

    key->af = AF_INET;
    key->saddr4 = iph->saddr;
    key->daddr4 = iph->daddr;
    key->protocol = iph->protocol;

    __u32 iph_len = iph->ihl * 4;
    if (iph_len < sizeof(*iph))
      return -1;

    /* Use tot_len (not data_end) for L4 size checks: Ethernet pads frames to
     * a 60-byte minimum, so data_end can be larger than the actual IP payload,
     * making truncated L4 headers appear in-bounds when they are not. */
    __u32 ip_tot_len = bpf_ntohs(iph->tot_len);
    if (ip_tot_len < iph_len)
      return -1;
    __u32 l4_len = ip_tot_len - iph_len;

    void *l4_hdr = (__u8 *)iph + iph_len;
    /* Pure scalar arithmetic — avoids pkt() pointer subtraction that the BPF
     * verifier rejects when zero-extended via <<= 32. */
    int l4_off = l3_off + (__s32)iph_len;

    /* IPv4 fragment detection.
     * Non-zero IP_OFFSET means a non-first fragment (no L4 header).
     * IP_MF set with offset==0 means the first fragment (L4 header present). */
    __u16 frag_info = bpf_ntohs(iph->frag_off);
    if (frag_info & IP_OFFSET) {
      key->flags |= FLOW_FLAG_FRAGMENT;
      return PARSE_NONFIRST_FRAG;
    }
    if (frag_info & IP_MF)
      key->flags |= FLOW_FLAG_FRAGMENT;

    if (key->protocol == IPPROTO_TCP) {
      if (l4_len < sizeof(struct tcphdr))
        return -1;
      struct tcphdr *tcph = l4_hdr;
      if ((void *)(tcph + 1) > data_end)
        return -1;
      key->sport = bpf_ntohs(tcph->source);
      key->dport = bpf_ntohs(tcph->dest);
    } else if (key->protocol == IPPROTO_UDP) {
      if (l4_len < sizeof(struct udphdr))
        return -1;
      struct udphdr *udph = l4_hdr;
      if ((void *)(udph + 1) > data_end)
        return -1;
      key->sport = bpf_ntohs(udph->source);
      key->dport = bpf_ntohs(udph->dest);
      /* QUIC detection: read first bytes of UDP payload.
       * Temporary variable avoids taking address of packed struct member. */
      __u16 f = key->flags;
      __u32 pay_off = (__u32)l4_off + (__u32)sizeof(struct udphdr);
      parse_quic_flags(data, data_end, pay_off, &f);
      key->flags = f;
    } else if (key->protocol == IPPROTO_ICMP) {
      if (l4_len < sizeof(struct icmphdr))
        return -1;
      struct icmphdr *icmph = l4_hdr;
      if ((void *)(icmph + 1) > data_end)
        return -1;
      /* Use ICMP type/code as pseudo-ports for rule matching. */
      key->sport = (__u16)icmph->type;
      key->dport = (__u16)icmph->code;
    }
    /* Other protocols: ports remain 0 */
    return l4_off;

  } else if (eth_proto == ETH_P_IPV6) {
    struct ipv6hdr *ip6h = l3_hdr;
    if ((void *)(ip6h + 1) > data_end)
      return -1;

    key->af = AF_INET6;
    __builtin_memcpy(key->saddr6, &ip6h->saddr, 16);
    __builtin_memcpy(key->daddr6, &ip6h->daddr, 16);
    key->protocol = ip6h->nexthdr;

    void *l4_hdr = (void *)(ip6h + 1);
    int l4_off = l3_off + (__s32)sizeof(*ip6h);

    /* Handle IPv6 fragment extension header (Next Header = 44).
     * The presence of the header means the datagram is fragmented; mark the
     * flow key for all fragments so every event shows the 'F' flag. */
    if (key->protocol == IPPROTO_FRAGMENT) {
      struct ipv6_frag_hdr *fraghdr = l4_hdr;
      if ((void *)(fraghdr + 1) > data_end)
        return -1;

      key->protocol = fraghdr->nexthdr;
      __u16 frag_off_val = bpf_ntohs(fraghdr->frag_off);

      l4_hdr = (void *)(fraghdr + 1);
      l4_off += (__s32)sizeof(struct ipv6_frag_hdr);

      key->flags |= FLOW_FLAG_FRAGMENT;

      /* Fragment offset in bits 15:3; non-zero → not the first fragment. */
      if (frag_off_val >> 3)
        return PARSE_NONFIRST_FRAG;
    }

    /* TODO: Handle other IPv6 extension headers */

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
      __u16 f = key->flags;
      __u32 pay_off = (__u32)l4_off + (__u32)sizeof(struct udphdr);
      parse_quic_flags(data, data_end, pay_off, &f);
      key->flags = f;
    } else if (key->protocol == IPPROTO_ICMPV6) {
      struct icmp6hdr *icmp6h = l4_hdr;
      if ((void *)(icmp6h + 1) > data_end)
        return -1;
      key->sport = (__u16)icmp6h->icmp6_type;
      key->dport = (__u16)icmp6h->icmp6_code;
    }
    return l4_off;
  }

  /* Non-IP traffic */
  return -1;
}

/*
 * Update action statistics for a matched rule or verdict-cache hit.
 * Accepts a pre-looked-up global_stats pointer to avoid redundant map lookups.
 * Always call from a single location per code path to avoid double-counting.
 */
static __always_inline void update_action_stats(struct global_stats *stats,
                                                __u32 action) {
  if (!stats)
    return;

  switch (action) {
  case ACTION_PASS:
  case ACTION_LOG:
    stats->policy_pass++;
    break;
  case ACTION_DROP:
    stats->policy_drops++;
    break;
#ifdef SURICATA_IPS
  case ACTION_INSPECT:
    stats->policy_pass++;
    stats->inspect_redirects++;
    break;
#endif
  }
}

#endif /* __POLICY_COMMON_H__ */
