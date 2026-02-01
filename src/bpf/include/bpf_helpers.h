/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * BPF helper function definitions for policy engine
 */

#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include "vmlinux_subset.h"

/* Compiler attributes */
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))
#define __weak __attribute__((weak))

/* Section markers */
#define SEC(name)                                                              \
  _Pragma("GCC diagnostic push")                                               \
      _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")               \
          __attribute__((section(name), used)) _Pragma("GCC diagnostic pop")

/* Character marker for license */
#define __char(x) static const char __license[] SEC("license") = x

/* Clang builtins */
#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

/* Byte order conversions */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_ntohl(x) __builtin_bswap32(x)
#define __bpf_htonl(x) __builtin_bswap32(x)
#define __bpf_be64_to_cpu(x) __builtin_bswap64(x)
#define __bpf_cpu_to_be64(x) __builtin_bswap64(x)
#else
#define __bpf_ntohs(x) (x)
#define __bpf_htons(x) (x)
#define __bpf_ntohl(x) (x)
#define __bpf_htonl(x) (x)
#define __bpf_be64_to_cpu(x) (x)
#define __bpf_cpu_to_be64(x) (x)
#endif

#define bpf_ntohs(x) __bpf_ntohs(x)
#define bpf_htons(x) __bpf_htons(x)
#define bpf_ntohl(x) __bpf_ntohl(x)
#define bpf_htonl(x) __bpf_htonl(x)

/* BPF map types */
enum bpf_map_type {
  BPF_MAP_TYPE_UNSPEC,
  BPF_MAP_TYPE_HASH,
  BPF_MAP_TYPE_ARRAY,
  BPF_MAP_TYPE_PROG_ARRAY,
  BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  BPF_MAP_TYPE_PERCPU_HASH,
  BPF_MAP_TYPE_PERCPU_ARRAY,
  BPF_MAP_TYPE_STACK_TRACE,
  BPF_MAP_TYPE_CGROUP_ARRAY,
  BPF_MAP_TYPE_LRU_HASH,
  BPF_MAP_TYPE_LRU_PERCPU_HASH,
  BPF_MAP_TYPE_LPM_TRIE,
  BPF_MAP_TYPE_ARRAY_OF_MAPS,
  BPF_MAP_TYPE_HASH_OF_MAPS,
  BPF_MAP_TYPE_DEVMAP,
  BPF_MAP_TYPE_SOCKMAP,
  BPF_MAP_TYPE_CPUMAP,
  BPF_MAP_TYPE_XSKMAP,
  BPF_MAP_TYPE_SOCKHASH,
  BPF_MAP_TYPE_CGROUP_STORAGE,
  BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
  BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
  BPF_MAP_TYPE_QUEUE,
  BPF_MAP_TYPE_STACK,
  BPF_MAP_TYPE_SK_STORAGE,
  BPF_MAP_TYPE_DEVMAP_HASH,
  BPF_MAP_TYPE_STRUCT_OPS,
  BPF_MAP_TYPE_RINGBUF,
  BPF_MAP_TYPE_INODE_STORAGE,
  BPF_MAP_TYPE_TASK_STORAGE,
  BPF_MAP_TYPE_BLOOM_FILTER,
};

/* Map definition macro (libbpf style) */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* BPF helper function declarations */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, __u32 size,
                              const void *unsafe_ptr) = (void *)4;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size,
                                ...) = (void *)6;
static __u32 (*bpf_get_prandom_u32)(void) = (void *)7;
static __u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static long (*bpf_skb_store_bytes)(void *skb, __u32 offset, const void *from,
                                   __u32 len, __u64 flags) = (void *)9;
static long (*bpf_l3_csum_replace)(void *skb, __u32 offset, __u64 from,
                                   __u64 to, __u64 size) = (void *)10;
static long (*bpf_l4_csum_replace)(void *skb, __u32 offset, __u64 from,
                                   __u64 to, __u64 flags) = (void *)11;
static long (*bpf_tail_call)(void *ctx, void *prog_array_map,
                             __u32 index) = (void *)12;
static long (*bpf_clone_redirect)(void *skb, __u32 ifindex,
                                  __u64 flags) = (void *)13;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static __u32 (*bpf_get_cgroup_classid)(void *skb) = (void *)17;
static long (*bpf_skb_vlan_push)(void *skb, __be16 vlan_proto,
                                 __u16 vlan_tci) = (void *)18;
static long (*bpf_skb_vlan_pop)(void *skb) = (void *)19;
static long (*bpf_skb_get_tunnel_key)(void *skb, void *key, __u32 size,
                                      __u64 flags) = (void *)20;
static long (*bpf_skb_set_tunnel_key)(void *skb, void *key, __u32 size,
                                      __u64 flags) = (void *)21;
static __u64 (*bpf_perf_event_read)(void *map, __u64 flags) = (void *)22;
static long (*bpf_redirect)(int ifindex, __u64 flags) = (void *)23;
static __u32 (*bpf_get_route_realm)(void *skb) = (void *)24;
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags,
                                     void *data, __u64 size) = (void *)25;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to,
                                  __u32 len) = (void *)26;
static long (*bpf_get_stackid)(void *ctx, void *map, __u64 flags) = (void *)27;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to,
                              __u32 to_size, __wsum seed) = (void *)28;
static long (*bpf_skb_get_tunnel_opt)(void *skb, void *opt,
                                      __u32 size) = (void *)29;
static long (*bpf_skb_set_tunnel_opt)(void *skb, void *opt,
                                      __u32 size) = (void *)30;
static long (*bpf_skb_change_proto)(void *skb, __be16 proto,
                                    __u64 flags) = (void *)31;
static long (*bpf_skb_change_type)(void *skb, __u32 type) = (void *)32;
static long (*bpf_skb_under_cgroup)(void *skb, void *map,
                                    __u32 index) = (void *)33;
static __u32 (*bpf_get_hash_recalc)(void *skb) = (void *)34;
static __u64 (*bpf_get_current_task)(void) = (void *)35;
static long (*bpf_probe_write_user)(void *dst, const void *src,
                                    __u32 len) = (void *)36;
static long (*bpf_current_task_under_cgroup)(void *map,
                                             __u32 index) = (void *)37;
static long (*bpf_skb_change_tail)(void *skb, __u32 len,
                                   __u64 flags) = (void *)38;
static long (*bpf_skb_pull_data)(void *skb, __u32 len) = (void *)39;
static __s64 (*bpf_csum_update)(void *skb, __wsum csum) = (void *)40;
static void (*bpf_set_hash_invalid)(void *skb) = (void *)41;
static long (*bpf_get_numa_node_id)(void) = (void *)42;
static long (*bpf_skb_change_head)(void *skb, __u32 len,
                                   __u64 flags) = (void *)43;
static long (*bpf_xdp_adjust_head)(void *xdp_md, int delta) = (void *)44;
static long (*bpf_probe_read_str)(void *dst, __u32 size,
                                  const void *unsafe_ptr) = (void *)45;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)46;
static __u32 (*bpf_get_socket_uid)(void *skb) = (void *)47;
static long (*bpf_set_hash)(void *skb, __u32 hash) = (void *)48;
static long (*bpf_setsockopt)(void *bpf_socket, int level, int optname,
                              void *optval, int optlen) = (void *)49;
static long (*bpf_skb_adjust_room)(void *skb, __s32 len_diff, __u32 mode,
                                   __u64 flags) = (void *)50;
static long (*bpf_redirect_map)(void *map, __u32 key, __u64 flags) = (void *)51;
static long (*bpf_sk_redirect_map)(void *skb, void *map, __u32 key,
                                   __u64 flags) = (void *)52;
static long (*bpf_sock_map_update)(void *skops, void *map, void *key,
                                   __u64 flags) = (void *)53;
static long (*bpf_xdp_adjust_meta)(void *xdp_md, int delta) = (void *)54;
static long (*bpf_perf_event_read_value)(void *map, __u64 flags, void *buf,
                                         __u32 buf_size) = (void *)55;
static long (*bpf_perf_prog_read_value)(void *ctx, void *buf,
                                        __u32 buf_size) = (void *)56;
static long (*bpf_getsockopt)(void *bpf_socket, int level, int optname,
                              void *optval, int optlen) = (void *)57;
static long (*bpf_override_return)(void *regs, __u64 rc) = (void *)58;
static long (*bpf_sock_ops_cb_flags_set)(void *bpf_sock,
                                         int argval) = (void *)59;
static long (*bpf_msg_redirect_map)(void *msg, void *map, __u32 key,
                                    __u64 flags) = (void *)60;
static long (*bpf_msg_apply_bytes)(void *msg, __u32 bytes) = (void *)61;
static long (*bpf_msg_cork_bytes)(void *msg, __u32 bytes) = (void *)62;
static long (*bpf_msg_pull_data)(void *msg, __u32 start, __u32 end,
                                 __u64 flags) = (void *)63;
static long (*bpf_bind)(void *ctx, void *addr, int addr_len) = (void *)64;
static long (*bpf_xdp_adjust_tail)(void *xdp_md, int delta) = (void *)65;
static long (*bpf_skb_get_xfrm_state)(void *skb, __u32 index, void *xfrm_state,
                                      __u32 size, __u64 flags) = (void *)66;
static long (*bpf_get_stack)(void *ctx, void *buf, __u32 size,
                             __u64 flags) = (void *)67;
static long (*bpf_skb_load_bytes_relative)(const void *skb, __u32 offset,
                                           void *to, __u32 len,
                                           __u32 start_header) = (void *)68;
static long (*bpf_fib_lookup)(void *ctx, void *params, int plen,
                              __u32 flags) = (void *)69;
static long (*bpf_sock_hash_update)(void *skops, void *map, void *key,
                                    __u64 flags) = (void *)70;
static long (*bpf_msg_redirect_hash)(void *msg, void *map, void *key,
                                     __u64 flags) = (void *)71;
static long (*bpf_sk_redirect_hash)(void *skb, void *map, void *key,
                                    __u64 flags) = (void *)72;
static long (*bpf_lwt_push_encap)(void *skb, __u32 type, void *hdr,
                                  __u32 len) = (void *)73;
static long (*bpf_lwt_seg6_store_bytes)(void *skb, __u32 offset,
                                        const void *from,
                                        __u32 len) = (void *)74;
static long (*bpf_lwt_seg6_adjust_srh)(void *skb, __u32 offset,
                                       __s32 delta) = (void *)75;
static long (*bpf_lwt_seg6_action)(void *skb, __u32 action, void *param,
                                   __u32 param_len) = (void *)76;
static long (*bpf_rc_repeat)(void *ctx) = (void *)77;
static long (*bpf_rc_keydown)(void *ctx, __u32 protocol, __u64 scancode,
                              __u32 toggle) = (void *)78;
static __u64 (*bpf_skb_cgroup_id)(void *skb) = (void *)79;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static void *(*bpf_get_local_storage)(void *map, __u64 flags) = (void *)81;
static long (*bpf_sk_select_reuseport)(void *reuse, void *map, void *key,
                                       __u64 flags) = (void *)82;
static __u64 (*bpf_skb_ancestor_cgroup_id)(void *skb,
                                           int ancestor_level) = (void *)83;
static void *(*bpf_sk_lookup_tcp)(void *ctx, void *tuple, __u32 tuple_size,
                                  __u64 netns, __u64 flags) = (void *)84;
static void *(*bpf_sk_lookup_udp)(void *ctx, void *tuple, __u32 tuple_size,
                                  __u64 netns, __u64 flags) = (void *)85;
static long (*bpf_sk_release)(void *sock) = (void *)86;
static long (*bpf_map_push_elem)(void *map, const void *value,
                                 __u64 flags) = (void *)87;
static long (*bpf_map_pop_elem)(void *map, void *value) = (void *)88;
static long (*bpf_map_peek_elem)(void *map, void *value) = (void *)89;
static long (*bpf_msg_push_data)(void *msg, __u32 start, __u32 len,
                                 __u64 flags) = (void *)90;
static long (*bpf_msg_pop_data)(void *msg, __u32 start, __u32 len,
                                __u64 flags) = (void *)91;
static long (*bpf_rc_pointer_rel)(void *ctx, __s32 rel_x,
                                  __s32 rel_y) = (void *)92;
static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;
static void *(*bpf_sk_fullsock)(void *sk) = (void *)95;
static void *(*bpf_tcp_sock)(void *sk) = (void *)96;
static long (*bpf_skb_ecn_set_ce)(void *skb) = (void *)97;
static void *(*bpf_get_listener_sock)(void *sk) = (void *)98;
static void *(*bpf_skc_lookup_tcp)(void *ctx, void *tuple, __u32 tuple_size,
                                   __u64 netns, __u64 flags) = (void *)99;
static long (*bpf_tcp_check_syncookie)(void *sk, void *iph, __u32 iph_len,
                                       void *th, __u32 th_len) = (void *)100;
static long (*bpf_sysctl_get_name)(void *ctx, char *buf, __u32 buf_len,
                                   __u64 flags) = (void *)101;
static long (*bpf_sysctl_get_current_value)(void *ctx, char *buf,
                                            __u32 buf_len) = (void *)102;
static long (*bpf_sysctl_get_new_value)(void *ctx, char *buf,
                                        __u32 buf_len) = (void *)103;
static long (*bpf_sysctl_set_new_value)(void *ctx, const char *buf,
                                        __u32 buf_len) = (void *)104;
static long (*bpf_strtol)(const char *buf, __u32 buf_len, __u64 flags,
                          long *res) = (void *)105;
static long (*bpf_strtoul)(const char *buf, __u32 buf_len, __u64 flags,
                           unsigned long *res) = (void *)106;
static void *(*bpf_sk_storage_get)(void *map, void *sk, void *value,
                                   __u64 flags) = (void *)107;
static long (*bpf_sk_storage_delete)(void *map, void *sk) = (void *)108;
static long (*bpf_send_signal)(__u32 sig) = (void *)109;
static __s64 (*bpf_tcp_gen_syncookie)(void *sk, void *iph, __u32 iph_len,
                                      void *th, __u32 th_len) = (void *)110;
static long (*bpf_skb_output)(void *ctx, void *map, __u64 flags, void *data,
                              __u64 size) = (void *)111;
static long (*bpf_probe_read_user)(void *dst, __u32 size,
                                   const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size,
                                     const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size,
                                       const void *unsafe_ptr) = (void *)114;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size,
                                         const void *unsafe_ptr) = (void *)115;
static long (*bpf_tcp_send_ack)(void *tp, __u32 rcv_nxt) = (void *)116;
static long (*bpf_send_signal_thread)(__u32 sig) = (void *)117;
static __u64 (*bpf_jiffies64)(void) = (void *)118;
static long (*bpf_read_branch_records)(void *ctx, void *buf, __u32 size,
                                       __u64 flags) = (void *)119;
static long (*bpf_get_ns_current_pid_tgid)(__u64 dev, __u64 ino, void *nsdata,
                                           __u32 size) = (void *)120;
static long (*bpf_xdp_output)(void *ctx, void *map, __u64 flags, void *data,
                              __u64 size) = (void *)121;
static __u64 (*bpf_get_netns_cookie)(void *ctx) = (void *)122;
static __u64 (*bpf_get_current_ancestor_cgroup_id)(int ancestor_level) =
    (void *)123;
static long (*bpf_sk_assign)(void *skb, void *sk, __u64 flags) = (void *)124;
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *)125;
static long (*bpf_seq_printf)(void *m, const char *fmt, __u32 fmt_size,
                              const void *data, __u32 data_len) = (void *)126;
static long (*bpf_seq_write)(void *m, const void *data,
                             __u32 len) = (void *)127;
static __u64 (*bpf_sk_cgroup_id)(void *sk) = (void *)128;
static __u64 (*bpf_sk_ancestor_cgroup_id)(void *sk,
                                          int ancestor_level) = (void *)129;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size,
                                  __u64 flags) = (void *)130;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
                                    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;
static __u64 (*bpf_ringbuf_query)(void *ringbuf, __u64 flags) = (void *)134;
static long (*bpf_csum_level)(void *skb, __u64 level) = (void *)135;
static void *(*bpf_skc_to_tcp6_sock)(void *sk) = (void *)136;
static void *(*bpf_skc_to_tcp_sock)(void *sk) = (void *)137;
static void *(*bpf_skc_to_tcp_timewait_sock)(void *sk) = (void *)138;
static void *(*bpf_skc_to_tcp_request_sock)(void *sk) = (void *)139;
static void *(*bpf_skc_to_udp6_sock)(void *sk) = (void *)140;
static long (*bpf_get_task_stack)(void *task, void *buf, __u32 size,
                                  __u64 flags) = (void *)141;

/* Bounded loop helper (kernel 5.17+, BPF helper ID 181).
 * The verifier analyses the callback body once regardless of nr_loops,
 * avoiding the state-space explosion that inline nested loops cause. */
typedef long (*bpf_callback_t)(__u32 index, void *ctx);
static long (*bpf_loop)(__u32 nr_loops, bpf_callback_t callback_fn,
                        void *callback_ctx, __u64 flags) = (void *)181;

/* XDP packet load/store helpers (kernel 5.19+, BPF helper IDs 188/189/190) */
static __u64 (*bpf_xdp_get_buff_len)(void *xdp_md) = (void *)188;
static long (*bpf_xdp_load_bytes)(void *xdp_md, __u32 offset, void *buf,
                                  __u32 len) = (void *)189;
static long (*bpf_xdp_store_bytes)(void *xdp_md, __u32 offset, void *buf,
                                   __u32 len) = (void *)190;

/* Flags for bpf_map_update_elem */
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2
#define BPF_F_LOCK 4

/* Flags for bpf_xdp_adjust_tail */
#define BPF_F_INGRESS (1ULL << 0)

/* Debug helper */
#define bpf_printk(fmt, ...)                                                   \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })

/* Barrier macros */
#define barrier() __asm__ __volatile__("" : : : "memory")
#define barrier_var(var) __asm__ __volatile__("" : : "r"(var))

#endif /* __BPF_HELPERS_H__ */
