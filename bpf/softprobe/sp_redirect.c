// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/pin_internal.h>
#include <common/preempt_guard.h>
#include <common/sockaddr.h>
#include <common/tp_info.h>
#include <common/trace_helpers.h>
#include <common/trace_parent.h>

#include <logger/bpf_dbg.h>
#include <pid/pid.h>
#include <pid/pid_helpers.h>
#include <shared/obi_ctx.h>

#include <softprobe/sp_types.h>

char __license[] SEC("license") = "Dual MIT/GPL";

volatile const u32 sp_obi_host_pid = 0;
volatile const u32 sp_obi_ns_pid = 0;
volatile const u32 sp_obi_ns_id = 0;
volatile const u16 sp_ingress_proxy_port = 0;
volatile const u16 sp_egress_proxy_port = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u8);
    __uint(max_entries, 16384);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_target_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u16);
    __type(value, u8);
    __uint(max_entries, 256);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_excluded_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, sp_orig_dst_t);
    __uint(max_entries, 65536);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_orig_dst SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, sp_tuple_key_t);
    __type(value, u64);
    __uint(max_entries, 65536);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_tuple_to_cookie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u16);
    __type(value, u16);
    __uint(max_entries, 1024);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_app_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 4);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_ingress_sockmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, sp_bypass_key_t);
    __type(value, u8);
    __uint(max_entries, 16384);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_obi_bypass_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 65536);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_sock_write_off SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __uint(pinning, OBI_PIN_INTERNAL);
} sp_write_ctx_events SEC(".maps");

static __always_inline bool sp_is_obi_self_task(const struct task_struct *task) {
    if (!task) {
        return false;
    }

    const u32 tgid = BPF_CORE_READ(task, tgid);
    if (sp_obi_host_pid != 0 && tgid == sp_obi_host_pid) {
        return true;
    }

    if (sp_obi_ns_pid != 0) {
        int ns_pid = 0;
        int ns_ppid = 0;
        u32 ns_id = 0;
        ns_pid_ppid((struct task_struct *)task, &ns_pid, &ns_ppid, &ns_id);
        if ((u32)ns_pid == sp_obi_ns_pid && (sp_obi_ns_id == 0 || ns_id == sp_obi_ns_id)) {
            return true;
        }
    }

    return false;
}

static __always_inline bool sp_is_target_task(const struct task_struct *task) {
    if (!task || sp_is_obi_self_task(task)) {
        return false;
    }

    const u32 tgid = BPF_CORE_READ(task, tgid);
    u64 host_key = (u64)tgid;
    if (bpf_map_lookup_elem(&sp_target_pids, &host_key) != NULL) {
        return true;
    }

    int ns_pid = 0;
    int ns_ppid = 0;
    u32 ns_id = 0;
    ns_pid_ppid((struct task_struct *)task, &ns_pid, &ns_ppid, &ns_id);

    u64 ns_key = ((u64)ns_id << 32) | (u32)ns_pid;
    if (bpf_map_lookup_elem(&sp_target_pids, &ns_key) != NULL) {
        return true;
    }

    // Cover children forked by a tracked target before userspace AllowPID updates sp_target_pids.
    const struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent && !sp_is_obi_self_task(parent)) {
        const u32 parent_tgid = BPF_CORE_READ(parent, tgid);
        u64 parent_host_key = (u64)parent_tgid;
        if (bpf_map_lookup_elem(&sp_target_pids, &parent_host_key) != NULL) {
            return true;
        }
        if (ns_ppid > 0) {
            u64 parent_ns_key = ((u64)ns_id << 32) | (u32)ns_ppid;
            if (bpf_map_lookup_elem(&sp_target_pids, &parent_ns_key) != NULL) {
                return true;
            }
        }
    }

    return false;
}

static __always_inline u32 sp_caller_pid(const struct task_struct *task) {
    if (!task) {
        return 0;
    }
    if (sp_obi_ns_id != 0) {
        int ns_pid = 0;
        int ns_ppid = 0;
        u32 ns_id = 0;
        ns_pid_ppid((struct task_struct *)task, &ns_pid, &ns_ppid, &ns_id);
        if (ns_id == sp_obi_ns_id && ns_pid > 0) {
            return (u32)ns_pid;
        }
    }
    return BPF_CORE_READ(task, tgid);
}

static __always_inline bool sp_port_excluded(u16 dport) {
    if (dport == 0 || dport == sp_egress_proxy_port || dport == sp_ingress_proxy_port) {
        return true;
    }
    return bpf_map_lookup_elem(&sp_excluded_ports, &dport) != NULL;
}

static __always_inline bool sp_is_ipv4_loopback(__be32 ip4) {
    return (bpf_ntohl(ip4) >> 24) == 127;
}

static __always_inline bool sp_is_ipv6_v4mapped(const __be32 ip6[4]) {
    return ip6[0] == 0 && ip6[1] == 0 && ip6[2] == bpf_htonl(0x0000ffff);
}

static __always_inline bool sp_is_ipv6_loopback(const __be32 ip6[4]) {
    if (ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0 && ip6[3] == bpf_htonl(1)) {
        return true;
    }
    if (sp_is_ipv6_v4mapped(ip6)) {
        return sp_is_ipv4_loopback(ip6[3]);
    }
    return false;
}

static __always_inline void sp_sock_addr_read_ip6(const struct bpf_sock_addr *ctx, __be32 ip6[4]) {
    u32 w0, w1, w2, w3;
    asm volatile("%[w0] = *(u32 *)(%[base] + %[o0])\n\t"
                 "%[w1] = *(u32 *)(%[base] + %[o1])\n\t"
                 "%[w2] = *(u32 *)(%[base] + %[o2])\n\t"
                 "%[w3] = *(u32 *)(%[base] + %[o3])"
                 : [w0] "=r"(w0), [w1] "=r"(w1), [w2] "=r"(w2), [w3] "=r"(w3)
                 : [base] "r"(ctx),
                   [o0] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 0),
                   [o1] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 4),
                   [o2] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 8),
                   [o3] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 12),
                   "m"(*ctx));
    ip6[0] = w0;
    ip6[1] = w1;
    ip6[2] = w2;
    ip6[3] = w3;
}

static __always_inline void
sp_sock_addr_write_ip6(struct bpf_sock_addr *ctx, __be32 w0, __be32 w1, __be32 w2, __be32 w3) {
    asm volatile("*(u32 *)(%[base] + %[o0]) = %[w0]\n\t"
                 "*(u32 *)(%[base] + %[o1]) = %[w1]\n\t"
                 "*(u32 *)(%[base] + %[o2]) = %[w2]\n\t"
                 "*(u32 *)(%[base] + %[o3]) = %[w3]"
                 : "=m"(*ctx)
                 : [base] "r"(ctx),
                   [w0] "r"((u32)w0),
                   [w1] "r"((u32)w1),
                   [w2] "r"((u32)w2),
                   [w3] "r"((u32)w3),
                   [o0] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 0),
                   [o1] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 4),
                   [o2] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 8),
                   [o3] "i"(offsetof(struct bpf_sock_addr, user_ip6) + 12));
}

SEC("cgroup/connect4")
int sp_connect4(struct bpf_sock_addr *ctx) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (sp_is_obi_self_task(task)) {
        return 1;
    }
    if (sp_egress_proxy_port == 0 || ctx->type != SOCK_STREAM) {
        return 1;
    }
    if (!sp_is_target_task(task)) {
        return 1;
    }

    const u16 dport = bpf_ntohs((u16)ctx->user_port);
    if (sp_port_excluded(dport)) {
        return 1;
    }
    if (sp_is_ipv4_loopback(ctx->user_ip4) && bpf_map_lookup_elem(&sp_app_ports, &dport) != NULL) {
        return 1;
    }

    const u64 cookie = bpf_get_socket_cookie(ctx);
    sp_orig_dst_t orig = {};
    __builtin_memcpy(orig.ip, &ctx->user_ip4, sizeof(ctx->user_ip4));
    orig.port = dport;
    orig.family = AF_INET;
    orig.pid = sp_caller_pid(task);

    bpf_map_update_elem(&sp_orig_dst, &cookie, &orig, BPF_ANY);
    u64 zero_off = 0;
    bpf_map_update_elem(&sp_sock_write_off, &cookie, &zero_off, BPF_NOEXIST);

    ctx->user_ip4 = bpf_htonl(0x7f000001);
    ctx->user_port = bpf_htons(sp_egress_proxy_port);
    return 1;
}

SEC("cgroup/connect6")
int sp_connect6(struct bpf_sock_addr *ctx) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (sp_is_obi_self_task(task)) {
        return 1;
    }
    if (sp_egress_proxy_port == 0 || ctx->type != SOCK_STREAM) {
        return 1;
    }
    if (!sp_is_target_task(task)) {
        return 1;
    }

    const u16 dport = bpf_ntohs((u16)ctx->user_port);
    if (sp_port_excluded(dport)) {
        return 1;
    }

    __be32 ip6[4] = {};
    sp_sock_addr_read_ip6(ctx, ip6);
    if (sp_is_ipv6_loopback(ip6) && bpf_map_lookup_elem(&sp_app_ports, &dport) != NULL) {
        return 1;
    }

    const u64 cookie = bpf_get_socket_cookie(ctx);
    sp_orig_dst_t orig = {};
    __builtin_memcpy(orig.ip, ip6, sizeof(ip6));
    orig.port = dport;
    orig.family = AF_INET6;
    orig.pid = sp_caller_pid(task);

    bpf_map_update_elem(&sp_orig_dst, &cookie, &orig, BPF_ANY);
    u64 zero_off = 0;
    bpf_map_update_elem(&sp_sock_write_off, &cookie, &zero_off, BPF_NOEXIST);

    if (sp_is_ipv6_v4mapped(ip6)) {
        sp_sock_addr_write_ip6(ctx, 0, 0, bpf_htonl(0x0000ffff), bpf_htonl(0x7f000001));
    } else {
        sp_sock_addr_write_ip6(ctx, 0, 0, 0, bpf_htonl(1));
    }
    ctx->user_port = bpf_htons(sp_egress_proxy_port);
    return 1;
}

SEC("cgroup/getpeername4")
int sp_getpeername4(struct bpf_sock_addr *ctx) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (sp_is_obi_self_task(task)) {
        return 1;
    }

    const u64 cookie = bpf_get_socket_cookie(ctx);
    const sp_orig_dst_t *orig = bpf_map_lookup_elem(&sp_orig_dst, &cookie);
    if (!orig || orig->family != AF_INET) {
        return 1;
    }

    __be32 ip4 = 0;
    __builtin_memcpy(&ip4, orig->ip, sizeof(ip4));
    ctx->user_ip4 = ip4;
    ctx->user_port = bpf_htons(orig->port);
    return 1;
}

SEC("cgroup/getpeername6")
int sp_getpeername6(struct bpf_sock_addr *ctx) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (sp_is_obi_self_task(task)) {
        return 1;
    }

    const u64 cookie = bpf_get_socket_cookie(ctx);
    const sp_orig_dst_t *orig = bpf_map_lookup_elem(&sp_orig_dst, &cookie);
    if (!orig || orig->family != AF_INET6) {
        return 1;
    }

    __be32 ip6[4] = {};
    __builtin_memcpy(ip6, orig->ip, sizeof(ip6));
    sp_sock_addr_write_ip6(ctx, ip6[0], ip6[1], ip6[2], ip6[3]);
    ctx->user_port = bpf_htons(orig->port);
    return 1;
}

static __always_inline void sp_record_bound_port(struct bpf_sock *ctx) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (sp_is_obi_self_task(task)) {
        return;
    }
    if (sp_ingress_proxy_port == 0 || ctx->type != SOCK_STREAM) {
        return;
    }
    if (!sp_is_target_task(task)) {
        return;
    }

    const u16 lport = (u16)ctx->src_port;
    if (sp_port_excluded(lport)) {
        return;
    }

    bpf_map_update_elem(&sp_app_ports, &lport, &lport, BPF_ANY);
}

SEC("cgroup/post_bind4")
int sp_post_bind4(struct bpf_sock *ctx) {
    sp_record_bound_port(ctx);
    return 1;
}

SEC("cgroup/post_bind6")
int sp_post_bind6(struct bpf_sock *ctx) {
    sp_record_bound_port(ctx);
    return 1;
}

SEC("sockops")
int sp_sockops(struct bpf_sock_ops *skops) {
    // uapi/linux/bpf.h: local_port is host byte order; remote_port is network-byte-order u32.
    const u16 lport = (u16)skops->local_port;
    const u16 rport = (u16)bpf_ntohl(skops->remote_port);

    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB: {
        // TCP_CONNECT_CB runs in syscall context where current_task owns the socket.
        const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
        if (sp_is_obi_self_task(task)) {
            if (lport != 0 && rport != 0 && bpf_map_lookup_elem(&sp_app_ports, &rport) != NULL) {
                sp_bypass_key_t bkey = {.client_port = lport, .target_port = rport};
                u8 one = 1;
                bpf_map_update_elem(&sp_obi_bypass_ports, &bkey, &one, BPF_ANY);
            }
            return 1;
        }

        const u64 cookie = bpf_get_socket_cookie(skops);
        if (bpf_map_lookup_elem(&sp_orig_dst, &cookie) != NULL && lport != 0 && rport != 0) {
            sp_tuple_key_t tkey = {.client_port = lport, .proxy_port = rport};
            bpf_map_update_elem(&sp_tuple_to_cookie, &tkey, &cookie, BPF_ANY);
        } else if (sp_is_target_task(task)) {
            u64 zero_off = 0;
            bpf_map_update_elem(&sp_sock_write_off, &cookie, &zero_off, BPF_NOEXIST);
        }
        break;
    }
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
        const u64 cookie = bpf_get_socket_cookie(skops);
        if (bpf_map_lookup_elem(&sp_orig_dst, &cookie) != NULL && lport != 0 && rport != 0) {
            sp_tuple_key_t tkey = {.client_port = lport, .proxy_port = rport};
            bpf_map_update_elem(&sp_tuple_to_cookie, &tkey, &cookie, BPF_ANY);
        }
        break;
    }
    default:
        break;
    }

    return 1;
}

SEC("sk_lookup")
int sp_sk_lookup(struct bpf_sk_lookup *ctx) {
    if (sp_ingress_proxy_port == 0 || ctx->protocol != IPPROTO_TCP) {
        return SK_PASS;
    }

    const u16 lport = (u16)ctx->local_port;
    if (lport == 0 || lport == sp_ingress_proxy_port || lport == sp_egress_proxy_port) {
        return SK_PASS;
    }
    if (bpf_map_lookup_elem(&sp_app_ports, &lport) == NULL) {
        return SK_PASS;
    }

    const u16 rport = bpf_ntohs(ctx->remote_port);
    sp_bypass_key_t bkey = {.client_port = rport, .target_port = lport};
    if (bpf_map_lookup_elem(&sp_obi_bypass_ports, &bkey) != NULL) {
        return SK_PASS;
    }

    u32 zero = 0;
    struct bpf_sock *sk = bpf_map_lookup_elem(&sp_ingress_sockmap, &zero);
    if (!sk) {
        return SK_PASS;
    }

    bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return SK_PASS;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE_GUARDED(sp_kprobe_tcp_connect, struct sock *sk) {
    (void)ctx;
    if (!sk) {
        return 0;
    }

    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    const u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    const u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (sp_is_obi_self_task(task)) {
        // Record OBI's ephemeral port before SYN enters loopback sk_lookup, even when OBI
        // runs outside the target cgroup.
        if (sport != 0 && dport != 0 && bpf_map_lookup_elem(&sp_app_ports, &dport) != NULL) {
            sp_bypass_key_t bkey = {.client_port = sport, .target_port = dport};
            u8 one = 1;
            bpf_map_update_elem(&sp_obi_bypass_ports, &bkey, &one, BPF_ANY);
        }
        return 0;
    }

    if (!sp_is_target_task(task)) {
        return 0;
    }

    const u64 cookie = (u64)BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
    if (cookie != 0 && sport != 0 && dport != 0 &&
        bpf_map_lookup_elem(&sp_orig_dst, &cookie) != NULL) {
        sp_tuple_key_t tkey = {.client_port = sport, .proxy_port = dport};
        bpf_map_update_elem(&sp_tuple_to_cookie, &tkey, &cookie, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE_GUARDED(sp_kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    (void)ctx;
    (void)msg;

    if (!sk || size == 0) {
        return 0;
    }

    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (sp_is_obi_self_task(task)) {
        return 0;
    }
    if (!sp_is_target_task(task)) {
        return 0;
    }

    const u64 cookie = (u64)BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
    if (cookie == 0) {
        return 0;
    }

    u64 *off_ptr = bpf_map_lookup_elem(&sp_sock_write_off, &cookie);
    if (!off_ptr) {
        if (bpf_map_lookup_elem(&sp_orig_dst, &cookie) == NULL) {
            return 0;
        }
        u64 zero_off = 0;
        bpf_map_update_elem(&sp_sock_write_off, &cookie, &zero_off, BPF_NOEXIST);
        off_ptr = bpf_map_lookup_elem(&sp_sock_write_off, &cookie);
        if (!off_ptr) {
            return 0;
        }
    }

    const u64 byte_offset = __sync_fetch_and_add(off_ptr, (u64)size);

    sp_write_ctx_event_t *ev =
        bpf_ringbuf_reserve(&sp_write_ctx_events, sizeof(sp_write_ctx_event_t), 0);
    if (!ev) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->sock_cookie = cookie;
    ev->byte_offset = byte_offset;
    ev->payload_len = (u32)size;
    ev->pid = (u32)(pid_tgid >> 32);
    ev->tid = (u32)pid_tgid;
    ev->flags = 0;
    __builtin_memset(ev->trace_id, 0, sizeof(ev->trace_id));
    __builtin_memset(ev->span_id, 0, sizeof(ev->span_id));

    pid_connection_info_t p_conn = {};
    u16 orig_dport = 0;
    const sp_orig_dst_t *orig = bpf_map_lookup_elem(&sp_orig_dst, &cookie);
    if (orig) {
        orig_dport = orig->port;
    }
    if (parse_full_sock_info(sk, &p_conn.conn)) {
        if (orig_dport == 0) {
            orig_dport = p_conn.conn.d_port;
        }
        sort_connection_info(&p_conn.conn);
        p_conn.pid = pid_from_pid_tgid(pid_tgid);
    }

    trace_key_t t_key = {};
    trace_key_from_pid_tid(&t_key);

    tp_info_pid_t *server_tp =
        find_parent_trace(&p_conn, pid_tgid, k_lw_thread_none, &t_key, orig_dport, NULL);
    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        __builtin_memcpy(ev->trace_id, server_tp->tp.trace_id, sizeof(ev->trace_id));
        __builtin_memcpy(ev->span_id, server_tp->tp.span_id, sizeof(ev->span_id));
        ev->flags = server_tp->tp.flags;
    } else {
        const obi_ctx_info_t *ctx_tp = obi_ctx__get(pid_tgid);
        if (ctx_tp && valid_trace(ctx_tp->trace_id)) {
            __builtin_memcpy(ev->trace_id, ctx_tp->trace_id, sizeof(ev->trace_id));
            __builtin_memcpy(ev->span_id, ctx_tp->span_id, sizeof(ev->span_id));
            ev->flags = 1;
        }
    }

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
