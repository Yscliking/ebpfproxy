// SPDX-License-Identifier: GPL-2.0
// eBPF traffic manager for IPv4 TCP/UDP: per-process direct/proxy/block.
//
// Hooks:
//   cgroup/connect4   - decide on outgoing TCP/UDP connect(); rewrite proxied
//                       destinations to a local userspace relay.
//   cgroup/sockops    - TCP only: promote the saved original destination from
//                       the socket-cookie keyed "pending" map to the
//                       local-port keyed "redirs_tcp" map once the local port
//                       is assigned.
//   cgroup/sendmsg4   - unconnected UDP: decide + rewrite + record redirect
//                       keyed by the (already assigned) local port.
//   fentry/udp_sendmsg- connected UDP: promote pending -> redirs_udp using the
//                       assigned local port.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_RULES 256
#define NAME_LEN 16          /* TASK_COMM_LEN */
#define RULE_NAME_MAX 64     /* executable basename prefix length */

#define ACTION_PROXY  0
#define ACTION_DIRECT 1
#define ACTION_BLOCK  2

#define PROTO_TCP 1
#define PROTO_UDP 2

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define LOOPBACK_BYTE 0x7f

struct rule {
	__u32 ip;	/* network-order-as-u32 */
	__u32 mask;	/* network-order-as-u32 */
	__u16 port_lo;	/* host order */
	__u16 port_hi;	/* host order */
	__u32 ord;	/* user-facing rule order, 1-based (for hit reporting) */
	__u8  name[RULE_NAME_MAX]; /* pattern matched against comm OR exe basename */
	__u8  name_len;	/* 0 = any process */
	__u8  proto;	/* PROTO_TCP | PROTO_UDP */
	__u8  action;	/* ACTION_* */
	__u8  enabled;
	__u8  wildcard;	/* 1 = prefix match ('git*'), 0 = exact match ('git') */
	__u8  proxy_id;	/* index into the userspace SOCKS5 proxy list */
};

struct cfg {
	__u32 rule_count;
	__u32 default_action;
	__u32 tcp_relay_port;
	__u32 udp_relay_port;
	__u32 log_level;	/* 0 off, 1 block, 2 +proxy, 3 +direct */
};

/* Decision event delivered to userspace through the ring buffer. */
struct event {
	__u64 ts;
	__u32 pid;
	__u32 ip;	/* network-order-as-u32 */
	__u16 port;	/* host order */
	__u8  proto;	/* PROTO_TCP | PROTO_UDP */
	__u8  action;	/* ACTION_* */
	__u32 rule_ord;
	__u32 proxy_id;
	__u8  comm[NAME_LEN];
};

struct dstinfo {
	__u32 ip;	/* network-order-as-u32 */
	__u16 port;	/* host order */
	__u16 connected;
	__u32 pid;
	__u32 rule_ord;	/* order of the rule that matched, 1-based */
	__u32 proxy_id;	/* SOCKS5 proxy index for PROXY flows */
	__u8  comm[NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct rule);
} rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg);
} cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct dstinfo);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct dstinfo);
} redirs_tcp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct dstinfo);
} redirs_udp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

enum {
	STAT_ALLOW = 0,
	STAT_PROXY = 1,
	STAT_BLOCK = 2,
	STAT_TCP = 3,
	STAT_UDP = 4,
	STAT_LOOP = 5,
};

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* wildcard=1 -> prefix match ("git*"); wildcard=0 -> exact match ("git"). */
static __always_inline int name_match(const __u8 *s, __u8 slen,
				      const __u8 *pat, __u8 len, __u8 wildcard)
{
#pragma clang loop unroll(disable)
	for (int i = 0; i < RULE_NAME_MAX; i++) {
		if (i >= len) {
			if (wildcard)
				return 1;
			/* exact: source must end here */
			return (i < slen && s[i] == 0) ? 1 : 0;
		}
		if (i >= slen)
			return 0;
		if (s[i] != pat[i])
			return 0;
	}
	return wildcard ? 1 : 0;
}

struct match_ctx {
	__u8 comm[NAME_LEN];
	__u8 exe[RULE_NAME_MAX];
	__u32 ip;
	__u32 rule_ord;	/* order of the matched rule */
	__u32 proxy_id;	/* proxy index of the matched rule */
	__u16 port;
	__u8 proto;
	__u8 action;
	__u8 found;
};

/* A rule's process field matches either the task comm or the executable
 * basename. Firefox renames its content/socket processes (comm becomes
 * "Web Content", ...) but the executable stays "firefox", so exe matching is
 * what makes multi-process applications work. */
static __always_inline int proc_match(struct match_ctx *m, const __u8 *pat,
				      __u8 len, __u8 wildcard)
{
	if (name_match(m->comm, NAME_LEN, pat, len, wildcard))
		return 1;
	if (name_match(m->exe, RULE_NAME_MAX, pat, len, wildcard))
		return 1;
	return 0;
}

static __always_inline void read_exe(__u8 *buf)
{
	struct task_struct *t = bpf_get_current_task_btf();
	if (!t)
		return;
	struct mm_struct *mm = BPF_CORE_READ(t, mm);
	if (!mm)
		return;
	struct file *f = BPF_CORE_READ(mm, exe_file);
	if (!f)
		return;
	struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
	if (!d)
		return;
	const unsigned char *n = BPF_CORE_READ(d, d_name.name);
	bpf_probe_read_kernel_str(buf, RULE_NAME_MAX, n);
}

/* bpf_loop callback: first matching rule wins. */
static long match_rule_cb(__u32 i, void *data)
{
	struct match_ctx *m = data;
	struct rule *r = bpf_map_lookup_elem(&rules, &i);

	if (!r || !r->enabled)
		return 0;
	if (!(r->proto & m->proto))
		return 0;
	if (r->name_len > 0 && !proc_match(m, r->name, r->name_len, r->wildcard))
		return 0;
	if (r->mask != 0 && ((m->ip & r->mask) != (r->ip & r->mask)))
		return 0;
	if (m->port < r->port_lo || m->port > r->port_hi)
		return 0;

	m->action = r->action;
	m->rule_ord = r->ord;
	m->proxy_id = r->proxy_id;
	m->found = 1;
	return 1; /* stop iterating */
}

/* Returns the action to apply for this flow and stores the order of the
 * matched rule (1-based, 0 when the default action is used) in *rule_ord and
 * the proxy index in *proxy_id. */
static __always_inline __u8 match_rules(const __u8 *comm, __u32 ip, __u16 port,
					__u8 want_proto, __u32 *rule_ord,
					__u32 *proxy_id)
{
	__u32 zero = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &zero);
	__u8 def = ACTION_DIRECT;

	if (c)
		def = c->default_action;

	struct match_ctx m = {};

#pragma clang loop unroll(full)
	for (int i = 0; i < NAME_LEN; i++)
		m.comm[i] = comm[i];
	read_exe(m.exe);
	m.ip = ip;
	m.port = port;
	m.proto = want_proto;
	m.action = def;
	m.rule_ord = 0;
	m.proxy_id = 0;
	m.found = 0;

	__u32 n = c ? c->rule_count : 0;
	if (n > MAX_RULES)
		n = MAX_RULES;

	bpf_loop(n, match_rule_cb, &m, 0);

	*rule_ord = m.rule_ord;
	*proxy_id = m.proxy_id;
	return m.found ? m.action : def;
}

static __always_inline void fill_dstinfo(struct dstinfo *di, __u32 ip,
					 __u32 nport, __u8 connected,
					 __u32 rule_ord, __u32 proxy_id,
					 const __u8 *comm)
{
	di->ip = ip;
	di->port = bpf_ntohs((__u16)nport);
	di->connected = connected;
	di->pid = bpf_get_current_pid_tgid() >> 32;
	di->rule_ord = rule_ord;
	di->proxy_id = proxy_id;
#pragma clang loop unroll(full)
	for (int i = 0; i < NAME_LEN; i++)
		di->comm[i] = comm[i];
}

/* Push a decision event to userspace, subject to the configured log level. */
static __always_inline void emit_event(__u8 action, __u8 proto, __u32 ip,
				       __u32 nport, __u32 rule_ord,
				       __u32 proxy_id, const __u8 *comm)
{
	__u32 zero = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &zero);
	__u32 lvl = c ? c->log_level : 0;
	int want;

	if (action == ACTION_BLOCK)
		want = lvl >= 1;
	else if (action == ACTION_PROXY)
		want = lvl >= 2;
	else
		want = lvl >= 3;
	if (!want)
		return;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ip = ip;
	e->port = bpf_ntohs((__u16)nport);
	e->proto = proto;
	e->action = action;
	e->rule_ord = rule_ord;
	e->proxy_id = proxy_id;
#pragma clang loop unroll(full)
	for (int i = 0; i < NAME_LEN; i++)
		e->comm[i] = comm[i];
	bpf_ringbuf_submit(e, 0);
}

/*
 * Common decision routine for the connect()/sendmsg() sock_addr hooks.
 * returns 0 to allow, non-zero to allow (rewriting when needed).
 * Sets *blocked when the caller must drop the operation.
 */
static __always_inline int decide4(struct bpf_sock_addr *ctx, __u8 want_proto,
				   __u8 connected, int record_by_port, int *blocked)
{
	__u8 comm[NAME_LEN] = {};
	__u8 exe[RULE_NAME_MAX] = {};
	__u8 pname[NAME_LEN] = {};
	struct dstinfo di = {};
	__u32 ip = ctx->user_ip4;
	__u16 port = bpf_ntohs((__u16)ctx->user_port);
	__u32 rule_ord = 0;
	__u8 action;

	*blocked = 0;
	bpf_get_current_comm(comm, NAME_LEN);

	/* Report the executable basename rather than the kernel thread name
	 * ("firefox" instead of "Socket Thread"). Fall back to comm. */
	read_exe(exe);
	if (exe[0]) {
#pragma clang loop unroll(full)
		for (int i = 0; i < NAME_LEN; i++)
			pname[i] = exe[i];
	} else {
#pragma clang loop unroll(full)
		for (int i = 0; i < NAME_LEN; i++)
			pname[i] = comm[i];
	}

	__u32 proxy_id = 0;
	action = match_rules(comm, ip, port, want_proto, &rule_ord, &proxy_id);

	__u32 zero = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &zero);
	__u32 relay = 0;
	if (c)
		relay = (want_proto == PROTO_UDP) ? c->udp_relay_port : c->tcp_relay_port;
	if (action == ACTION_PROXY && (!c || relay == 0))
		action = ACTION_DIRECT;

	emit_event(action, want_proto, ip, ctx->user_port, rule_ord, proxy_id, pname);

	if (action == ACTION_BLOCK) {
		stat_inc(STAT_BLOCK);
		*blocked = 1;
		return 0;
	}
	if (action != ACTION_PROXY) {
		stat_inc(STAT_ALLOW);
		return 1;
	}

	fill_dstinfo(&di, ip, ctx->user_port, connected, rule_ord, proxy_id, pname);

	if (record_by_port) {
		/* sendmsg4: local port is already assigned. */
		__u32 lport = 0;
		if (ctx->sk)
			lport = ctx->sk->src_port;
		if (lport)
			bpf_map_update_elem(&redirs_udp, &lport, &di, BPF_ANY);
		else {
			__u64 cookie = bpf_get_socket_cookie(ctx);
			bpf_map_update_elem(&pending, &cookie, &di, BPF_ANY);
		}
	} else {
		__u64 cookie = bpf_get_socket_cookie(ctx);
		bpf_map_update_elem(&pending, &cookie, &di, BPF_ANY);
	}

	ctx->user_ip4 = bpf_htonl(0x7f000001);
	ctx->user_port = bpf_htons((__u16)relay);
	stat_inc(STAT_PROXY);
	if (want_proto == PROTO_TCP)
		stat_inc(STAT_TCP);
	else
		stat_inc(STAT_UDP);
	return 1;
}

SEC("cgroup/connect4")
int connect4_prog(struct bpf_sock_addr *ctx)
{
	int blocked = 0;

	if (ctx->type == SOCK_DGRAM) {
		/* Connected UDP: recorded in pending, promoted by fentry. */
		decide4(ctx, PROTO_UDP, 1, 0, &blocked);
	} else {
		decide4(ctx, PROTO_TCP, 0, 0, &blocked);
	}
	return blocked ? 0 : 1;
}

SEC("cgroup/sendmsg4")
int sendmsg4_prog(struct bpf_sock_addr *ctx)
{
	int blocked = 0;
	decide4(ctx, PROTO_UDP, 0, 1, &blocked);
	return blocked ? 0 : 1;
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops)
{
	if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 1;

	__u64 cookie = bpf_get_socket_cookie(skops);
	struct dstinfo *di = bpf_map_lookup_elem(&pending, &cookie);
	if (!di)
		return 1;

	__u32 lport = skops->local_port;
	struct dstinfo v = {};
	v.ip = di->ip;
	v.port = di->port;
	v.connected = 1;
	v.pid = di->pid;
	v.rule_ord = di->rule_ord;
	v.proxy_id = di->proxy_id;
#pragma clang loop unroll(full)
	for (int i = 0; i < NAME_LEN; i++)
		v.comm[i] = di->comm[i];

	bpf_map_update_elem(&redirs_tcp, &lport, &v, BPF_ANY);
	bpf_map_delete_elem(&pending, &cookie);
	return 1;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_sendmsg_prog, struct sock *sk, struct msghdr *msg, size_t len)
{
	__u64 cookie = bpf_get_socket_cookie(sk);
	struct dstinfo *di = bpf_map_lookup_elem(&pending, &cookie);
	if (!di)
		return 0;

	__u32 lport = sk->__sk_common.skc_num;
	struct dstinfo v = {};
	v.ip = di->ip;
	v.port = di->port;
	v.connected = 1;
	v.pid = di->pid;
	v.rule_ord = di->rule_ord;
	v.proxy_id = di->proxy_id;
#pragma clang loop unroll(full)
	for (int i = 0; i < NAME_LEN; i++)
		v.comm[i] = di->comm[i];

	bpf_map_update_elem(&redirs_udp, &lport, &v, BPF_ANY);
	bpf_map_delete_elem(&pending, &cookie);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
