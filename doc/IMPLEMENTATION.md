# Implementation guide

This is a from-scratch recipe for building an eBPF per-process TCP/UDP traffic
manager like `ebpfproxy`. It follows the same structure as the repository and
calls out the non-obvious parts.

## 0. Toolchain

```sh
# Void Linux (no network proxy needed for xbps)
xbps-install -Sy clang llvm lld bpftool libbpf-devel

# Go modules are fetched through the SOCKS5 proxy on 1080
export HTTPS_PROXY=socks5://127.0.0.1:1080
export GOFLAGS=-mod=mod GOSUMDB=off
```

Requirements: cgroup v2 mounted at `/sys/fs/cgroup`, kernel BTF at
`/sys/kernel/btf/vmlinux`, and a kernel with `bpf_loop` (>= 5.17).

## 1. Generate `vmlinux.h`

The eBPF program needs kernel struct definitions for CO-RE reads:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

Commit `bpf/vmlinux.h` (or regenerate it with `make vmlinux`).

## 2. Write the eBPF program (`bpf/proxy.bpf.c`)

### 2.1 Rule and context structs

```c
struct rule {
    __u32 ip; __u32 mask;      /* network-order-as-u32 */
    __u16 port_lo; __u16 port_hi;
    __u8  name[64]; __u8 name_len;
    __u8  proto;   /* PROTO_TCP|PROTO_UDP */
    __u8  action;  /* PROXY|DIRECT|BLOCK */
    __u8  enabled;
};

struct dstinfo {
    __u32 ip; __u16 port; __u16 connected;
    __u32 pid; __u8 comm[16];
};
```

### 2.2 Maps

```c
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 256);
         __type(key, __u32); __type(value, struct rule); } rules SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, struct cfg); } cfg_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536);
         __type(key, __u64); __type(value, struct dstinfo); } pending SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536);
         __type(key, __u32); __type(value, struct dstinfo); } redirs_tcp SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536);
         __type(key, __u32); __type(value, struct dstinfo); } redirs_udp SEC(".maps");
```

### 2.3 Rule matching with `bpf_loop`

Do **not** write `for (i=0;i<n;i++) { r = lookup(rules,i); ... break; }`. The
verifier turns that into an "infinite loop detected" error once the induction
variable is spilled and `n` is unbounded. Use `bpf_loop`:

```c
struct match_ctx { __u8 comm[16]; __u8 exe[64]; __u32 ip; __u16 port;
                   __u8 proto; __u8 action; __u8 found; };

static long match_rule_cb(__u32 i, void *data) {
    struct match_ctx *m = data;
    struct rule *r = bpf_map_lookup_elem(&rules, &i);
    if (!r || !r->enabled) return 0;
    if (!(r->proto & m->proto)) return 0;
    if (r->name_len && !proc_match(m, r->name, r->name_len)) return 0;
    if (r->mask && ((m->ip & r->mask) != (r->ip & r->mask))) return 0;
    if (m->port < r->port_lo || m->port > r->port_hi) return 0;
    m->action = r->action; m->found = 1; return 1;
}

bpf_loop(n, match_rule_cb, &m, 0);   /* &m MUST be a stack pointer */
```

The callback context **must** be a stack pointer; passing a map value is
rejected with `R3 type=map_value expected=fp`.

### 2.4 Process matching (comm + executable)

```c
static __always_inline void read_exe(__u8 *buf) {
    struct task_struct *t = bpf_get_current_task_btf();
    if (!t) return;
    struct mm_struct *mm = BPF_CORE_READ(t, mm);
    if (!mm) return;
    struct file *f = BPF_CORE_READ(mm, exe_file);
    if (!f) return;
    struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
    if (!d) return;
    bpf_probe_read_kernel_str(buf, 64, BPF_CORE_READ(d, d_name.name));
}
```

Include `<bpf/bpf_core_read.h>`. Match against both `comm` and `exe` prefixes.
`bpf_get_current_task_btf()` and `bpf_probe_read_kernel_str()` are allowed in
`cgroup/connect4`/`sendmsg4` (verified).

### 2.5 The four hooks

```c
SEC("cgroup/connect4")
int connect4_prog(struct bpf_sock_addr *ctx) {
    if (ctx->type == SOCK_DGRAM) decide4(ctx, PROTO_UDP, /*connected=*/1, ...);
    else                         decide4(ctx, PROTO_TCP, 0, ...);
}

SEC("cgroup/sendmsg4")
int sendmsg4_prog(struct bpf_sock_addr *ctx) {
    decide4(ctx, PROTO_UDP, /*connected=*/0, /*record_by_port=*/1, ...);
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops) {
    if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB) return 1;
    /* promote pending[cookie] -> redirs_tcp[skops->local_port] */
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(udp_sendmsg_prog, struct sock *sk, struct msghdr *msg, size_t len) {
    /* promote pending[cookie] -> redirs_udp[sk->__sk_common.skc_num] */
}
```

`decide4` looks up the rule, then on PROXY stores the original destination and
rewrites:

```c
ctx->user_ip4  = bpf_htonl(0x7f000001);
ctx->user_port = bpf_htons(relay_port);
```

Add the guards (loopback, multicast, link-local) **before** rule lookup.

## 3. Generate Go bindings

`internal/bpf/bpf.go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 \
//  -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I ../../bpf" \
//  proxy ../../bpf/proxy.bpf.c
package bpf
```

Run `go generate ./internal/bpf`. It emits `proxy_x86_bpfel.go`/`.o`. Wrap the
unexported generated types in `internal/bpf/export.go` and expose:

- `Load(cfg) (*Manager, error)` — loads and attaches all four programs,
- `SetRules([]Rule)`, `SetDefaultAction(uint8)`,
- `LookupRedirTCP(port)`, `PeekRedirUDP(port)`,
- `Stats()`, `Close()`.

Attach with `link.AttachCgroup` for the three cgroup hooks and
`link.AttachTracing` for the fentry program.

## 4. Rule expansion (`internal/rule/rule.go`)

Parse `process:hosts:ports:protocol:action`, then expand to kernel rules:

- process list split on `;`/`,`; each becomes a prefix (`cur*` → `cur`, `*` → empty),
- hosts: IP → `/32`, CIDR → mask, hostname → resolve to IPv4 now,
- ports: single / range / `*`,
- cross product capped at `bpf.MaxRules` (256).

Set each kernel entry's `Ord` to the 1-based position of the user rule it came
from, so the matched order can be reported. Do not add hidden rules; every
decision should be a user-visible rule (only loopback/non-unicast guards are
implicit in the eBPF program).

## 5. SOCKS5 client (`internal/socks/socks.go`)

- `DialTCP(dst)`: greeting (`0x05`), optional RFC 1929 user/pass, `CONNECT`,
  read reply, return the connection.
- `AssociateUDP()`: greeting+auth on a control TCP connection, `UDP ASSOCIATE`,
  parse the relay endpoint, create a connected UDP socket.
- `Send(dst, payload)` / `Receive()` handle the 10-byte UDP request header.

## 6. Relays (`internal/relay`)

TCP: accept → lookup by peer port → `DialTCP` → bidirectional copy.

UDP: see [ARCHITECTURE.md](ARCHITECTURE.md) §5. For spoofing, create the socket
with `IP_TRANSPARENT` before binding:

```go
lc := net.ListenConfig{Control: func(n, a string, c syscall.RawConn) error {
    var e error
    c.Control(func(fd uintptr) {
        e = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
    })
    return e
}}
pc, _ := lc.ListenPacket(ctx, "udp4", remoteAddr)
```

## 7. Engine and UI

`internal/engine/engine.go` wires BPF + relays, applies rules and holds the
event channel. `internal/tui/tui.go` is a bubbletea app; run start/stop as
`tea.Cmd` so the UI never blocks. `cmd/ebpfproxy/main.go` parses flags and
chooses TUI or headless.

## 8. Gotchas (all encountered)

1. **`src_port` is 0 at `connect4`.** The local port is assigned later, so you
   need `sockops`/`fentry` to correlate. Verify with a small probe.
2. **`sendmsg4` does not fire for connected UDP `send()`** (no `msg_name`).
   Use `fentry/udp_sendmsg` for that case.
3. **`sendmsg4` sees a valid source port even for untouched, unbound sockets**
   (autobind happens first), so unconnected UDP can be recorded directly.
4. **Verifier "infinite loop detected"** with a hand-rolled rule loop → use
   `bpf_loop`; callback ctx must be a stack pointer.
5. **Connected UDP replies must come from the relay address** (the client is
   connected to it); unconnected replies should be spoofed to the remote.
6. **UDP source spoofing needs `IP_TRANSPARENT`** set before `bind`.
7. **One UDP association per flow is flaky.** Share one association and
   multiplex all flows; route replies by remote source.
8. **The janitor goroutine must be interruptible**, otherwise `Close()` blocks a
   full tick interval (this was the "stop hangs" bug).
9. **Match the executable basename, not only `comm`**, for multi-process apps.
10. **Never redirect loopback/multicast** or you get loops / useless proxy
    attempts and error spam.
