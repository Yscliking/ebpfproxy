# Architecture

## 1. Overview

`ebpfproxy` splits into three layers:

```
┌──────────────────────────────────────────────────────────────────┐
│ eBPF (kernel)        bpf/proxy.bpf.c                              │
│   process/dst/port/proto rule lookup, allow/deny, destination     │
│   rewrite to the local relay, and the "original destination"      │
│   side channel (maps)                                             │
├──────────────────────────────────────────────────────────────────┤
│ Userspace data plane internal/relay + internal/socks              │
│   accept redirected flows, look up the original destination,      │
│   perform SOCKS5 CONNECT / UDP ASSOCIATE, relay bytes/datagrams   │
├──────────────────────────────────────────────────────────────────┤
│ Control plane + UI   internal/engine + internal/rule + internal/tui│
│   load/attach programs, push rules, collect stats, terminal UI    │
└──────────────────────────────────────────────────────────────────┘
```

The kernel never speaks SOCKS5. It only decides and rewrites. Authentication
and protocol handling happen entirely in userspace.

## 2. Loaded BPF objects

Maps (see `bpf/proxy.bpf.c`):

| Map | Type | Key → Value | Purpose |
|-----|------|-------------|---------|
| `rules` | ARRAY (256) | `u32` → `struct rule` | rule table, first match wins |
| `cfg_map` | ARRAY (1) | `u32` → `struct cfg` | rule count, default action, relay ports |
| `pending` | LRU_HASH | `u64 cookie` → `struct dstinfo` | original dst before the local port is known |
| `redirs_tcp` | LRU_HASH | `u32 local_port` → `struct dstinfo` | TCP redirect table |
| `redirs_udp` | LRU_HASH | `u32 local_port` → `struct dstinfo` | UDP redirect table |
| `stats` | PERCPU_ARRAY (6) | `u32` → `u64` | counters |

Programs:

| Program | Section / attach | Role |
|---------|------------------|------|
| `connect4_prog` | `cgroup/connect4` (`AttachCGroupInet4Connect`) | TCP connect + connected UDP connect decision/rewrite |
| `sockops_prog` | `cgroup/sockops` (`AttachCGroupSockOps`) | move `pending[cookie]` → `redirs_tcp[local_port]` |
| `sendmsg4_prog` | `cgroup/sendmsg4` (`AttachCGroupUDP4Sendmsg`) | unconnected UDP decision/rewrite |
| `udp_sendmsg_prog` | `fentry/udp_sendmsg` | move `pending[cookie]` → `redirs_udp[local_port]` for connected UDP |

All cgroup programs attach to the path in `--cgroup` (default `/sys/fs/cgroup`).

## 3. Rule model

Kernel rule (`bpf/proxy.bpf.c`):

```c
struct rule {
    __u32 ip;          /* network-order-as-u32 */
    __u32 mask;        /* network-order-as-u32, 0 = any */
    __u16 port_lo;     /* host order */
    __u16 port_hi;     /* host order */
    __u32 ord;         /* user rule order, 1-based (for hit reporting) */
    __u8  name[64];    /* process pattern */
    __u8  name_len;    /* 0 = any process */
    __u8  proto;       /* PROTO_TCP | PROTO_UDP */
    __u8  action;      /* ACTION_PROXY | ACTION_DIRECT | ACTION_BLOCK */
    __u8  enabled;
    __u8  wildcard;    /* 1 = prefix ("git*"), 0 = exact ("git") */
};
```

Matching runs through `bpf_loop(n, match_rule_cb, &ctx, 0)`. `bpf_loop` was
chosen because a hand-written bounded loop over map lookups triggered the
verifier's "infinite loop detected" error (the induction variable was spilled
to the stack). The callback receives a **stack pointer** as context (the
verifier rejects a map-value pointer there).

`proc_match()` compares the rule name against **two** strings (exact or prefix
depending on `wildcard`):

1. `ctx->comm` (`bpf_get_current_comm`, 16 bytes), and
2. `ctx->exe`, the executable basename read once with
   `BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name)`.

Matching the executable is what makes multi-process applications work: Firefox
renames its content/socket processes (`comm` becomes `Web Content`, …) but the
executable remains `firefox`.

## 4. The original-destination side channel

The rewritten packet only carries `127.0.0.1:<relay>`, so the original
destination travels out of band:

```
connect(dst)
   │
   ▼
connect4: pending[cookie] = {dst}; user_ip4/port = 127.0.0.1:relay
   │
   ▼  (kernel assigns local port P)
sockops / fentry: redirs_*[P] = pending[cookie]
   │
   ▼
relay accepts from 127.0.0.1:P; reads LookupAndDelete(P) -> {dst}
```

Why two steps: at `connect4` the source port is still 0 (verified
empirically), but the socket cookie exists. `sockops`/`fentry` run after the
port is bound, so they bridge cookie → port.

Cases:

| Case | Writer | Key |
|------|--------|-----|
| TCP | `connect4` → `sockops` | socket cookie → local port |
| UDP connected | `connect4` → `fentry/udp_sendmsg` | cookie → local port |
| UDP unconnected | `sendmsg4` directly | local port (`ctx->sk->src_port`, already bound) |

`struct dstinfo` carries `ip`, `port` (host order), a `connected` flag, `pid`,
`rule_ord` (the user rule order that matched), `proxy_id` (which configured
SOCKS5 proxy to use) and `comm` so the UI can show the originating process, the
rule that hit and the proxy. The TCP relay dials `ProxyFor(proxy_id)`; the UDP
relay keeps one association per proxy id and routes replies by
`(proxy_id, remote)`.

## 5. Userspace relays

### TCP (`internal/relay/tcp.go`)

Listens on `127.0.0.1:<tcp-relay-port>`. For every accepted connection:

1. read the peer's source port,
2. `LookupRedirTCP(port)` to recover the destination,
3. `socks.Client.DialTCP(dst)` (SOCKS5 CONNECT, with optional auth),
4. copy bytes both ways, half-closing with `CloseWrite`.

### UDP (`internal/relay/udp.go`)

Listens on `127.0.0.1:<udp-relay-port>`. For each datagram:

1. `PeekRedirUDP(client_port)` (peek, not delete, since a socket may send many),
2. create/reuse a flow keyed by `(client, dst)`,
3. send the payload through one **shared** SOCKS5 UDP association
   (`AssociateUDP`), multiplexing all flows.

Replies are routed by the SOCKS5 remote source address:

- **connected** client socket → reply from the relay socket itself, because the
  client is connected to `127.0.0.1:<udp-relay-port>`;
- **unconnected** client socket → reply from a per-remote `IP_TRANSPARENT`
  socket bound to the remote address, so the datagram *appears* to come from the
  real server (otherwise strict clients drop it).

A single association is shared to avoid per-datagram handshake churn (which made
UDP flaky). Idle flows are garbage collected after 120 s.

## 6. No hidden bypass, rule order and events

There are **no hidden rules and no implicit bypasses**. Every flow — including
loopback, multicast/broadcast and link-local — is decided by the rule table and
the default action. In particular, with a catch-all/default `PROXY` you must add
`DIRECT` rules for loopback and for the proxy process, otherwise the relay's own
connection to the proxy is redirected back into the relay and loops.

Consequence: the eBPF program must never be relied on to protect the tool
itself. This is a deliberate change from v0.1.x (which forced loopback and
non-unicast DIRECT).

Rules are evaluated in array order, top to bottom, and the **first match wins**
(`bpf_loop` stops at the first matching callback). Each entry stores the user
rule's order (`ord`, 1-based) so the matched rule number can be reported.
Reordering in the UI simply rewrites the array.

Process matching supports both exact and prefix patterns via a per-rule
`wildcard` byte: `git` (wildcard=0) matches only `git`, `git*` (wildcard=1)
matches any `git...`.

### Decision events

Every decision is pushed to a `BPF_MAP_TYPE_RINGBUF` named `events`
(`bpf/proxy.bpf.c: struct event`). The payload carries timestamp, pid, ip, port,
protocol, action, matched rule order and the **executable basename** (read in
kernel, falling back to `comm`). Userspace reads it with
`github.com/cilium/ebpf/ringbuf` and turns each record into a UI event.

Emission is gated by `cfg.log_level` so no work is done when logging is reduced:

| level | logged |
|-------|--------|
| 0 off | nothing |
| 1 block | BLOCK |
| 2 proxy (default) | BLOCK + PROXY |
| 3 all | BLOCK + PROXY + DIRECT |

Programs are attached to cgroup fds; if the process dies, the fds close and the
hooks detach automatically.

## 7. Concurrency

- eBPF is per-packet/per-connect and race-free by construction; map updates are
  atomic.
- The TCP relay handles each connection in its own goroutine.
- The UDP relay has one read loop, one association read loop, a janitor, and a
  mutex-guarded flow/spoof table.
- The TUI runs the engine start/stop asynchronously (`tea.Cmd`) so the UI never
  blocks.
