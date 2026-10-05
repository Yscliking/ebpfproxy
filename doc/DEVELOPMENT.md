# Development archive

A chronological log of how the project was built, including the experiments
that decided the design and the dead ends. Useful for anyone changing the
interception mechanism.

## Environment (discovered first)

```
OS        : Void Linux
Kernel    : 6.18.48_1 x86_64, BTF present (/sys/kernel/btf/vmlinux, 5 MB)
cgroup    : cgroup2 mounted on /sys/fs/cgroup
Go        : go1.27.1
Clang     : clang 21 (installed via xbps-install clang llvm lld bpftool libbpf-devel)
Proxy     : v2ray on 127.0.0.1:1080 (SOCKS5 TCP+UDP) and :1081 (HTTP)
Reference : /home/void/tls/pb (ProxyBridge C, NFQUEUE based)
```

Go modules were fetched through `HTTPS_PROXY=socks5://127.0.0.1:1080` with
`GOSUMDB=off GOFLAGS=-mod=mod`.

## Design question 1: how to redirect per-process traffic?

`tc`/XDP classifiers have no reliable process context, so we used the cgroup
`connect4` hook, which runs in the connecting task's context and can rewrite the
destination. The open question was how the userspace relay learns the *original*
destination after the rewrite.

### Experiment 1 — is the source port known at `connect4`?

Probe: a `cgroup/connect4` program that stores `ctx->sk->src_port` and the
destination into a map keyed by socket cookie; a Go program dials localhost and
dumps the map.

```
client local addr: 127.0.0.1:52388
cookie=8197 pid=4606 has_sk=1 src_ip=00000000 src_port=0 dst_ip=0100007f dst_port=14340
```

**Result: `src_port == 0`.** The local port is assigned after the hook, so we
cannot key the redirect table by source port at `connect4` time. (First attempt
to test this hung because we dialled `1.1.1.1` which is blocked directly; testing
against the local proxy fixed it.)

### Experiment 2 — cookie → local port transfer with `sockops`

Add a `sockops` program on `BPF_SOCK_OPS_TCP_CONNECT_CB` (which runs after
`inet_hash_connect`). `connect4` saves the destination under the socket cookie;
`sockops` moves it to a port keyed map.

```
client local addr: ip=127.0.0.1 port=50964
key.ip=0100007f key.port=50964 -> dst.ip=0100007f dst_port=14340
```

**Result: works.** `local_ip4` is network-order packed, `local_port` is host
order, and `dst_port=14340` is network order (1080). This became the TCP design.

## Design question 2: UDP

### Experiment 3 — `sendmsg4` for unconnected UDP

A `cgroup/sendmsg4` program reading `ctx->sk->src_port` and rewriting the dest.

- Bound socket: `src=...:57228 orig=...:53` — source port present.
- Truly unbound raw `sendto`: `src=00000000:58391` — **source port still
  present**, because autobind happens before the hook.

**Result: unconnected UDP can be recorded directly in a port-keyed map.**

### Experiment 4 — connected UDP needs `fentry`

`sendmsg4` is only invoked when `sendmsg` carries a destination (`msg_name`), so
a connected `write()`/`send()` never hits it. Re-reading the kernel confirms the
hook is inside `if (msg->msg_name)`.

Added `fentry/udp_sendmsg` (signature `int udp_sendmsg(struct sock*, struct msghdr*, size_t)`)
to promote `pending[cookie] → redirs_udp[sk->__sk_common.skc_num]`.

```
connected local: 127.0.0.1:54542
key_port=54542 -> orig=08080808(port=13568) local_port=54542 cookie=12294
```

**Result: works.** This is the connected-UDP design.

## Design question 3: correct UDP replies

A connected client socket is connected to `127.0.0.1:<relay>`, so replies must
come from the relay. An unconnected client validates the source address, so
replies should appear to come from the remote server.

### Experiment 5 — `IP_TRANSPARENT` source spoofing

Small C program: set `IP_TRANSPARENT`, bind to `1.2.3.4:9999`, send to a local
listener.

```
got 5 bytes from 1.2.3.4:9999
```

**Result: works.** Unconnected UDP replies are sent from a per-remote
`IP_TRANSPARENT` socket.

## Design question 4: process identity

The reference ProxyBridge (Linux) resolves the process from the socket inode to
`/proc/<pid>/exe`, which is why it handles Firefox. Our first version matched
`bpf_get_current_comm` only. A probe showed a child can rename its `comm` while
keeping the executable:

```
comm="firefox"      exe="exetest" parent_comm="probe"
comm="Web Content"  exe="exetest" parent_comm="firefox"
```

**Decision:** match the rule prefix against both `comm` and the executable
basename, read in-kernel via CO-RE. This fixed Firefox without a userspace
process watcher.

## The verifier battle

The first rule loop:

```c
for (__u32 i = 0; i < MAX_RULES; i++) {
    if (i >= n) break;
    r = bpf_map_lookup_elem(&rules, &i);
    ...
}
```

failed with `infinite loop detected at insn ...` even with `MAX_RULES` constant
and `n` clamped; the induction variable was spilled and the state did not
converge. Full `clang` unrolling was refused. The fix was `bpf_loop`:

- callback context must be a **stack** pointer (`R3 type=map_value expected=fp`
  otherwise);
- the callback returns non-zero to stop after the first match.

`bpf_loop` is present on this kernel (`bpftool feature probe`).

## Design question 5: UDP reliability

Creating a fresh SOCKS5 UDP association per flow made UDP intermittently time
out (the first datagram after association setup was often lost). Refactor: one
**shared** association per relay, multiplexing all flows, with replies routed by
remote source address. Result: 11/12 consecutive DNS queries succeeded, only the
very first after setup was lost.

## Chronology of the first working build

1. Validated TCP redirect (`connect4` + `sockops`).
2. Validated UDP unconnected (`sendmsg4`) and connected (`fentry`).
3. Validated spoofing (`IP_TRANSPARENT`).
4. Built the Go project: rules, SOCKS5, TCP/UDP relays, engine, TUI, CLI.
5. Fought the verifier; switched the rule loop to `bpf_loop`.
6. End-to-end tests: block-all (with `opencode`/`ebpfproxy` direct), TCP proxy
   to a directly-blocked host, UDP proxy with a spoofed reply source, crash
   cleanup via `kill -9`.

## Post-release fixes (see CHANGELOG)

- Stop hung because the UDP janitor only noticed shutdown on its next 30 s tick.
- Firefox was slow: renamed content processes did not match a `firefox` rule →
  added executable-basename matching.
- Rule IDs were monotonic instead of reusing freed numbers.
- Multicast/link-local UDP was being sent to the proxy → added non-unicast
  guards.
- Quitting waited for proxied applications to close their connections; the TCP
  relay now force-closes in-flight connections on shutdown.
- Hardcoded process rules (`opencode`, `v2ray`, …) were removed in favour of
  user-defined rules, and rules became explicitly orderable with hit reporting.
- Process matching became exact-or-prefix (`git` vs `git*`), the implicit
  loopback/non-unicast bypass was removed, and a ring buffer was added so
  PROXY / DIRECT / BLOCK decisions are all logged (with log levels and a
  full-screen viewer). Logs show the executable basename read in kernel, not the
  thread `comm`.

## Testing harness kept around

- `/tmp/opencode/probenet.c` — sets its own `comm`, does TCP connects and DNS
  UDP queries (connected + unconnected).
- `/tmp/opencode/firefox.c` — binary named `firefox` that forks a child renaming
  itself `Web Content`, both connecting to `1.1.1.1:443`.
- `/tmp/opencode/final_test.sh` — the three-scenario regression suite.
