# ebpfproxy

eBPF-based TCP/UDP traffic manager for Linux — a **Proxifier** for Linux.

It transparently **redirects**, **blocks** or **allows** any application's
traffic through a **SOCKS5** proxy, without the app knowing.

> **IPv4 only.** To stop IPv6 leaks, block IPv6 egress:
> ```sh
> sudo ip6tables -A OUTPUT -j DROP
> ```

## Features

- **eBPF based** — cgroup hooks, no iptables/NFQUEUE, no app changes.
- Manages **TCP and UDP** (IPv4).
- Per-process **rules**: `PROXY`, `DIRECT`, `BLOCK`.
- **Transparent SOCKS5 proxying** — works for proxy-unaware apps.
- **Multiple proxies per app** — give each rule its own SOCKS5 proxy
  (`PROXY@v2ray`, `PROXY@clash`, …).
- **Protect your IP** — force chosen apps through the proxy.
- Ordered rules, **first match wins**; logs show which rule hit.
- **Exact or prefix** process match: `git` matches only `git`, `git*` matches
  any `git...`.
- **No hidden bypass.** Loopback, broadcast and link-local are NOT special —
  every flow is decided by your rules and the default action.
- **Traffic log** for proxy / direct / block, with the real program name, and a
  full-screen viewer.

## Build

Requires: Go, clang/llvm, bpftool, libbpf headers, kernel with BTF + cgroup v2.

```sh
make                 # builds ./ebpfproxy
sudo ./ebpfproxy --help
```

The generated eBPF bindings are committed. If you edit `bpf/proxy.bpf.c`:

```sh
make vmlinux generate build
```

## Usage guide

Goal: localhost and the proxy go direct, Firefox goes through the proxy, and
everything else (all IPv4 TCP/UDP) also goes through the proxy.

Example: v2ray SOCKS5 on `127.0.0.1:1080`.

Rules are checked top to bottom; the first match wins:

| # | Rule | Meaning |
|---|------|---------|
| 1 | `*:127.0.0.1;localhost:*:BOTH:DIRECT` | localhost stays direct |
| 2 | `v2ray:*:*:BOTH:DIRECT` | the proxy itself stays direct (no loop) |
| 3 | `firefox:*:*:BOTH:PROXY` | Firefox through the proxy |

Then set the **default action to `PROXY`**, so all unmatched IPv4 TCP/UDP goes
through the proxy:

```sh
sudo ./ebpfproxy --proxy socks5://127.0.0.1:1080 \
  --rule '*:127.0.0.1;localhost:*:BOTH:DIRECT' \
  --rule 'v2ray:*:*:BOTH:DIRECT' \
  --rule 'firefox:*:*:BOTH:PROXY' \
  --default-action PROXY
```

Or run the TUI (rules are saved to `~/.config/ebpfproxy/config.json`):

```sh
sudo ./ebpfproxy
# press s to start/apply
```

Use `--default-action BLOCK` instead of `PROXY` if you want unmatched traffic
blocked rather than proxied.

### Rule syntax

```
process:hosts:ports:protocol:action
```

- `process` — matched against the task `comm` **or** the executable basename.
  `git` matches only `git`; `git*` matches any `git...`; `*` matches any;
  multiple with `;` / `,`
- `hosts` — IPv4 / CIDR / hostname / `*`; multiple with `;` / `,`
- `ports` — port, range, or `*`; multiple with `;` / `,`
- `protocol` — `TCP`, `UDP` or `BOTH`
- `action` — `PROXY`, `DIRECT` or `BLOCK`; optionally `PROXY@<proxy>` to pick a
  specific configured proxy (no `@` = the default proxy)

### Multiple proxies

Configure named proxies (config `proxies`, or repeat `--proxy`):

```sh
sudo ./ebpfproxy --headless \
  --proxy v2ray=127.0.0.1:1080 \
  --proxy clash=127.0.0.1:1909 \
  --proxy ss=127.0.0.1:1192 \
  --rule 'a.exe:*:*:BOTH:PROXY@v2ray' \
  --rule 'b.exe:*:*:BOTH:PROXY@clash' \
  --rule 'c.exe:*:*:BOTH:PROXY@ss'
```

Each flow is dialed through the proxy selected by its rule; logs show it
(`-> 1.1.1.1:443 via v2ray`). `--default-proxy <name>` chooses which proxy
rules without `@name` use. In the TUI, edit proxies in **Settings** (`a` add,
`d` delete) and put the proxy name in the rule's **proxy** field.

### Matched rules and logs

All traffic is logged with the **program name** (not the kernel thread name)
and the rule that matched:

```
[14:14:04] TCP PROXY  rule #1  pid=18012  firefox  -> 1.1.1.1:443
[14:14:04] TCP DIRECT rule -   pid=18013  ebpfproxy -> 127.0.0.1:1080
[14:14:04] TCP BLOCK  rule #2  pid=18014  curl     -> 10.0.0.5:22
```

Log volume is controlled by the **log level** (Settings tab or `--log-level`):
`off`, `block`, `proxy` (default), `all`. The Rules tab shows the order (`#`
column); use `k` / `j` to move a rule up or down.

> **No implicit bypass:** the tool never silently skips traffic. Loopback,
> broadcast and link-local flows are decided by your rules and default action
> too. With a catch-all/default `PROXY`, always add `DIRECT` rules for loopback
> and the proxy process (as in the guide above) or the proxy connection loops.

## TUI keys

| Key | Action |
|-----|--------|
| `1`-`4` / `tab` | switch tab (Status / Rules / Logs / Settings) |
| `s` / `x` | start / stop |
| `↑` / `↓` | select rule |
| `k` / `j` | move rule up / down |
| `a` / `e` / `d` | add / edit / delete rule |
| `space` | enable/disable rule |
| `enter` / `f` | (Logs tab) full-screen log viewer |
| `j` / `k` | (Logs tab) scroll; in full screen `q`/`esc` back, `g`/`G` top/bottom |
| `q` | quit (stops first) |

## Docs

See [`doc/`](doc/) for architecture, implementation, development notes,
changelog and testing — plus the [DNS-over-Tor cookbook](doc/DNS-OVER-TOR.md)
for running a local DoH resolver on port 53 through a proxy.
