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
- **Protect your IP** — force chosen apps through the proxy.
- Ordered rules, **first match wins**; logs show which rule hit.
- No hidden rules. Loopback and non-unicast traffic is always direct.

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

- `process` — name or prefix, matched against the task name **or** executable
  basename; `*` = any; multiple with `;` / `,`
- `hosts` — IPv4 / CIDR / hostname / `*`; multiple with `;` / `,`
- `ports` — port, range, or `*`; multiple with `;` / `,`
- `protocol` — `TCP`, `UDP` or `BOTH`
- `action` — `PROXY`, `DIRECT` or `BLOCK`

### Matched rules

Every proxied connection is logged with the rule that matched:

```
[14:14:04] TCP PROXY  rule #1  pid=18012  firefox  -> 1.1.1.1:443
```

The Rules tab shows the order (`#` column); use `k` / `j` to move a rule up or
down.

## TUI keys

| Key | Action |
|-----|--------|
| `1`-`4` / `tab` | switch tab (Status / Rules / Logs / Settings) |
| `s` / `x` | start / stop |
| `↑` / `↓` | select rule |
| `k` / `j` | move rule up / down |
| `a` / `e` / `d` | add / edit / delete rule |
| `space` | enable/disable rule |
| `q` | quit (stops first) |

## Docs

See [`doc/`](doc/) for architecture, implementation, development notes,
changelog and testing.
