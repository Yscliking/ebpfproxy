# ebpfproxy documentation

This directory contains the project documentation. Start here.

| Document | Contents |
|----------|----------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the data path works: eBPF hooks, redirect correlation maps, rule engine, SOCKS5 relays. |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | How to build it from scratch, file by file, including the gotchas we hit. |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Development archive: environment discovery, experiments, decisions, dead ends. |
| [CHANGELOG.md](CHANGELOG.md) | Version history and the bugs fixed in each version. |
| [TESTING.md](TESTING.md) | How to reproduce the functional tests (block / proxy / direct / UDP spoof / Firefox). |

## Project at a glance

`ebpfproxy` is an eBPF based per-process IPv4 TCP/UDP traffic manager written in
Go. It can **BLOCK**, **DIRECT** or **PROXY** (through SOCKS5) traffic matched by
process, destination, port and protocol, and it exposes a terminal UI plus a
headless CLI.

```
 app ── connect() ──► eBPF rule lookup ──┬─ BLOCK  → EPERM
                                         ├─ DIRECT → unchanged
                                         └─ PROXY  → dst := 127.0.0.1:<relay>
                                                         │
                                          userspace relay ─┴─ SOCKS5 ─► proxy ─► internet
```

- Entry point: `cmd/ebpfproxy/main.go`
- eBPF program: `bpf/proxy.bpf.c`
- Userspace data plane: `internal/relay`, `internal/socks`
- Control plane: `internal/engine`, `internal/rule`, `internal/bpf`
- UI: `internal/tui`

Version: `0.2.0`.
