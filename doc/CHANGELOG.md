# Changelog

All notable changes to `ebpfproxy`, and the bugs fixed in each version.

## v0.3.0

### Added

- **Multiple SOCKS5 proxies with per-rule selection.** Configure a named proxy
  list (`proxies` in the config, or repeated `--proxy [name=]addr`), then pin a
  rule to a proxy with `PROXY@<name>`, e.g.
  `firefox:*:*:BOTH:PROXY@clash`. Proxies without `@name` (or `""`) use the
  default proxy (`--default-proxy`).
- The chosen proxy id travels through the kernel side channel
  (`struct rule.proxy_id` → `struct dstinfo.proxy_id` → event) so the TCP relay
  dials the right proxy and the UDP relay keeps **one association per proxy**.
  Replies are routed by `(proxy id, remote)`.
- Logs show the proxy for PROXY flows, e.g. `... -> 1.1.1.1:443 via v2ray`.
- TUI: the rule form has a **proxy** field; Settings lists each proxy
  (`proxy/<name>`) and a `default_proxy` selector, with `a` to add and `d` to
  delete a proxy.
- Legacy single-proxy configs (`proxy_addr` / user / pass) are migrated to a
  proxy named `default` automatically.

### Changed

- Version bumped to `0.3.0`.

## v0.2.0

### Changed

- **Exact vs prefix process matching.** `git` now matches only `git`; use
  `git*` for a prefix match. Implemented with a `wildcard` flag per kernel rule
  (`bpf/proxy.bpf.c: name_match`).
- **Removed all implicit bypasses.** Loopback, multicast/broadcast and
  link-local traffic are no longer forced DIRECT; every flow is decided by the
  rules and the default action. This means a catch-all/default `PROXY` requires
  explicit `DIRECT` rules for loopback and the proxy process, otherwise the
  relay's own connection would loop.
- **Program name in logs instead of thread name.** The eBPF hook stores the
  executable basename (already read for matching) so logs show `firefox`
  instead of `Socket Thread` / `DNS Resolver`, and `git-remote-https` instead
  of a truncated thread name. Userspace `/proc` lookup remains only as a
  fallback.

### Added

- **Traffic log for every action.** A BPF ring buffer (`events`) carries
  PROXY / DIRECT / BLOCK decisions to userspace, so the log is no longer
  limited to proxied flows.
- **Log level** setting (`off`, `block`, `proxy`, `all`), configurable in the
  TUI Settings tab and with `--log-level`. The level is enforced in the kernel
  to avoid overhead when logging is reduced.
- **Full-screen log viewer** in the TUI: from the Logs tab press `enter`/`f`;
  `j`/`k` scroll, `g`/`G` jump to top/bottom, `c` clears, `q`/`esc` returns.
  The normal Logs tab also scrolls with `j`/`k` and keeps its position.
- Version bumped to `0.2.0`.

## v0.1.3

### Added

- **`--help` / `-h`** with a full usage screen (options, rule syntax, examples,
  implicit guards, notes). Invalid flags also print it.

### Changed

- Rules tab reordering is now **`k` (move up)** and **`j` (move down)**;
  `↑`/`↓` (and `shift+↑`/`shift+↓`) are still accepted. Navigation is with the
  arrow keys.
- Version bumped to `0.1.3`.

## v0.1.2

### Fixed

| # | Report | Root cause | Fix | Verification |
|---|--------|------------|-----|--------------|
| 1 | `q` detaches eBPF but the tool then waits for Firefox to exit | `TCPRelay.Close()` waited on the wait group for every in-flight connection handler, and closing the listener does not close already-accepted sockets | Track active connections and force-close them on `Close()`; only the accept loop is waited for, with a 1 s cap (`internal/relay/tcp.go`). UDP shutdown is capped at 2 s | With a proxied connection held open, `Stop()` returned in **123 ms** and the client connection was closed |

### Added

- **Rule ordering.** The Rules tab shows the evaluation order (`#` column) and
  `shift+↑` / `shift+↓` moves the selected rule up/down. Rules are evaluated top
  to bottom and the first match wins.
- **Hit-order reporting.** Each connection log line now shows which user rule
  order matched, e.g. `TCP PROXY rule #2 pid=... firefox -> host:443`. The
  matched order is carried from the kernel (`struct rule.ord` →
  `struct dstinfo.rule_ord`) to the relay events.

### Changed

- **Removed all hardcoded process rules** (`opencode`, `ebpfproxy`, `v2ray`,
  `xray`, `clash`). They are now ordinary user rules that can be added, edited
  and removed. The only implicit guards left are loopback and
  multicast/broadcast/link-local destinations (which must never be proxied).
  If you use a catch-all rule, add your own `DIRECT` rules.
- Version bumped to `0.1.2`.

## v0.1.1

### Fixed

| # | Report | Root cause | Fix | Verification |
|---|--------|------------|-----|--------------|
| 1 | Pressing stop in the TUI hung "for some time without response" | `UDPRelay`'s janitor goroutine checked the `closing` flag only when its 30 s ticker fired, so `Close()` blocked in `wg.Wait()` | Added a `done` channel; `Close()` closes it and the janitor returns immediately (`internal/relay/udp.go`) | Stop with a live UDP association measured at **125 ms** (was up to 30 s) |
| 2 | Firefox very slow / no response; only some traffic proxied | Firefox content/socket processes rename their `comm` (`Web Content`, …) while the executable stays `firefox`; rules matched `comm` only, so those processes missed the rule | Match the rule prefix against both `comm` **and** the executable basename, read in-kernel with CO-RE (`bpf/proxy.bpf.c: read_exe`, `proc_match`) | A binary named `firefox` with a `Web Content` child: `firefox` BLOCK blocks both; `firefox` PROXY proxies both to `1.1.1.1:443` |
| 3 | Add rule 1, delete it, add again → new rule is numbered 2 | New rules used a monotonically increasing `nextID` | Added `freeID()` returning the smallest unused positive ID (`internal/tui/tui.go`) | add/del/add yields 1 again |
| 4 | Lots of "UDP port inaccessible" messages | Multicast/broadcast/link-local datagrams (mDNS, SSDP, DHCP) were being sent to the SOCKS5 proxy, and transient proxy failures were logged every datagram | Guard non-unicast/loopback/link-local to DIRECT always; deduplicate UDP error events to one per 30 s per flow | Counters/`STAT_LOOP`; log no longer floods |

### Changed

- **TUI start/stop are asynchronous.** `s`/`x` (and `q` while running) run in a
  `tea.Cmd`, show a progress status, then verify the shutdown and print a
  report. `verifyStopped()` re-binds the relay ports to prove they are free and
  reports per component, e.g. `stopped: tcp relay :15001 stopped; udp relay
  :15002 stopped; bpf hooks detached`.
- `q` now stops first (showing the report) and requires a second `q` to exit.
- Process rules document matching against `comm` **or** executable basename.
- Corrected the `--proxy` credential form in the docs to
  `socks5://user:pass@host:port`.
- Version bumped to `0.1.1`.

## v0.1.0

Initial implementation.

### Added

- eBPF interception for IPv4 TCP and UDP using cgroup hooks:
  `cgroup/connect4`, `cgroup/sockops`, `cgroup/sendmsg4`,
  `fentry/udp_sendmsg`.
- Redirect correlation maps (`pending`, `redirs_tcp`, `redirs_udp`) so
  userspace can recover the original destination after the kernel rewrites it to
  the local relay.
- In-kernel rule table (up to 256 rules) evaluated with `bpf_loop`, first match
  wins; fields: process prefix (comm/exe), IPv4/mask, port range, protocol.
- Actions: `PROXY`, `DIRECT`, `BLOCK`.
- Userspace SOCKS5 client: TCP `CONNECT` and UDP `ASSOCIATE` with optional
  RFC 1929 username/password auth.
- TCP transparent relay and UDP transparent relay (shared association, reply
  source spoofing with `IP_TRANSPARENT` for unconnected clients).
- Mandatory safety rules: `opencode*`, `ebpfproxy`, common proxy processes →
  DIRECT; loopback never redirected.
- Bubbletea TUI (Status / Rules / Logs / Settings), JSON config persistence, and
  a headless CLI (`--proxy`, `--rule`, `--default-action`, relay ports,
  `--cgroup`).

### Known limitations

- IPv4 only.
- UDP inherits the upstream proxy's UDP reliability.
- Hostname rules are resolved to IPv4 at rule load time.
