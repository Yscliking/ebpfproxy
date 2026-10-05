# Cookbook: encrypted DNS (DoH) through Tor

Run a local DNS server on `127.0.0.1:53` that resolves via **DNS-over-HTTPS**
(Cloudflare + Google) and sends every upstream connection through **Tor**.
This is useful together with `ebpfproxy` when you run a catch-all default
`BLOCK`: the local resolver is a single, explicit DNS path.

## Why it works with Tor

Tor's SOCKS5 proxy is **TCP only** — it has no UDP ASSOCIATE. So the choice of
upstream protocol matters:

| Protocol | Transport | Over Tor? |
|----------|-----------|-----------|
| DoH (DNS-over-HTTPS) | TCP/TLS | ✅ yes |
| DoT (DNS-over-TLS) | TCP/TLS | ✅ yes |
| DNSCrypt | **UDP** | ❌ no |
| DoH3 (HTTP/3 / QUIC) | **UDP** | ❌ no |
| Plain DNS | **UDP** | ❌ no |

So: use DoH/DoT, and turn off DNSCrypt and HTTP/3.

## 1. Tor

Ensure Tor is running and its SOCKS port is listening (default `9050`):

```sh
ss -lntp | grep 9050      # LISTEN 127.0.0.1:9050
```

## 2. dnscrypt-proxy

```sh
sudo xbps-install -S dnscrypt-proxy
```

Edit `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` and set (leave the rest default):

```toml
# local DNS server
listen_addresses = ['127.0.0.1:53']

# upstream: DoH only, non-China providers
server_names = ['cloudflare', 'google']
doh_servers = true
dnscrypt_servers = false        # DNSCrypt is UDP -> cannot go over Tor
odoh_servers = false
http3 = false                   # DoH3 is QUIC/UDP

# force TCP and route everything through Tor's SOCKS5
force_tcp = true
proxy = 'socks5://127.0.0.1:9050'

# Tor is slower: raise the query timeout
timeout = 10000

# skip the startup connectivity probe (it cannot pass over Tor)
netprobe_timeout = 0

# CRITICAL: disable the plain-DNS bootstrap.
# With IP-based DoH stamps it is not needed; otherwise it sends unencrypted
# UDP directly (not via Tor) and a BLOCK-default firewall drops it.
bootstrap_resolvers = []

ignore_system_dns = true
```

> The `cloudflare` and `google` stamps already contain literal IPs
> (`1.0.0.1`, `8.8.8.8`, …), so no name resolution is needed to reach them.
> If you use a hostname-only DoH server you must provide a bootstrap resolver
> and that one lookup will be plain UDP sent directly.

### Optional: isolated Tor circuit

Give dnscrypt-proxy its own Tor circuit so it never shares an exit with your
other traffic:

```toml
proxy = 'socks5://dnscrypt:dnscrypt@127.0.0.1:9050'
```

## 3. Enable and start (runit on Void)

```sh
sudo ln -s /etc/sv/dnscrypt-proxy /var/service/
sudo sv up dnscrypt-proxy
sv status dnscrypt-proxy
```

## 4. Verify

Expected startup log (in the foreground, or from syslog):

```
Now listening to 127.0.0.1:53 [UDP]
Now listening to 127.0.0.1:53 [TCP]
[cloudflare] OK (DoH) - rtt: 448ms
[google]     OK (DoH) - rtt: 474ms
live servers: 2
```

Query it locally:

```sh
dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml -resolve example.com
```

Confirm all upstream traffic is TCP to Tor and there is **no** external UDP:

```sh
ss -tnp | grep dnscrypt        # -> 127.0.0.1:9050  (TCP)
ss -unp | grep dnscrypt        # -> only 127.0.0.1:53 (the local listener)
```

## 5. Point the system at it (optional)

```sh
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
# Void + dhcpcd: avoid it being overwritten
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf.head
```

## Notes

- The **local** UDP socket on `127.0.0.1:53` is normal: that is how
  applications send queries to dnscrypt-proxy. It stays on loopback.
- The only **upstream** traffic is DoH over TCP through the SOCKS5 proxy.
- If `ebpfproxy` runs with a catch-all/default `BLOCK`, the old bootstrap UDP
  (to `9.9.9.11:53` / `8.8.8.8:53`) was the "dnscrypt-proxy BLOCK UDP -> IP"
  you may have seen. Removing `bootstrap_resolvers` eliminates it.
- To send DNS through a **vmess node** instead of Tor, change the proxy to your
  v2ray SOCKS5 port, e.g. `proxy = 'socks5://127.0.0.1:1080'`.
- Pick other non-China providers by listing their names from
  `/etc/dnscrypt-proxy/public-resolvers.md`, e.g.
  `['cloudflare', 'google', 'quad9-doh-ip4-port443-nofilter-pri']`.
