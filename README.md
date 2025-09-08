# pfwatch

**pfwatch** is a lightweight, console-based monitoring tool for **OpenBSD PF**  
(edge firewalls, routers, gateways).  

It consumes logs from the `pflog0` pseudo-interface (via `tcpdump`) and the PF
state table (via `pfctl -ss`) and displays a live **"top"-style view**:

- 🌍 **Top countries** by traffic (GeoIP2 lookup)
- 🖥️ **Top internal hosts** (inbound/outbound, bytes/packets)
- 🌐 **Domains** (via reverse DNS or static `ip_map`) with categories
- 🔎 **Active PF states** snapshot
- ⏱️ **Rolling window statistics** (default: last 5 minutes, configurable)

---

## Features

- 🛡️ Built for **OpenBSD PF** (works directly with `pflog0` + `pfctl`)
- 📡 Real-time packet accounting (bytes/packets)
- 🌍 Optional **GeoIP2** country resolution
- 🔄 **Threaded rDNS resolver**:
  - Non-blocking (never stalls packet parsing)
  - Results cached with TTL
  - Cache persisted to JSON across restarts
- 🗺️ **Static IP/CIDR mapping (`ip_map`)** for addresses without PTR records:
  - Example: `1.1.1.1 → cloudflare-dns`
  - Supports whole subnets: `140.82.121.0/24 → github`
- ⚡ Minimal dependencies: `python3`, `pyyaml`, `geoip2` (optional)
- 🖥️ Console UI only — no GUI, no DB, no external agents

---

## Configuration

Configuration is provided in a YAML file, e.g. `pfwatch.yml`:

```yaml
pflog_interface: pflog0
tcpdump_path: /usr/sbin/tcpdump
pfctl_path: /sbin/pfctl

internal_cidrs:
  - 192.168.56.0/24
  - 192.168.143.0/24

geoip_mmdb: /home/pawel/pfwatch/GeoLite2-Country.mmdb   # optional
reverse_dns: true
rdns_cache_path: /home/pawel/pfwatch/pfwatch-rdns.json
rdns_ttl_secs: 86400
rdns_workers: 16
rdns_save_secs: 60

refresh_secs: 2
window_secs: 300
poll_states: true
states_poll_secs: 3

domain_categories:
  netflix: entertainment
  youtube: entertainment
  tiktok: entertainment
  cloudflare: cdn
  akamai: cdn
  amazonaws: cloud
  google: cloud
  microsoft: cloud

ip_map:
  1.1.1.1: cloudflare-dns
  8.8.8.8: google-dns
  8.8.4.4: google-dns
  178.215.228.24: pool.ntp
  140.82.121.0/24: github
