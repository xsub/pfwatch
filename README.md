# pfwatch

**pfwatch** is a lightweight console tool for OpenBSD administrators who want to
see *what’s happening right now* on their PF firewall/router.

It consumes logs from the `pflog0` pseudo-interface (via `tcpdump`) and the PF
state table (via `pfctl -ss`), then gives you a live "top"-style view:

- **Top countries** by traffic (GeoIP2 lookup)
- **Internal hosts** with most inbound/outbound traffic
- **Reverse-DNS resolved domains**, categorized by simple rules
- **Active PF states** snapshot
- **Rolling window** stats (default: last 5 minutes)

## Features

- 🛡️ Designed for **OpenBSD PF** (edge routers, firewalls, gateways)
- 📡 Real-time packet accounting (bytes/packets per direction)
- 🌍 Optional GeoIP2 country resolution
- 🔄 **Background-threaded rDNS** resolver:
  - Non-blocking (never stalls packet processing)
  - Results cached with TTL
  - Cache persisted to JSON on disk (restored across restarts)
- ⚡ Minimal dependencies (`python3`, `pyyaml`, `geoip2` if you want GeoIP)
- 🖥️ Runs in the console, no heavy GUI or database required

## Configuration

Configuration is provided in a YAML file, e.g. `pfwatch.yml`:

```yaml
pflog_interface: pflog0
tcpdump_path: /sbin/tcpdump
pfctl_path: /sbin/pfctl

internal_cidrs:
  - 192.168.0.0/16
  - 10.0.0.0/8

geoip_mmdb: /var/db/GeoLite2/GeoLite2-Country.mmdb
reverse_dns: true
rdns_cache_path: /var/db/pfwatch-rdns.json
rdns_ttl_secs: 86400
rdns_workers: 16
rdns_save_secs: 60

refresh_secs: 3
window_secs: 300
poll_states: true
