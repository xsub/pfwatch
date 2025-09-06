## 1) Minimal setup on OpenBSD

Make sure PF logging is enabled on the rules you care about, e.g.:

```pf
pass out log on egress inet proto { tcp udp icmp }
pass in  log on egress inet proto { tcp udp icmp }
```

Reload PF:

```sh
doas pfctl -f /etc/pf.conf
```

## 2) Install Python + GeoIP

```sh
doas pkg_add python%3 py3-geoip2 py3-yaml
```

> 💡 If you prefer, you can skip `geoip2` and the tool will run without countries.

Get a GeoLite2 Country DB (free, requires a MaxMind account):

- Download `GeoLite2-Country.mmdb`  
- Place it in e.g. `/var/db/GeoLite2-Country.mmdb`

Save the config from the example `pfwatch.yml` (adjust networks and paths).

---

## Usage

```sh
doas python3 pfwatch.py pfwatch.yml
```
