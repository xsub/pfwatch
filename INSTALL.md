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

## 2) Install Python + dependencies

Install system packages for Python and YAML:

```sh
doas pkg_add python%3 py3-yaml
```

Create a virtual environment and install `geoip2` via pip (optional, only if you want country lookups):

```sh
python3 -m venv ~/pfwatch-venv
. ~/pfwatch-venv/bin/activate

python -m pip install --upgrade pip
pip install geoip2 PyYAML
```

> 💡 If you skip installing `geoip2`, the tool will still run, but country lookups will show as `N/A`.

## 3) GeoLite2 Country DB

Download the free GeoLite2 Country DB (requires a [MaxMind account](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)):

- Download `GeoLite2-Country.mmdb`  
- Place it in e.g. `/var/db/GeoLite2-Country.mmdb`

Update your `pfwatch.yml` config to point to this file.

---

## Usage

```sh
. ~/pfwatch-venv/bin/activate
doas python pfwatch.py pfwatch.yml
```
