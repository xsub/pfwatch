#!/usr/bin/env python3
# pfwatch.py — PF pflog watcher with:
# - GeoIP (local mmdb)
# - background rDNS with persistent JSON cache
# - PF tables mapping (pfctl -t <table> -T show) -> label/category
# - PF states snapshot
# - rolling "top" view
# OpenBSD compatible
# (c) 2025 pawel.suchanecki@gmail.com / XSUB

import asyncio
import ipaddress
import os
import re
import signal
import socket
import sys
import time
import yaml
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional, Dict, Tuple, List

# ---------------- GeoIP ----------------
_GEOIP_READER = None
def load_geoip(mmdb_path: Optional[str]):
    global _GEOIP_READER
    if not mmdb_path:
        return
    try:
        import geoip2.database
        _GEOIP_READER = geoip2.database.Reader(mmdb_path)
    except Exception as e:
        print(f"[geoip] disabled ({e})", file=sys.stderr)

def ip_to_country(ip: str) -> str:
    if _GEOIP_READER is None:
        return "N/A"
    try:
        r = _GEOIP_READER.country(ip)
        return r.country.iso_code or "??"
    except Exception:
        return "??"

# ---------------- Background rDNS (persistent cache) ----------------
class BackgroundResolver:
    def __init__(self, enabled: bool, ttl_secs: int = 24*3600, max_workers: int = 16,
                 cache_path: Optional[str] = None):
        self.enabled = enabled
        self.ttl_secs = ttl_secs
        self.cache_path = cache_path
        self.executor = ThreadPoolExecutor(max_workers=max_workers) if enabled else None
        self._cache: Dict[str, Dict[str, object]] = {}
        self._lock = threading.Lock()

    def load_from_file(self):
        if not self.enabled or not self.cache_path:
            return
        try:
            import json
            now = time.time()
            with open(self.cache_path, "r") as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                return
            kept = 0
            with self._lock:
                for ip, rec in raw.items():
                    if not isinstance(rec, dict):
                        continue
                    name = str(rec.get("name", ""))
                    try:
                        exp = float(rec.get("exp", 0))
                    except Exception:
                        exp = 0.0
                    st = rec.get("state", "failed")
                    if exp > now and st in ("fresh", "failed"):
                        self._cache[ip] = {"name": name, "exp": exp, "state": st}
                        kept += 1
            print(f"[rdns] loaded {kept} entries from {self.cache_path}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[rdns] load failed ({e}); starting empty", file=sys.stderr)

    def save_to_file(self):
        if not self.enabled or not self.cache_path:
            return
        try:
            import json
            now = time.time()
            with self._lock:
                data = {ip: rec for ip, rec in self._cache.items()
                        if float(rec.get("exp", 0)) > now and rec.get("state") != "pending"}
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
            os.replace(tmp, self.cache_path)
        except Exception as e:
            print(f"[rdns] save failed ({e})", file=sys.stderr)

    def shutdown(self):
        try:
            self.save_to_file()
        finally:
            if self.executor:
                self.executor.shutdown(wait=False)

    def _now(self) -> float: return time.time()

    def _is_fresh(self, rec: Dict[str, object]) -> bool:
        return rec and float(rec.get("exp", 0)) > self._now() and rec.get("state") == "fresh"

    def get(self, ip: str) -> str:
        if not self.enabled:
            return ''
        with self._lock:
            rec = self._cache.get(ip)
            if self._is_fresh(rec):
                return str(rec.get("name", ""))
            return ''

    def submit(self, ip: str):
        if not self.enabled:
            return
        now = self._now()
        with self._lock:
            rec = self._cache.get(ip)
            if rec and float(rec.get("exp", 0)) > now and rec.get("state") in ("fresh", "pending"):
                return
            self._cache[ip] = {"name": "", "exp": now + 60, "state": "pending"}
        self.executor.submit(self._resolve_and_store, ip)

    def _resolve_and_store(self, ip: str):
        name, state = "", "failed"
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            name = name.rstrip(".")
            state = "fresh"
        except Exception:
            name, state = "", "failed"
        with self._lock:
            ttl = self.ttl_secs if state == "fresh" else 15 * 60
            self._cache[ip] = {"name": name, "exp": self._now() + ttl, "state": state}

    def stats(self) -> Tuple[int, int, int, int]:
        with self._lock:
            fresh = pending = failed = 0
            now = self._now()
            for rec in self._cache.values():
                if float(rec.get("exp", 0)) <= now:
                    continue
                st = rec.get("state")
                if st == "fresh":   fresh += 1
                elif st == "pending": pending += 1
                elif st == "failed":  failed += 1
            return fresh, pending, failed, len(self._cache)

# ---------------- PF tables watcher ----------------
class PFTables:
    """
    Periodically polls pfctl -t <table> -T show for configured tables.
    Each table is associated with a label and optional category.
    Lookup is O(#tables * entries) via ipaddress membership (fine for small/medium sets).
    """
    def __init__(self, pfctl_path: str, items: List[dict], poll_secs: int = 30):
        self.pfctl_path = pfctl_path
        self.items_cfg = items[:]  # [{table,label,category?}, ...]
        self.poll_secs = poll_secs
        self._lock = threading.Lock()
        # runtime structure: [{table, label, category, nets:[IPv4Network/IPv6Network or IPv4Address]}]
        self._sets: List[dict] = []

    def _parse_line(self, ln: str):
        tok = ln.strip()
        if not tok: return None
        # pfctl may output single IPs or CIDRs
        try:
            if '/' in tok:
                return ipaddress.ip_network(tok, strict=False)
            else:
                return ipaddress.ip_network(tok + "/32", strict=False) if ':' not in tok else ipaddress.ip_network(tok + "/128", strict=False)
        except Exception:
            return None

    async def poll_loop(self):
        while True:
            await self._refresh_once()
            await asyncio.sleep(max(5, self.poll_secs))

    async def _refresh_once(self):
        new_sets: List[dict] = []
        for it in self.items_cfg:
            table = it.get("table")
            label = it.get("label", table)
            category = it.get("category", "uncategorized")
            if not table:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.pfctl_path, "-t", table, "-T", "show",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                out, _ = await proc.communicate()
                nets = []
                for ln in out.decode("utf-8", errors="replace").splitlines():
                    n = self._parse_line(ln)
                    if n is not None:
                        nets.append(n)
                new_sets.append({"table": table, "label": label, "category": category, "nets": nets})
            except Exception as e:
                # keep going; table may not exist yet
                continue
        with self._lock:
            self._sets = new_sets

    def label_for_ip(self, ip: str) -> Tuple[str, str]:
        """Return (label, category) if IP is in any table; else ('','')."""
        try:
            ipobj = ipaddress.ip_address(ip)
        except ValueError:
            return '', ''
        with self._lock:
            for entry in self._sets:
                for net in entry["nets"]:
                    if ipobj in net:
                        return entry["label"], entry["category"]
        return '', ''

# ---------------- tcpdump pflog parsing ----------------
TCPDUMP_RE = re.compile(
    r'^(?P<ts>\d+\.\d+)\s+.*?:\s+(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):\s*(?P<rest>.*)$'
)
PORT_SPLIT_RE = re.compile(r'^(?P<ip>\[?[0-9a-fA-F\.:]+\]?)\.(?P<port>\d+)$')
LENGTH_RE = re.compile(r'length\s+(?P<len>\d+)')
PROTO_RE = re.compile(r'\b(UDP|TCP|ICMP|ESP|AH)\b', re.IGNORECASE)

def split_ip_port(token: str):
    m = PORT_SPLIT_RE.match(token)
    if not m:
        return token, None
    return m.group('ip'), int(m.group('port'))

def detect_proto(rest: str) -> str:
    m = PROTO_RE.search(rest)
    if not m:
        if 'Flags [' in rest:
            return 'TCP'
        return 'IP'
    return m.group(0).upper()

def extract_len(rest: str) -> int:
    m = LENGTH_RE.search(rest)
    return int(m.group('len')) if m else 0

# ---------------- pfctl -ss parsing ----------------
STATE_RE = re.compile(r'^\s*\S+\s+(?P<proto>\S+)\s+(?P<src>[^ ]+)\s+->\s+(?P<dst>[^ ]+)')

# ---------------- Rolling window counters ----------------
class RollingCounter:
    def __init__(self, window_secs=300):
        self.window = deque()
        self.bytes = 0
        self.pkts = 0
        self.window_secs = window_secs

    def add(self, ts: float, length: int):
        self.window.append((ts, length))
        self.bytes += length
        self.pkts += 1
        self._expire(ts)

    def _expire(self, now: float):
        cutoff = now - self.window_secs
        while self.window and self.window[0][0] < cutoff:
            _, l = self.window.popleft()
            self.bytes -= l
            self.pkts -= 1
        if self.bytes < 0: self.bytes = 0
        if self.pkts  < 0: self.pkts  = 0

    def snapshot(self, now: float):
        self._expire(now)
        return self.bytes, self.pkts

# ---------------- Main app ----------------
class PFWatch:
    def __init__(self, cfg):
        self.cfg = cfg
        self.internal_nets = [ipaddress.ip_network(x) for x in cfg.get('internal_cidrs', [])]
        self.reverse_dns_enabled = bool(cfg.get('reverse_dns', False))
        self.domain_categories = {k.lower(): v for k, v in cfg.get('domain_categories', {}).items()}

        # PF tables mapper
        self.pf_tables_cfg = cfg.get('ip_tables', []) or []
        self.pf_tables = PFTables(
            pfctl_path=os.path.expanduser(cfg.get('pfctl_path', '/sbin/pfctl')),
            items=self.pf_tables_cfg,
            poll_secs=int(cfg.get('ip_tables_poll_secs', 30))
        )

        # background rDNS with persistence
        self.resolver = BackgroundResolver(
            enabled=self.reverse_dns_enabled,
            ttl_secs=int(cfg.get('rdns_ttl_secs', 24*3600)),
            max_workers=int(cfg.get('rdns_workers', 16)),
            cache_path=os.path.expanduser(cfg.get('rdns_cache_path')) if cfg.get('rdns_cache_path') else None
        )
        self.resolver.load_from_file()

        # stats
        W = cfg['window_secs']
        self.per_host_out = defaultdict(lambda: RollingCounter(W))
        self.per_host_in  = defaultdict(lambda: RollingCounter(W))
        self.per_country  = defaultdict(lambda: RollingCounter(W))
        self.per_domain   = defaultdict(lambda: RollingCounter(W))
        self.active_states = []

    def is_internal(self, ip: str) -> bool:
        try:
            ipobj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(ipobj in net for net in self.internal_nets)

    def categorize_domain(self, name: str) -> str:
        n = name.lower()
        for needle, cat in self.domain_categories.items():
            if needle in n:
                return cat
        return "uncategorized"

    def name_and_cat_for_ip(self, ip: str) -> Tuple[str, str]:
        # 1) PF tables first
        lbl, cat = self.pf_tables.label_for_ip(ip)
        if lbl:
            # if category empty, fallback to categorize_domain on label
            return lbl, (cat or self.categorize_domain(lbl))
        # 2) rDNS (cached)
        if self.reverse_dns_enabled:
            host = self.resolver.get(ip) or ''
            if host:
                return host, self.categorize_domain(host)
        return '', ''

    def handle_packet(self, ts: float, src_ip: str, src_port, dst_ip: str, dst_port, proto: str, length: int):
        now = ts
        src_int = self.is_internal(src_ip)
        dst_int = self.is_internal(dst_ip)

        if src_int and not dst_int:
            self.per_host_out[src_ip].add(now, length)
            self.per_country[ip_to_country(dst_ip)].add(now, length)
            name, cat = self.name_and_cat_for_ip(dst_ip)
            if not name and self.reverse_dns_enabled:
                self.resolver.submit(dst_ip)
            elif name:
                self.per_domain[name].add(now, length)

        elif dst_int and not src_int:
            self.per_host_in[dst_ip].add(now, length)
            self.per_country[ip_to_country(src_ip)].add(now, length)
            name, cat = self.name_and_cat_for_ip(src_ip)
            if not name and self.reverse_dns_enabled:
                self.resolver.submit(src_ip)
            elif name:
                self.per_domain[name].add(now, length)

        elif src_int and dst_int:
            self.per_host_out[src_ip].add(now, length)
            self.per_host_in[dst_ip].add(now, length)
        # external<->external ignored

    def render(self):
        os.system('clear')
        now = time.time()

        def top_n(counter_map, n=10):
            items = []
            for k, rc in counter_map.items():
                b, p = rc.snapshot(now)
                if b or p:
                    items.append((b, p, k))
            items.sort(reverse=True)
            return items[:n]

        print(f"PF Watch — live (window={self.cfg['window_secs']}s)  {datetime.now():%Y-%m-%d %H:%M:%S}")
        print("="*80)

        if self.reverse_dns_enabled:
            fr, pn, fl, total = self.resolver.stats()
            print(f"rDNS cache: fresh={fr} pending={pn} failed={fl} total={total}")

        print("\nTop countries (bytes / pkts):")
        for b, p, c in top_n(self.per_country, 10):
            print(f"  {c:>3}  {b:>12,}  / {p:>7}")

        print("\nTop internal hosts (outbound):")
        for b, p, h in top_n(self.per_host_out, 10):
            print(f"  {h:<15}  {b:>12,}  / {p:>7}")

        print("\nTop internal hosts (inbound):")
        for b, p, h in top_n(self.per_host_in, 10):
            print(f"  {h:<15}  {b:>12,}  / {p:>7}")

        print("\nTop domains (with categories):")
        for b, p, dom in top_n(self.per_domain, 10):
            cat = self.categorize_domain(dom)
            print(f"  {dom:<40} {b:>12,} / {p:>7}   [{cat}]")

        if self.cfg.get('poll_states', False):
            print("\nActive connections snapshot:")
            for line in self.active_states[:20]:
                print("  " + line)
            more = max(0, len(self.active_states) - 20)
            if more:
                print(f"  ... (+{more} more)")

    async def run_tcpdump(self):
        td = os.path.expanduser(self.cfg.get('tcpdump_path', '/sbin/tcpdump'))
        iface = self.cfg.get('pflog_interface', 'pflog0')
        cmd = [td, '-n', '-e', '-tt', '-l', '-i', iface]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        async for raw in proc.stdout:
            try:
                line = raw.decode('utf-8', errors='replace').strip()
                m = TCPDUMP_RE.match(line)
                if not m:
                    continue
                ts = float(m.group('ts'))
                src_tok = m.group('src')
                dst_tok = m.group('dst')
                rest = m.group('rest')

                src_ip, src_port = split_ip_port(src_tok)
                dst_ip, dst_port = split_ip_port(dst_tok)
                proto = detect_proto(rest)
                length = extract_len(rest)

                src_ip = src_ip.strip('[]')
                dst_ip = dst_ip.strip('[]')

                self.handle_packet(ts, src_ip, src_port, dst_ip, dst_port, proto, length)
            except Exception:
                continue

    async def poll_states(self):
        pfctl = os.path.expanduser(self.cfg.get('pfctl_path', '/sbin/pfctl'))
        while True:
            try:
                proc = await asyncio.create_subprocess_exec(
                    pfctl, '-ss',
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                out, _ = await proc.communicate()
                lines = out.decode('utf-8', errors='replace').splitlines()
                snapshot = []
                for ln in lines:
                    m = STATE_RE.match(ln)
                    if m:
                        proto = m.group('proto')
                        src = m.group('src')
                        dst = m.group('dst')
                        snapshot.append(f"{proto:<4} {src} -> {dst}")
                self.active_states = snapshot
            except Exception:
                self.active_states = []
            await asyncio.sleep(self.cfg.get('states_poll_secs', 5))

    async def autosave_rdns(self):
        interval = int(self.cfg.get('rdns_save_secs', 60))
        if interval <= 0:
            return
        try:
            while True:
                await asyncio.sleep(interval)
                self.resolver.save_to_file()
        except asyncio.CancelledError:
            pass

# ---------------- entrypoint ----------------
async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} pfwatch.yml", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], 'r') as f:
        cfg = yaml.safe_load(f)

    # defaults
    cfg.setdefault('window_secs', 300)
    cfg.setdefault('refresh_secs', 3)
    cfg.setdefault('poll_states', True)
    cfg.setdefault('states_poll_secs', 5)
    cfg.setdefault('rdns_ttl_secs', 24*3600)
    cfg.setdefault('rdns_workers', 16)
    cfg.setdefault('rdns_save_secs', 60)
    cfg.setdefault('ip_tables_poll_secs', 30)

    # expand ~ paths
    for key in ("geoip_mmdb", "rdns_cache_path", "tcpdump_path", "pfctl_path"):
        val = cfg.get(key)
        if isinstance(val, str) and val.startswith("~"):
            cfg[key] = os.path.expanduser(val)

    load_geoip(cfg.get('geoip_mmdb', None))
    watcher = PFWatch(cfg)

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, loop.stop)

    tasks = [
        asyncio.create_task(watcher.run_tcpdump()),
        asyncio.create_task(watcher.poll_states()) if cfg.get('poll_states', False) else None,
        asyncio.create_task(watcher.autosave_rdns()),
        asyncio.create_task(watcher.pf_tables.poll_loop()) if cfg.get('ip_tables') else None,
    ]
    tasks = [t for t in tasks if t is not None]

    try:
        while True:
            # simple UI loop inline (avoids double clear + tail flicker)
            watcher.render()
            await asyncio.sleep(cfg.get('refresh_secs', 3))
    except asyncio.CancelledError:
        pass
    finally:
        watcher.resolver.shutdown()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
