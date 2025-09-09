#!/usr/bin/env python3
# pfwatch.py — PF pflog watcher with:
# - GeoIP (local mmdb)
# - background rDNS with persistent JSON cache
# - YAML ip_map overrides (single IP or CIDR) for non-resolvable IPs
# - PF states snapshot
# - rolling, scrollable “top” view (curses UI) with IP/fragment filter
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
import curses
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional, Dict, Tuple, Union

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
            if self.cache_path:
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
        # ip_map supports single IP or CIDR
        self.ip_map = []
        for k, v in cfg.get('ip_map', {}).items():
            try:
                net = ipaddress.ip_network(k, strict=False)
            except Exception:
                continue
            self.ip_map.append((net, str(v)))

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

        # UI filter (applied)
        self.filter_q = ""

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

    def name_for_ip(self, ip: str) -> str:
        try:
            ipobj = ipaddress.ip_address(ip)
        except ValueError:
            return ''
        # 1) ip_map
        for net, label in self.ip_map:
            if ipobj in net:
                return label
        # 2) rDNS
        if self.reverse_dns_enabled:
            return self.resolver.get(ip) or ''
        return ''

    def handle_packet(self, ts: float, src_ip: str, src_port, dst_ip: str, dst_port, proto: str, length: int):
        now = ts
        src_int = self.is_internal(src_ip)
        dst_int = self.is_internal(dst_ip)

        if src_int and not dst_int:
            self.per_host_out[src_ip].add(now, length)
            self.per_country[ip_to_country(dst_ip)].add(now, length)
            name = self.name_for_ip(dst_ip)
            if name:
                self.per_domain[name].add(now, length)
            elif self.reverse_dns_enabled:
                self.resolver.submit(dst_ip)

        elif dst_int and not src_int:
            self.per_host_in[dst_ip].add(now, length)
            self.per_country[ip_to_country(src_ip)].add(now, length)
            name = self.name_for_ip(src_ip)
            if name:
                self.per_domain[name].add(now, length)
            elif self.reverse_dns_enabled:
                self.resolver.submit(src_ip)

        elif src_int and dst_int:
            self.per_host_out[src_ip].add(now, length)
            self.per_host_in[dst_ip].add(now, length)
        # external<->external ignored

    # ---------- helpers ----------
    def _match_filter_ip_or_name(self, ip_str: str) -> bool:
        q = (self.filter_q or "").strip()
        if not q:
            return True
        s = str(ip_str)
        if q in s:
            return True
        nm = self.name_for_ip(s) or ""
        return q.lower() in nm.lower()

    def _sorted_items(self, counter_map, now, kind="host"):
        items = []
        for k, rc in counter_map.items():
            b, p = rc.snapshot(now)
            if not (b or p):
                continue
            if kind == "host":
                if not self._match_filter_ip_or_name(k):
                    continue
            elif kind == "domain":
                q = (self.filter_q or "").strip().lower()
                if q and q not in str(k).lower():
                    continue
            items.append((b, p, k))
        items.sort(key=lambda t: (-t[0], -t[1], str(t[2])))
        return items

    # ---------- UI sizing (limit panes to ≤ ui_pane_max_ratio of available) ----------
    def _calc_pane_h(self, screen_h: int, pane_start_y: int) -> int:
        reserved_bottom = 8
        available = max(0, screen_h - pane_start_y - reserved_bottom)
        ratio = float(self.cfg.get('ui_pane_max_ratio', 0.5))
        ratio = min(max(ratio, 0.1), 1.0)
        if available == 0:
            return 0
        pane_h = min(available, int(available * ratio) or available)
        return max(5, pane_h)

    # ---------- curses UI ----------
    def render_curses(self, stdscr, offsets, editing_filter: bool, edit_buffer: str):
        now = time.time()
        h, w = stdscr.getmaxyx()
        stdscr.erase()

        def safe_add(y, x, s, attr=0):
            try:
                if y < h and x < w and y >= 0 and x >= 0:
                    stdscr.addnstr(y, x, s, max(0, w - x), attr)
            except curses.error:
                pass

        title = f"PF Watch — live (window={self.cfg['window_secs']}s)  {datetime.now():%Y-%m-%d %H:%M:%S}"
        safe_add(0, 0, title, curses.A_BOLD)
        safe_add(1, 0, "═" * (w-1))

        y = 2
        if self.reverse_dns_enabled:
            fr, pn, fl, total = self.resolver.stats()
            safe_add(y, 0, f"rDNS cache: fresh={fr} pending={pn} failed={fl} total={total}")
            y += 1

        # Filter indicator / input
        filt = self.filter_q.strip()
        if filt:
            safe_add(y, 0, f"Filter: {filt}", curses.A_DIM)
            y += 1
        if editing_filter:
            safe_add(y, 0, f"Enter filter (IP/fragment), Enter=apply, Esc=clear: {edit_buffer}", curses.A_BOLD)
            y += 1

        pane_top = y + 1
        safe_add(y, 0, "Outbound (internal → external) — sorted, scroll with Q/A", curses.A_UNDERLINE)
        right_hdr = "Inbound (external → internal) — scroll with W/S"
        safe_add(y, max(w // 2, len("Outbound (internal → external) — sorted, scroll with Q/A") + 2),
                 right_hdr, curses.A_UNDERLINE)

        left_x = 0
        right_x = w // 2
        pane_h = self._calc_pane_h(h, pane_top)

        # compute ordered (and filtered) lists
        out_items = self._sorted_items(self.per_host_out, now, kind="host")
        in_items  = self._sorted_items(self.per_host_in,  now, kind="host")

        def draw_pane(x, items, offset, title_cols=("Host","Bytes","Pkts")):
            hdr = f"{title_cols[0]:<20} {title_cols[1]:>14} / {title_cols[2]:>7}"
            safe_add(pane_top, x, hdr, curses.A_DIM | curses.A_BOLD)
            if not items:
                safe_add(pane_top + 1, x, "(no matches)" if self.filter_q else "(no traffic yet)", curses.A_DIM)
            else:
                visible = items[offset: offset + pane_h]
                for idx, (b, p, k) in enumerate(visible, start=1):
                    label = self.name_for_ip(k) or str(k)
                    line = f"{label:<20.20} {b:>14,} / {p:>7}"
                    safe_add(pane_top + idx, x, line)
                total = len(items)
                end = min(offset + pane_h, total)
                status = f"[{offset+1 if total else 0}-{end}/{total}]"
                safe_add(pane_top + pane_h + 1, x, status, curses.A_DIM)

        draw_pane(left_x,  out_items, offsets['out'])
        draw_pane(right_x, in_items,  offsets['in'])

        y = pane_top + pane_h + 3
        safe_add(y, 0, "Top countries (bytes / pkts):", curses.A_UNDERLINE); y += 1
        for b, p, c in self._sorted_items(self.per_country, now, kind="country")[:min(10, h - y - 6)]:
            safe_add(y, 0, f"  {c:>3}  {b:>12,}  / {p:>7}"); y += 1

        if y < h - 5:
            safe_add(y, 0, "Top domains (with categories):", curses.A_UNDERLINE); y += 1
            dom_rows_avail = max(0, h - y - 4)
            for b, p, dom in self._sorted_items(self.per_domain, now, kind="domain")[:dom_rows_avail]:
                cat = self.categorize_domain(dom)
                safe_add(y, 0, f"  {dom:<40.40} {b:>12,} / {p:>7}   [{cat}]"); y += 1

        if self.cfg.get('poll_states', False) and y < h - 2:
            safe_add(y, 0, "Active connections snapshot:", curses.A_UNDERLINE); y += 1
            q = (self.filter_q or "").strip().lower()
            shown = 0
            for line in self.active_states:
                if q and q not in line.lower():
                    continue
                if y >= h - 1:
                    break
                safe_add(y, 2, line); y += 1; shown += 1
            if shown == 0:
                safe_add(y, 2, "(no matches)" if q else "(no data)", curses.A_DIM)

        if h > 2:
            helpmsg = "Keys: Q/A Out • W/S In • '/' filter • Esc clear filter • Ctrl-C quit"
            safe_add(h-2, 0, helpmsg, curses.A_DIM)

        stdscr.refresh()

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
                        src_name = self.name_for_ip(src.split(':')[0]) or src
                        dst_name = self.name_for_ip(dst.split(':')[0]) or dst
                        snapshot.append(f"{proto:<4} {src_name} -> {dst_name}")
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

# ---------------- entrypoints ----------------
async def _run_with_curses(stdscr, cfg):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    load_geoip(cfg.get('geoip_mmdb', None))
    watcher = PFWatch(cfg)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except NotImplementedError:
            pass

    tasks = [
        asyncio.create_task(watcher.run_tcpdump()),
        asyncio.create_task(watcher.poll_states()) if cfg.get('poll_states', False) else None,
        asyncio.create_task(watcher.autosave_rdns()),
    ]
    tasks = [t for t in tasks if t is not None]

    offsets = {'out': 0, 'in': 0}

    # filter editing state
    editing_filter = False
    edit_buffer = ""
    applied_filter = ""

    try:
        while True:
            try:
                ch = stdscr.getch()
                if ch != -1:
                    if editing_filter:
                        if ch in (27,):  # ESC
                            edit_buffer = ""
                            applied_filter = ""
                            watcher.filter_q = ""
                            editing_filter = False
                        elif ch in (10, 13):  # Enter
                            applied_filter = edit_buffer.strip()
                            watcher.filter_q = applied_filter
                            editing_filter = False
                            # reset scroll when filter changes
                            offsets['out'] = offsets['in'] = 0
                        elif ch in (curses.KEY_BACKSPACE, 127, 8):
                            edit_buffer = edit_buffer[:-1]
                        elif 32 <= ch <= 126:
                            edit_buffer += chr(ch)
                    else:
                        if ch in (ord('q'), ord('Q')):
                            offsets['out'] = max(0, offsets['out'] - 1)
                        elif ch in (ord('a'), ord('A')):
                            offsets['out'] = offsets['out'] + 1
                        elif ch in (ord('w'), ord('W')):
                            offsets['in'] = max(0, offsets['in'] - 1)
                        elif ch in (ord('s'), ord('S')):
                            offsets['in'] = offsets['in'] + 1
                        elif ch == ord('/'):
                            editing_filter = True
                            edit_buffer = watcher.filter_q

                # clamp offsets to list sizes using same pane height logic as renderer
                now = time.time()
                h, w = stdscr.getmaxyx()
                base_y = 2
                if watcher.reverse_dns_enabled:
                    base_y += 1
                if watcher.filter_q:
                    base_y += 1
                if editing_filter:
                    base_y += 1
                pane_top = base_y + 1
                pane_h = watcher._calc_pane_h(h, pane_top)

                out_len = len(watcher._sorted_items(watcher.per_host_out, now, kind="host"))
                in_len  = len(watcher._sorted_items(watcher.per_host_in,  now, kind="host"))

                max_out = max(0, out_len - pane_h)
                max_in  = max(0, in_len  - pane_h)
                offsets['out'] = min(offsets['out'], max_out)
                offsets['in']  = min(offsets['in'],  max_in)
            except Exception:
                pass

            watcher.render_curses(stdscr, offsets, editing_filter, edit_buffer)
            await asyncio.sleep(cfg.get('refresh_secs', 3))
    except asyncio.CancelledError:
        pass
    finally:
        watcher.resolver.shutdown()
        for t in tasks:
            t.cancel()

def _load_cfg_from_argv():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} pfwatch.yml", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], 'r') as f:
        cfg = yaml.safe_load(f)
    cfg.setdefault('window_secs', 300)
    cfg.setdefault('refresh_secs', 3)
    cfg.setdefault('poll_states', True)
    cfg.setdefault('states_poll_secs', 5)
    cfg.setdefault('rdns_ttl_secs', 24*3600)
    cfg.setdefault('rdns_workers', 16)
    cfg.setdefault('rdns_save_secs', 60)
    cfg.setdefault('ui', 'curses')
    cfg.setdefault('ui_pane_max_ratio', 0.5)
    for key in ("geoip_mmdb", "rdns_cache_path", "tcpdump_path", "pfctl_path"):
        val = cfg.get(key)
        if isinstance(val, str) and val.startswith("~"):
            cfg[key] = os.path.expanduser(val)
    return cfg

def _run_plain(cfg):
    load_geoip(cfg.get('geoip_mmdb', None))
    watcher = PFWatch(cfg)

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except NotImplementedError:
            pass

    async def driver():
        tasks = [
            asyncio.create_task(watcher.run_tcpdump()),
            asyncio.create_task(watcher.poll_states()) if cfg.get('poll_states', False) else None,
            asyncio.create_task(watcher.autosave_rdns()),
        ]
        tasks = [t for t in tasks if t is not None]
        try:
            while True:
                os.system('clear')
                now = time.time()
                print(f"PF Watch — live (window={cfg['window_secs']}s)  {datetime.now():%Y-%m-%d %H:%M:%S}")
                print("="*120)
                if watcher.reverse_dns_enabled:
                    fr, pn, fl, total = watcher.resolver.stats()
                    print(f"rDNS cache: fresh={fr} pending={pn} failed={fl} total={total}")
                def dump(title, items, limit=10):
                    print(f"\n{title}")
                    for b, p, k in items[:limit]:
                        print(f"  {str(k):<20.20} {b:>14,} / {p:>7}")
                dump("Outbound (internal → external):",
                     watcher._sorted_items(watcher.per_host_out, now))
                dump("Inbound (external → internal):",
                     watcher._sorted_items(watcher.per_host_in, now))
                dump("Top countries (bytes / pkts):",
                     [(b,p,c) for (b,p,c) in watcher._sorted_items(watcher.per_country, now, kind="country")])
                print("\nTop domains (with categories):")
                for b,p,dom in watcher._sorted_items(watcher.per_domain, now, kind="domain")[:10]:
                    cat = watcher.categorize_domain(dom)
                    print(f"  {dom:<40.40} {b:>12,} / {p:>7}   [{cat}]")
                if cfg.get('poll_states', False):
                    print("\nActive connections snapshot:")
                    for line in watcher.active_states[:20]:
                        print("  " + line)
                await asyncio.sleep(cfg.get('refresh_secs', 3))
        finally:
            watcher.resolver.shutdown()
            for t in tasks:
                t and t.cancel()

    asyncio.run(driver())

# ---------------- main ----------------
if __name__ == '__main__':
    cfg = _load_cfg_from_argv()
    if cfg.get('ui', 'curses') == 'curses':
        def _wrapper(stdscr):
            asyncio.run(_run_with_curses(stdscr, cfg))
        try:
            curses.wrapper(_wrapper)
        except KeyboardInterrupt:
            pass
    else:
        try:
            _run_plain(cfg)
        except KeyboardInterrupt:
            pass
