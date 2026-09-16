#!/usr/bin/env python3
import os
import sys
import json
import time
import random
import warnings
from urllib.parse import urljoin, urlencode
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

console = Console()

CANDIDATE_PATHS = [
    "/", "/login", "/api/", "/api/v1/status", "/admin", "/search",
    "/user", "/auth", "/graphql", "/rest/v1/"
]
VARIANTS = [
    lambda p: p,
    lambda p: p.upper(),
    lambda p: p.rstrip("/") + "/",
    lambda p: p + "?" + urlencode({"q": "test"}),
    lambda p: p.replace("/", "//"),
    lambda p: p.rstrip("/") + "/..;/",
    lambda p: p + "%2e%2e/",
    lambda p: p + "%2F",
]
HDR_SETS = [
    {},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
]

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]   Ah-Puch - Rate‑Limit & WAF Bypass Test")
    console.print(f"[cyan]{bar}\n")

def pick_base(domain, timeout):
    if not domain or not str(domain).strip():
        return None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
            return r.url
        except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
            pass
    return None

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def inject_random_ip(hdr):
    h = hdr.copy()
    if "X-Forwarded-For" in h and h["X-Forwarded-For"] in ("127.0.0.1", "10.0.0.1"):
        h["X-Forwarded-For"] = rand_ip()
    if "X-Real-IP" in h and h["X-Real-IP"] == "10.0.0.1":
        h["X-Real-IP"] = rand_ip()
    return h

def probe_once(url, hdrs, timeout):
    t0 = time.time()
    try:
        r = requests.get(url, headers=hdrs, timeout=timeout, verify=True, allow_redirects=False)
        dt = (time.time() - t0) * 1000
        return str(r.status_code), len(r.content), dt
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return "ERR", 0, 0.0

def run_burst(url, hdrs, timeout, batch_size):
    codes = []
    times = []
    blocked_at = None
    for i in range(batch_size):
        h = inject_random_ip(hdrs)
        code, _, dt = probe_once(url, h, timeout)
        codes.append(code)
        times.append(dt)
        if blocked_at is None and code in ("403", "429"):
            blocked_at = i + 1
    avg_rt = mean(times) if times else 0.0
    return codes, blocked_at, avg_rt

def build_targets(base):
    targets = []
    for p in CANDIDATE_PATHS:
        for fn in VARIANTS:
            path = fn(p)
            url = urljoin(base, path.lstrip("/"))
            targets.append(url)
    return list(dict.fromkeys(targets))

def run(target, threads, opts):
    banner()
    if not target or not str(target).strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 60))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    try:
        batch_size = max(1, min(int(opts.get("batch_size", 25)), 100))
    except (TypeError, ValueError):
        batch_size = 25
    try:
        thr = max(1, min(int(threads), 32))
    except (TypeError, ValueError):
        thr = 1
    domain = clean_domain_input(target)
    if not domain:
        return 2
    base = pick_base(domain, timeout)
    if not base:
        console.print("[red]✖ Unable to reach domain[/red]")
        return

    targets = build_targets(base)
    total = len(targets) * len(HDR_SETS)
    console.print(f"[white]* Testing {len(targets)} paths × {len(HDR_SETS)} header sets "
                  f"with {thr} threads, batch_size={batch_size}, timeout={timeout}s[/white]")

    rows = []
    futures = {}
    with ThreadPoolExecutor(max_workers=thr) as pool:
        for url in targets:
            for hdr in HDR_SETS:
                fut = pool.submit(run_burst, url, hdr, timeout, batch_size)
                futures[fut] = (url, hdr)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as pg:
            task = pg.add_task("Running bursts…", total=total)
            for fut in as_completed(futures):
                url, hdr = futures[fut]
                codes, blocked_at, avg_rt = fut.result()
                dominant = max(set(codes), key=codes.count)
                hdr_label = ";".join(f"{k}:{v}" for k, v in hdr.items()) or "-"
                rows.append((url, hdr_label, dominant, str(blocked_at or "-"), f"{avg_rt:.1f}ms"))
                pg.advance(task)

    table = Table(title=f"Rate‑Limit & WAF Results – {domain}", header_style="bold magenta")
    for col, style in [("URL", "cyan"), ("HdrSet", "green"), ("MainCode", "yellow"), ("BlockedAt", "white"), ("AvgRTT", "blue")]:
        table.add_column(col, style=style, overflow="fold")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[green]* Rate‑Limit & WAF bypass testing completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=160)
        export_console.print(table)
        export_console.print("* Rate‑Limit & WAF bypass testing completed")
        write_to_file(os.path.join(out, "rate_limit_waf_bypass.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = sys.argv[2] if len(sys.argv) > 2 else "10"
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            pass
    raise SystemExit(run(tgt, thr, opts))
