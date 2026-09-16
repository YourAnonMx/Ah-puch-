import os
import sys
import json
import re
import requests
from urllib.parse import quote
import dns.resolver
import urllib3
import math
import asyncio
import aiohttp
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

console = Console()
TEAL = "#2EC4B6"
ENTROPY_THR = 4.0
DAYS_DEFAULT = 30

async def fetch_json(url, timeout):
    if not url or not str(url).strip():
        return None
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as sess:
            async with sess.get(url, allow_redirects=False) as r:
                if r.status == 200:
                    return await r.json(content_type=None)
                return None
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, TypeError, ValueError):
        return None

async def gather_sources(dom, timeout):
    if not dom or not str(dom).strip():
        return defaultdict(lambda: {"src": set(), "dates": []})
    ct_url = f"https://crt.sh/?q=%25.{quote(dom)}&output=json"
    pdns_url = f"https://dns.bufferover.run/dns?q={dom}"
    tc_url = f"https://api.threatcrowd.org/v2/domain/report/?domain={dom}"
    tasks = [fetch_json(ct_url, timeout), fetch_json(pdns_url, timeout), fetch_json(tc_url, timeout)]
    results = await asyncio.gather(*tasks)
    out = defaultdict(lambda: {"src": set(), "dates": []})
    if results[0]:
        for rec in results[0]:
            for name in rec.get("name_value", "").split():
                if name.endswith(dom):
                    out[name]["src"].add("CT")
                    out[name]["dates"].append(rec.get("not_before"))
    if results[1]:
        for entry in (results[1].get("FDNS_A", []) + results[1].get("RDNS", [])):
            host = entry.split(",")[-1].strip()
            if host.endswith(dom):
                out[host]["src"].add("pDNS")
    if results[2] and results[2].get("subdomains"):
        for sub in results[2]["subdomains"]:
            if sub.endswith(dom):
                out[sub]["src"].add("ThreatCrowd")
    return out

def entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())

async def run(target, threads, opts):
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]        Ah-Puch – Domain Shadowing Detector")
    console.print(f"[{TEAL}]{bar}\n")

    if not target or not str(target).strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 60))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    try:
        days = max(1, min(int(opts.get("days", DAYS_DEFAULT)), 3650))
    except (TypeError, ValueError):
        days = DAYS_DEFAULT
    dom = clean_domain_input(target)
    if not dom:
        return 2
    console.print(f"[*] Enumerating recent sub-domains (<= {days} days) for [cyan]{dom}[/cyan]\n")

    raw_map = await gather_sources(dom, timeout)

    rows = []
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    for host, info in raw_map.items():
        dates = []
        for value in info["dates"]:
            if not value:
                continue
            try:
                dates.append(datetime.fromisoformat(str(value).split()[0]))
            except (AttributeError, TypeError, ValueError):
                continue
        if dates and all(d < cutoff for d in dates):
            continue
        label = host.split(".")[0]
        ent = entropy(label)
        flag = "Y" if ent >= ENTROPY_THR else "-"
        srcs = ",".join(sorted(info["src"]))
        rows.append((host, srcs, flag, f"{ent:.2f}"))
    rows.sort()

    table = Table(title=f"Shadowing Analysis – {dom}", show_header=True, header_style="bold white")
    for col in ["Sub-Domain", "Sources", "High Entropy?", "Entropy"]:
        table.add_column(col, overflow="fold")
    for r in rows:
        table.add_row(*r)

    console.print(table if rows else "[yellow]No recent sub-domains found[/yellow]")
    console.print("[green][*] Shadowing detection completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out_dir, "domain_shadowing.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = sys.argv[2] if len(sys.argv) > 2 else "4"
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError):
        opts = {}
    raise SystemExit(asyncio.run(run(tgt, thr, opts)))
