#!/usr/bin/env python3
import os
import sys
import time
import requests
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, API_KEYS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

def banner():
    console.print("""
==============================================
 Ah-Puch - Advanced Website Carbon & Resource Profiler
==============================================
""")

def normalize(url):
    if not url.startswith(('http://','https://')):
        url = 'http://' + url
    return url

def fetch_html(url, timeout):
    start = time.time()
    r = requests.get(url, timeout=timeout, verify=True)
    return r.text, time.time() - start, len(r.content)

def extract_assets(html, base):
    soup = BeautifulSoup(html, 'html.parser')
    tags = {
        'img':'src', 'script':'src', 'link':'href',
        'video':'src', 'audio':'src'
    }
    assets = set()
    for tag, attr in tags.items():
        for t in soup.find_all(tag):
            u = t.get(attr)
            if u:
                full = urljoin(base, u)
                assets.add(full)
    return list(assets)

def classify(url):
    ext = urlparse(url).path.split('.')[-1].lower()
    if ext in ('js','mjs'): return 'script'
    if ext == 'css':      return 'style'
    if ext in ('jpg','jpeg','png','gif','webp','svg'): return 'image'
    if ext in ('woff','woff2','ttf','otf'): return 'font'
    if ext in ('mp4','webm','ogg'): return 'media'
    return 'other'

def get_size(url, timeout):
    try:
        r = requests.head(url, timeout=timeout, verify=True)
        size = r.headers.get('Content-Length')
        if size and size.isdigit():
            return int(size), r.elapsed.total_seconds()
    except:
        pass
    try:
        r = requests.get(url, timeout=timeout, verify=True)
        return len(r.content), r.elapsed.total_seconds()
    except:
        return 0, 0.0

def get_official_co2(url, timeout):
    key = API_KEYS.get("WEBSITE_CARBON_API_KEY","")
    if not key:
        return None
    api = f"https://api.websitecarbon.com/site?url={url}"
    r = requests.get(api, headers={"Authorization":f"Bearer {key}"}, timeout=timeout, verify=True)
    if r.ok:
        return r.json().get('statistics',{}).get('co2',{}).get('grid',{}).get('grams')
    return None

def run(target):
    banner()
    url = normalize(target.strip())
    console.print(f"[*] Profiling {url}\n")
    html, html_time, html_size = fetch_html(url, DEFAULT_TIMEOUT)
    assets = extract_assets(html, url)
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Fetching assets", total=len(assets), url="")
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(get_size, a, DEFAULT_TIMEOUT): a for a in assets}
            for fut in as_completed(futures):
                a = futures[fut]
                sz, t = fut.result()
                tp = classify(a)
                third = urlparse(a).netloc != urlparse(url).netloc
                results.append((a, tp, sz, t, '3rd' if third else '1st'))
                prog.update(task, advance=1, url=a[:30] + "…")
    by_type = {}
    for _, tp, sz, t, dom in results:
        rec = by_type.setdefault(tp, {'count':0,'size':0,'time':0.0,'third':0})
        rec['count'] += 1
        rec['size']  += sz
        rec['time']  += t
        if dom == '3rd': rec['third'] += 1
    total_assets = len(results)
    total_size   = html_size + sum(r[2] for r in results)
    manual_co2   = total_size / (1024*1024) * 0.81
    official_co2 = get_official_co2(url, DEFAULT_TIMEOUT)
    summary_tbl = Table(show_header=True, header_style="bold white")
    summary_tbl.add_column("Metric", style="cyan")
    summary_tbl.add_column("Value", style="magenta")
    summary_tbl.add_row("HTML Size", f"{html_size} bytes")
    summary_tbl.add_row("HTML Load Time", f"{html_time:.2f} s")
    summary_tbl.add_row("Assets Count", str(total_assets))
    summary_tbl.add_row("Total Size", f"{total_size} bytes")
    summary_tbl.add_row("Manual CO2 Estimate", f"{manual_co2:.2f} g")
    if official_co2 is not None:
        summary_tbl.add_row("Official CO2 (API)", f"{official_co2:.2f} g")
    console.print(summary_tbl)
    detail_tbl = Table(show_header=True, header_style="bold white")
    detail_tbl.add_column("Type", style="cyan")
    detail_tbl.add_column("Count", justify="right")
    detail_tbl.add_column("Size(bytes)", justify="right")
    detail_tbl.add_column("Time(s)", justify="right")
    detail_tbl.add_column("3rd-party", justify="right")
    for tp, v in by_type.items():
        detail_tbl.add_row(
            tp,
            str(v['count']),
            str(v['size']),
            f"{v['time']:.2f}",
            str(v['third'])
        )
    console.print(detail_tbl)
    console.print(Panel(f"Total runtime: {html_time + sum(v['time'] for v in by_type.values()):.2f}s", title="Summary"))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        console.print("[!] No URL provided.")
