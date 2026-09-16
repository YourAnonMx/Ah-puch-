#!/usr/bin/env python3
import os
import sys
import json
import re
import time
import random
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()

LIB_REGEX = {
    "jquery":    r"jquery[-\.]([0-9.]+)\.js",
    "bootstrap": r"bootstrap[-\.]([0-9.]+)\.js",
    "angular":   r"angular[-\.]([0-9.]+)\.js",
    "react":     r"react[-\.]([0-9.]+)\.js",
    "vue":       r"vue(?:\.runtime)?[-\.]([0-9.]+)\.js"
}
CDNS = ("cloudflare", "googleapis", "cdn.jsdelivr", "cdnjs", "unpkg", "akamai", "fastly")

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]  Ah-Puch – Dependency JS/CDN Scanner")
    console.print(f"[cyan]{bar}\n")

def fetch(url, timeout):
    target = str(url or "").strip()
    if not target:
        return ""
    try:
        return session.get(target, timeout=timeout, verify=True, allow_redirects=False).text
    except (requests.RequestException, OSError, ValueError):
        return ""

def crawl(seed, limit, timeout, workers):
    if not str(seed or "").strip() or limit <= 0:
        return []
    workers = max(1, min(int(workers), 64))
    seen = {seed}
    queue = [seed]
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Crawling pages…", total=limit, url=seed)
        idx = 0
        while idx < len(queue) and len(seen) < limit:
            url = queue[idx]
            prog.update(task, url=url, advance=1)
            html = fetch(url, timeout)
            for link in re.findall(r'(?:href|src)=["\']([^"\'#]+)', html, re.I):
                full = urljoin(url, link)
                if full.startswith("http") and urlparse(full).netloc == urlparse(seed).netloc and full not in seen:
                    seen.add(full)
                    queue.append(full)
            idx += 1
    return list(seen)

def analyze(resource, base_domains):
    dom = urlparse(resource).netloc
    ext = dom not in base_domains
    cdn = next((c for c in CDNS if c in dom), "-")
    filename = os.path.basename(urlparse(resource).path)
    lib, ver = "-", "-"
    for name, rg in LIB_REGEX.items():
        m = re.search(rg, filename, re.I)
        if m:
            lib, ver = name, m.group(1)
            break
    return resource, "JS" if resource.endswith(".js") else "CSS", lib, ver, "Y" if ext else "-", cdn

def run(target, threads, opts):
    banner()
    start = time.time()
    domain = clean_domain_input(str(target or ""))
    if not domain:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        pages = max(1, min(int(opts.get("max_pages", 150)), 500))
        ratio = max(0.0, min(float(opts.get("sample_ratio", 0.30)), 1.0))
        workers = max(1, min(int(threads), 64))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid dependency-scanner options.[/red]")
        return 2
    seed = f"https://{domain}"

    console.print(f"[white][*] Crawling up to [yellow]{pages}[/yellow] pages on [cyan]{domain}[/cyan][/white]")
    urls = crawl(seed, pages, timeout, workers)
    chosen_count = min(len(urls), max(1, int(len(urls) * ratio))) if urls else 0
    chosen = random.sample(urls, chosen_count) if chosen_count else []
    console.print(f"[white][*] Inspecting [green]{len(chosen)}[/green] pages for dependencies[/white]\n")

    deps = set()
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Scanning pages…", total=len(chosen), url=next(iter(chosen), "-"))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(fetch, url, timeout): url for url in chosen}
            for fut in futures:
                html = fut.result()
                for link in re.findall(r'(?:src|href)=["\']([^"\'#]+)', html, re.I):
                    full = urljoin(futures[fut], link)
                    if full.startswith("http"):
                        deps.add(full)
                prog.update(task, advance=1, url=futures[fut])

    base_domains = {urlparse(seed).netloc}
    rows = []
    cdn_counter = Counter()
    external_count = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]Analyzing…[/white]"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog2:
        task2 = prog2.add_task("Analyzing resources…", total=len(deps), url=next(iter(deps), "-"))
        with ThreadPoolExecutor(max_workers=workers) as pool2:
            for res in pool2.map(lambda u: analyze(u, base_domains), sorted(deps)):
                rows.append(res)
                if res[4] == "Y":
                    external_count += 1
                if res[5] != "-":
                    cdn_counter[res[5]] += 1
                prog2.update(task2, advance=1, url=res[0])

    tbl = Table(title=f"Dependencies – {domain}", header_style="bold magenta", box=box.MINIMAL)
    for h in ("Resource", "Type", "Library", "Version", "External", "CDN"):
        tbl.add_column(h, overflow="fold")
    for r in rows:
        tbl.add_row(*r)
    console.print(tbl)

    top_cdns = ", ".join(f"{c}:{n}" for c, n in cdn_counter.most_common(5)) or "-"
    summary = (
        f"Total deps: {len(rows)}  "
        f"External: {external_count}  "
        f"Top CDNs: {top_cdns}  "
        f"Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] Total dependencies scanned[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(tbl)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(
            os.path.join(out_dir, "dependency_js_cdn_scanner.txt"),
            export_console.export_text()
        )
    return 0

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
