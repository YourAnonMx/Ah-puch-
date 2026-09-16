#!/usr/bin/env python3
import os
import sys
import json
import re
import time
import random
import concurrent.futures
import requests
import urllib3

from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
from colorama import init

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"
session = requests.Session()

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]      Ah-Puch – Clickjacking Test")
    console.print(f"[{TEAL}]{bar}\n")

def crawl(seed: str, limit: int, timeout: int):
    if not str(seed or "").strip():
        return []
    limit = max(1, int(limit))
    seen = {seed}
    queue = [seed]
    idx = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Crawling pages…", total=limit, url=seed)
        while idx < len(queue) and len(seen) < limit:
            url = queue[idx]
            prog.update(task, advance=1, url=url)
            try:
                r = session.get(url, timeout=timeout, verify=True)
                for link in re.findall(r'href=["\']([^"\'#]+)', r.text):
                    full = urljoin(url, link)
                    if full.startswith(("http://", "https://")) and urlparse(full).netloc == urlparse(seed).netloc and full not in seen:
                        seen.add(full)
                        queue.append(full)
            except (requests.RequestException, OSError):
                pass
            idx += 1
    return list(seen)

def assess(url: str, timeout: int):
    if not str(url or "").strip():
        return url, "ERR", "ERR", "Unknown"
    try:
        r = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
        xfo = r.headers.get("X-Frame-Options", "-")
        csp = r.headers.get("Content-Security-Policy", "-")
    except Exception:
        return url, "ERR", "ERR", "Unknown"
    truncated = (csp[:60] + "…") if len(csp) > 60 else csp
    safe = "-"
    if xfo.upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp.lower() and "none" in csp.lower():
        safe = "Y"
    return url, xfo, truncated, "No" if safe == "Y" else "Yes"

def table_out(rows, title="Clickjacking Test"):
    tbl = Table(
        title=title,
        header_style="bold magenta",
        box=box.MINIMAL
    )
    tbl.add_column("URL", style="cyan", overflow="fold")
    tbl.add_column("X-Frame-Options", style="green")
    tbl.add_column("CSP (truncated)", style="yellow")
    tbl.add_column("Vulnerable?", style="red", justify="center")
    for r in rows:
        tbl.add_row(*r)
    console.print(tbl)
    return tbl

def run(target: str, threads: int, opts: dict):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    threads = max(1, int(threads))
    pages   = max(1, int(opts.get("max_pages", 60)))
    ratio   = min(1.0, max(0.0, float(opts.get("sample_ratio", 0.3))))
    domain = clean_domain_input(target)
    if not domain:
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return
    start = time.time()
    seed = f"https://{domain}"

    console.print(f"[white][*] Crawling up to [yellow]{pages}[/yellow] pages on [cyan]{domain}[/cyan][/white]")
    urls = crawl(seed, pages, timeout)
    sample = random.sample(urls, max(1, min(len(urls), int(len(urls) * ratio))))
    console.print(f"[white][*] Testing [green]{len(sample)}[/green] pages for clickjacking[/white]\n")

    rows = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]Testing…[/white]"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("", total=len(sample))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for res in pool.map(lambda u: assess(u, timeout), sample):
                rows.append(res)
                prog.advance(task)

    tbl = table_out(rows, f"Clickjacking Test – {domain}")
    vuln_count = sum(1 for r in rows if r[3] == "Yes")
    safe_count = len(rows) - vuln_count
    summary = f"Vulnerable: {vuln_count}  Safe: {safe_count}  Elapsed: {time.time() - start:.2f}s"
    panel = Panel(summary, title="Summary", style="bold white")
    console.print(panel)
    console.print("[green][*] Clickjacking test completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(tbl)
        export_console.print(panel)
        write_to_file(os.path.join(out, "clickjacking_test.txt"), export_console.export_text())

if __name__ == "__main__":
    start = time.time()
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            opts = {}
    run(tgt, thr, opts)
