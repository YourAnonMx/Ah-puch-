#!/usr/bin/env python3
import os, sys, json, re, time, requests, urllib.parse
from collections import Counter, deque
from tabulate import tabulate
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

console = Console()
DEFAULT_RATE = 0.2

def banner():
    console.print("[cyan]" + "="*40)
    console.print("[cyan]            Ah-Puch – Web Crawler")
    console.print("[cyan]" + "="*40)

def run(target, threads, opts):
    banner()
    dom        = clean_domain_input(target)
    base       = opts.get("start_url") or f"https://{dom}"
    max_pages  = int(opts.get("max_pages", 400))
    depth_lim  = int(opts.get("depth", 3))
    rate       = float(opts.get("rate_limit", DEFAULT_RATE))
    timeout    = max(0.1, float(opts.get("timeout", DEFAULT_TIMEOUT)))
    verify_ssl = bool(opts.get("verify_ssl", True))

    console.print(f"[white]* Start: [cyan]{base}[/cyan] – pages:[yellow]{max_pages}[/yellow] depth:[yellow]{depth_lim}[/yellow][/white]")

    q, seen, pages, counter = deque([(base,0)]), {base}, [], Counter()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as pg:
        tk = pg.add_task("Crawling…", total=max_pages)
        while q and len(pages) < max_pages:
            url, d = q.popleft()
            try:
                # Delay only between requests. Sleeping before the first request
                # wastes one complete rate interval and made bounded runs exceed
                # their outer deadline even when every request was local/fast.
                if pages and rate > 0:
                    time.sleep(rate)
                r = requests.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
                ct = r.headers.get("Content-Type","").split(";")[0]
                status = r.status_code
            except requests.RequestException:
                ct, status = "-", "ERR"
            pages.append([url, status, ct])
            counter[ct or "unknown"] += 1
            if d < depth_lim and "html" in ct:
                for h in re.findall(r'href=["\']([^"\']+)', r.text, re.I):
                    u = urllib.parse.urljoin(url, h.split("#")[0])
                    if u.startswith("http") and urllib.parse.urlparse(u).netloc == urllib.parse.urlparse(base).netloc and u not in seen:
                        seen.add(u); q.append((u, d+1))
            pg.advance(tk)

    console.print(f"[white]* Crawled [green]{len(pages)}[/green] pages[/white]")
    console.print("[white]Content-Type summary:[/white]")
    for k,v in counter.items(): console.print(f"  • {k or 'unknown'}: {v}")

    tbl = tabulate(pages, headers=["URL","Status","Content-Type"], tablefmt="grid")
    console.print(tbl)
    console.print("[green]* Web crawl completed[/green]")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out, "web_crawl.txt"), tbl)

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv)>1 else ""
    thr = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 4
    opts = {}
    if len(sys.argv)>3:
        try: opts = json.loads(sys.argv[3])
        except: pass
    run(tgt, thr, opts)
