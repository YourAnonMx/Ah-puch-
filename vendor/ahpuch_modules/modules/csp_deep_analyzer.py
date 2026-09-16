#!/usr/bin/env python3
import os
import sys
import json
import re
import random
import time
import concurrent.futures
import requests
import urllib3

from urllib.parse import urljoin, urlparse
from collections import Counter, defaultdict
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

BASE_DIRECTIVES = {"default-src","script-src","object-src","base-uri","frame-ancestors"}
BAD_TOKENS = ("unsafe-inline","unsafe-eval","data:","blob:","filesystem:","*")
HTTP_RE = re.compile(r"\bhttp://",re.I)

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]     Ah-Puch – CSP Deep Analyzer")
    console.print(f"[cyan]{bar}\n")

def crawl(seed, limit, timeout):
    if not isinstance(seed, str) or not seed.strip():
        return []
    try:
        limit = int(limit)
        timeout = float(timeout)
    except (TypeError, ValueError):
        return []
    if limit <= 0:
        return []
    limit = min(limit, 500)
    q = [seed]
    seen = {seed}
    idx = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Crawling pages…", total=limit, url=seed)
        while idx < len(q) and len(seen) < limit:
            url = q[idx]
            prog.update(task, advance=1, url=url)
            try:
                r = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
                for u in re.findall(r'href=["\']([^"\'#]+)', r.text):
                    full = urljoin(url, u)
                    if full.startswith("http") and urlparse(full).netloc == urlparse(seed).netloc and full not in seen:
                        seen.add(full)
                        q.append(full)
            except (AttributeError, OSError, requests.RequestException, TypeError, ValueError):
                pass
            idx += 1
    return list(seen)

def extract_meta(html):
    m = re.search(r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)', html, re.I)
    return m.group(1) if m else None

def fetch_policy(url, timeout):
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        r = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
        header = r.headers.get("Content-Security-Policy")
        meta = extract_meta(r.text)
        return header if header else meta
    except (AttributeError, OSError, requests.RequestException, TypeError, ValueError):
        return None

def tokenize(policy):
    out = []
    for directive in policy.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        out.append((parts[0], parts[1:] if len(parts) > 1 else []))
    return out

def analyse(policy):
    severity = "LOW"
    issues = []
    dirs = dict(tokenize(policy))
    missing = sorted(BASE_DIRECTIVES - dirs.keys())
    if missing:
        issues.append("Missing:" + ",".join(missing))
    bad = []
    for d, vals in dirs.items():
        for b in BAD_TOKENS:
            if any(b in v for v in vals):
                bad.append(f"{d}:{b}")
    if bad:
        issues.append("Weak:" + ",".join(bad))
        severity = "HIGH"
    if HTTP_RE.search(policy):
        issues.append("Insecure:http")
        severity = "HIGH"
    return severity, issues, dirs

def run(target, threads, opts):
    if not isinstance(target, str) or not target.strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    banner()
    start = time.time()
    try:
        timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    timeout = min(max(timeout, 1), 60)
    try:
        pages = int(opts.get("max_pages", 100))
    except (TypeError, ValueError):
        pages = 100
    pages = min(max(pages, 1), 500)
    try:
        ratio = float(opts.get("sample_ratio", 0.4))
    except (TypeError, ValueError):
        ratio = 0.4
    ratio = min(max(ratio, 0.0), 1.0)
    try:
        threads = int(threads)
    except (TypeError, ValueError):
        threads = 1
    threads = min(max(threads, 1), 32)
    domain = clean_domain_input(target)
    seed = f"https://{domain}"

    console.print(f"[white][*] Crawling up to [yellow]{pages}[/yellow] pages on [cyan]{domain}[/cyan][/white]")
    urls = crawl(seed, pages, timeout)
    if not urls:
        console.print("[yellow][*] No reachable pages to analyze[/yellow]")
        return 1
    sample = random.sample(urls, min(len(urls), max(1, int(len(urls) * ratio))))
    console.print(f"[white][*] Collecting CSP from [green]{len(sample)}[/green] pages[/white]\n")

    findings = []
    dir_counter = Counter()
    ext_scripts = defaultdict(int)
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Analyzing CSP…", total=len(sample), url=sample[0])
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch_policy, u, timeout): u for u in sample}
            for fut in concurrent.futures.as_completed(futures):
                url = futures[fut]
                policy = fut.result()
                prog.update(task, advance=1, url=url)
                if policy:
                    sev, issues, dirs = analyse(policy)
                    findings.append((url, sev, " | ".join(issues) if issues else "-"))
                    for d in dirs:
                        dir_counter[d] += 1
                    for src in dirs.get("script-src", []):
                        if src.startswith("http"):
                            ext_scripts[src] += 1

    headers_tbl = Table(title="CSP Findings", header_style="bold magenta", box=box.MINIMAL)
    headers_tbl.add_column("URL", overflow="fold", style="cyan")
    headers_tbl.add_column("Severity", style="green")
    headers_tbl.add_column("Issues", style="yellow")
    for row in findings:
        headers_tbl.add_row(*row)
    console.print(headers_tbl)

    summary_tbl = Table(title="Directive Counts", header_style="bold magenta", box=box.MINIMAL)
    summary_tbl.add_column("Directive", style="cyan")
    summary_tbl.add_column("Count", style="green")
    for d, c in dir_counter.most_common():
        summary_tbl.add_row(d, str(c))
    console.print(summary_tbl)

    if ext_scripts:
        ext_tbl = Table(title="External Script Sources", header_style="bold magenta", box=box.MINIMAL)
        ext_tbl.add_column("Source", style="cyan", overflow="fold")
        ext_tbl.add_column("Count", style="green")
        for src, c in sorted(ext_scripts.items(), key=lambda x: -x[1]):
            ext_tbl.add_row(src, str(c))
        console.print(ext_tbl)

    high = sum(1 for _, s, _ in findings if s == "HIGH")
    low = len(findings) - high
    summary = f"Pages: {len(sample)}  HIGH: {high}  LOW: {low}  Elapsed: {time.time()-start:.2f}s"
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] CSP deep analysis completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(headers_tbl)
        export_console.print(summary_tbl)
        if ext_scripts:
            export_console.print(ext_tbl)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "csp_analysis.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            opts = {}
    sys.exit(run(tgt, thr, opts))
