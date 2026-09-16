#!/usr/bin/env python3
import os
import sys
import re
import requests
from urllib.parse import urljoin, urlparse
from collections import Counter, defaultdict, deque
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input

requests.packages.urllib3.disable_warnings()

DEFAULT_MAX_PAGES = 100
DEFAULT_INCLUDE_SUBDOMAINS = False

CAT_ANALYTICS = ("google-analytics","googletagmanager","gtm","segment","mixpanel","amplitude","snowplow")
CAT_ADS       = ("doubleclick","adservice","adsystem","adnxs","criteo","taboola","outbrain")
CAT_SOCIAL    = ("facebook","fbcdn","twitter","t.co","linkedin","instagram","youtube","ytimg")
CAT_TAGS      = ("tag","tracker","pixel")

SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)

console = Console()

def banner():
    console.print("""
    =============================================
     Ah-Puch - Third-Party Script Risk Profiler
    =============================================
    """)

def parse_opts(argv):
    max_pages = DEFAULT_MAX_PAGES
    include_subs = DEFAULT_INCLUDE_SUBDOMAINS
    feed_path = None
    i = 3
    while i < len(argv):
        if argv[i] == "--max-pages" and i + 1 < len(argv):
            try:
                max_pages = int(argv[i+1])
            except (TypeError, ValueError):
                pass
            i += 2
            continue
        if argv[i] == "--include-subdomains":
            include_subs = True
            i += 1
            continue
        if argv[i] == "--feed" and i + 1 < len(argv):
            feed_path = argv[i+1]
            i += 2
            continue
        i += 1
    return max_pages, include_subs, feed_path

def norm_base(target):
    if not isinstance(target, str) or not target.strip():
        return ""
    if "://" not in target:
        target = "https://" + target
    if not target.endswith("/"):
        target += "/"
    return target

def same_domain(link, base_netloc, include_subs):
    host = urlparse(link).netloc.lower()
    if host == base_netloc:
        return True
    if include_subs and host.endswith("." + base_netloc):
        return True
    return False

def extract_links(html, base_url):
    links = []
    for m in re.finditer(r"(?:href|src)=['\"]([^'\"#]+)['\"]", html, re.I):
        links.append(urljoin(base_url, m.group(1)))
    return links

def crawl(start, max_pages, include_subs, timeout):
    if not isinstance(start, str) or not start.strip():
        return []
    try:
        max_pages = int(max_pages)
        timeout = float(timeout)
    except (TypeError, ValueError):
        return []
    if max_pages <= 0:
        return []
    max_pages = min(max_pages, 500)
    base_netloc = urlparse(start).netloc.lower()
    seen = {start}
    queue = deque([start])
    pages = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.completed}/{task.total} Crawling pages"),
        BarColumn(),
        console=console,
        transient=True
    ) as pg:
        task = pg.add_task("", total=max_pages)
        while queue and len(pages) < max_pages:
            url = queue.popleft()
            try:
                r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
            except (OSError, requests.RequestException, TypeError, ValueError):
                pg.advance(task)
                continue
            pages.append((url, r))
            pg.advance(task)
            ct = r.headers.get("Content-Type","")
            if "text/html" in ct:
                for link in extract_links(r.text, url):
                    if same_domain(link, base_netloc, include_subs) and link not in seen:
                        seen.add(link)
                        queue.append(link)
    return pages

def load_feed(path):
    feed = {}
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "," in line:
                        host, cat = line.split(",", 1)
                        feed[host.lower()] = cat
        except OSError:
            pass
    return feed

def classify_host(host, feed):
    h = host.lower()
    if h in feed:
        return feed[h]
    if any(x in h for x in CAT_ANALYTICS):
        return "analytics"
    if any(x in h for x in CAT_ADS):
        return "ads"
    if any(x in h for x in CAT_SOCIAL):
        return "social"
    if any(x in h for x in CAT_TAGS):
        return "tagmgr"
    return "unknown"

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
    raw = sys.argv[1]
    threads = sys.argv[2] if len(sys.argv) > 2 else "1"
    max_pages, include_subs, feed_path = parse_opts(sys.argv)
    domain = clean_domain_input(raw)
    base = norm_base(domain)
    if not base:
        console.print("[red][!] Invalid target.[/red]")
        sys.exit(2)
    feed = load_feed(feed_path)

    console.print(f"[white][*] Crawling up to {max_pages} pages (include_subdomains={include_subs}).[/white]")
    pages = crawl(base, max_pages, include_subs, DEFAULT_TIMEOUT)

    host_hits = Counter()
    host_samples = defaultdict(list)

    for url, resp in pages:
        ct = resp.headers.get("Content-Type","")
        if "text/html" not in ct:
            continue
        for src in SCRIPT_SRC_RE.findall(resp.text):
            full = urljoin(url, src)
            h = urlparse(full).netloc
            if not h:
                continue
            host_hits[h] += 1
            if len(host_samples[h]) < 3:
                host_samples[h].append(url)

    rows = []
    for host, count in host_hits.most_common():
        category = classify_host(host, feed)
        https_flag = "Y" if any(u.startswith("https://") for u in host_samples[host]) else "N"
        sample_pages = ",".join(host_samples[host])
        rows.append((host, category, str(count), https_flag, sample_pages))

    table = Table(title=f"Third-Party Script Risk: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Host", style="cyan", overflow="fold")
    table.add_column("Category", style="green")
    table.add_column("Hits", style="yellow")
    table.add_column("HTTPS?", style="white")
    table.add_column("Sample Pages", style="magenta", overflow="fold")

    if rows:
        for row in rows:
            table.add_row(*row)
        console.print(table)
    else:
        console.print("[yellow][!] No external script hosts observed.[/yellow]")

    console.print("[white][*] Third-party script risk profiling completed.[/white]")
