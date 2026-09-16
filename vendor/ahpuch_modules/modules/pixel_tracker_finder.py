#!/usr/bin/env python3
import os
import sys
import re
import requests
import urllib3
import warnings
from urllib.parse import urljoin, urlparse
from collections import deque
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)
console = Console()
TEAL = "#2EC4B6"

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

MAX_PAGES = 30
pat_link = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)
pat_img  = re.compile(r"<img([^>]*)>", re.I)
pat_attr = re.compile(r'([a-zA-Z_:-]+)\s*=\s*["\']([^"\']*)["\']')
tracker_signals = (
    "pixel","track","analytics","beacon","utm_","ga('create","gtag(",
    "ads","conversion","collect"
)

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch - Pixel Tracker Finder")
    console.print(f"[{TEAL}]{bar}\n")

def fetch(url):
    target = str(url or "").strip()
    if not target:
        return "ERR", "", url
    try:
        r = requests.get(target, timeout=DEFAULT_TIMEOUT,
                         verify=True, allow_redirects=False)
        return r.status_code, r.text, r.url
    except (requests.RequestException, OSError, ValueError):
        return "ERR", "", url

def crawl(domain):
    if not str(domain or "").strip():
        return []
    for scheme in ("https","http"):
        root = f"{scheme}://{domain}"
        code, html, final = fetch(root)
        if code != "ERR":
            break
    else:
        return []

    rootloc = urlparse(final).netloc
    q = deque([final])
    seen = {final}
    pages = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.completed}/{task.total} pages"),
        BarColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Crawling…", total=MAX_PAGES)
        while q and len(pages) < MAX_PAGES:
            u = q.popleft()
            code, html, u2 = fetch(u)
            pages.append((u2, code, html))
            progress.advance(task)
            if code == "ERR" or not html:
                continue
            for m in pat_link.finditer(html):
                href = urljoin(u2, m.group(1))
                if (href.startswith("http") and
                    urlparse(href).netloc == rootloc and
                    href not in seen):
                    seen.add(href)
                    q.append(href)

    return pages

def classify_pixel(attrs, page_html, domain):
    w     = attrs.get("width","")
    h     = attrs.get("height","")
    style = attrs.get("style","").lower()
    src   = attrs.get("src","")
    host  = urlparse(src).netloc

    if w == "1" and h == "1":
        kind = "1x1 Pixel"
    elif "display:none" in style or "opacity:0" in style:
        kind = "Hidden"
    elif any(sig in src.lower() for sig in tracker_signals) or \
         any(sig in page_html.lower() for sig in tracker_signals):
        kind = "Tracker"
    else:
        kind = "Image"

    scope = "External" if host and domain not in host else "Internal"
    return scope, kind

def extract_pixels(url, html, domain):
    results = []
    for m in pat_img.finditer(html):
        attrs = {k.lower():v for k,v in pat_attr.findall(m.group(1))}
        if "src" not in attrs:
            continue
        src = urljoin(url, attrs["src"])
        scope, kind = classify_pixel(attrs, html, domain)
        results.append((url, src, scope, kind))
    return results

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    pages = crawl(domain)
    findings = []
    for url, code, html in pages:
        if code == "ERR" or not html:
            continue
        findings.extend(extract_pixels(url, html, domain))

    if findings:
        table = Table(title=f"Pixel Trackers – {domain}", header_style="bold magenta")
        table.add_column("Page", style="cyan", overflow="fold")
        table.add_column("Image URL", style="green", overflow="fold")
        table.add_column("Scope", style="yellow")
        table.add_column("Type", style="white")
        for row in findings:
            table.add_row(*row)
        console.print(table)
    else:
        console.print("[yellow][!] No pixel/trackers discovered across sampled pages.[/yellow]")

    console.print("[green][*] Pixel tracker scan completed[/green]")
