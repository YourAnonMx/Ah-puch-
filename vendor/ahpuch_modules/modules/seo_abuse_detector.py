#!/usr/bin/env python3
import os
import sys
import re
import json
import time
import warnings
import requests
import urllib3

from urllib.parse import urljoin, urlparse
from collections import deque
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)
console = Console()

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT


MAX_PAGES     = 25
UA_NORMAL     = "Mozilla/5.0 AhPuchSEO/1.0"
UA_GOOGLEBOT  = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SUS_CSS       = ("display:none","visibility:hidden","font-size:0","opacity:0",
                 "position:absolute","left:-9999px")
SUS_KEYWORDS  = ("casino","viagra","loan","btc","porn","sex","rx","cheap","free money")


def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]      Ah-Puch - SEO Abuse Detector")
    console.print(f"[cyan]{bar}\n")

def fetch(url, ua):
    target = str(url or "").strip()
    if not target:
        return "ERR", "", url
    try:
        r = requests.get(
            target,
            headers={"User-Agent": ua},
            timeout=DEFAULT_TIMEOUT,
            verify=True,
            allow_redirects=False
        )
        return r.status_code, r.text, r.url
    except (requests.RequestException, OSError, ValueError):
        return "ERR", "", url

def crawl(domain, ua):
    if not str(domain or "").strip():
        return []
    root = None
    for scheme in ("https","http"):
        code, html, final = fetch(f"{scheme}://{domain}", ua)
        if code != "ERR":
            root = final
            break
    if not root:
        return []

    netloc = urlparse(root).netloc
    q      = deque([root])
    seen   = {root}
    pages  = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.completed}/{task.total} pages"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task(f"Crawling ({ua[:8]})…", total=MAX_PAGES)
        while q and len(pages) < MAX_PAGES:
            url = q.popleft()
            code, html, resolved = fetch(url, ua)
            pages.append((resolved, code, html))
            prog.advance(task)
            if code == "ERR" or not html:
                continue
            for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
                href = urljoin(resolved, m.group(1))
                if (href.startswith("http") and
                    urlparse(href).netloc == netloc and
                    href not in seen):
                    seen.add(href)
                    q.append(href)
    return pages

def analyze_page(html):
    links      = re.findall(r'<a[^>]+>', html)
    text       = re.sub(r'<[^>]+>', ' ', html)
    link_count = len(links)
    text_len   = len(text)
    ratio      = (link_count / max(text_len,1)) * 1000
    hidden_css = sum(1 for token in SUS_CSS if token in html.lower())
    spam_kw    = sum(1 for kw in SUS_KEYWORDS if kw in html.lower())
    return link_count, text_len, ratio, hidden_css, spam_kw

def compare_cloak(normal, bot):
    bot_map = {url: (code, len(html or "")) for url, code, html in bot}
    diffs   = []
    for url, code, html in normal:
        b = bot_map.get(url)
        if not b:
            continue
        bot_code, bot_len = b
        norm_len = len(html or "")
        if code != bot_code:
            diffs.append((url, str(code), str(bot_code), "StatusMismatch"))
        elif abs(norm_len - bot_len) > 5000:
            diffs.append((url, str(norm_len), str(bot_len), "LengthDiff"))
    return diffs


if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] Please pass a domain (e.g. example.com).[/red]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    start  = time.time()

    pages_n = crawl(domain, UA_NORMAL)
    pages_g = crawl(domain, UA_GOOGLEBOT)

    results = []
    for url, code, html in pages_n:
        if code == "ERR" or not html:
            continue
        lc, tl, ratio, hidden, spam = analyze_page(html)
        results.append((url, str(code), str(lc), str(tl), f"{ratio:.2f}", str(hidden), str(spam)))

    table = Table(title=f"SEO Signals – {domain}", box=box.MINIMAL)
    table.add_column("URL",       style="cyan", overflow="fold")
    table.add_column("Status",    style="green")
    table.add_column("Links",     style="yellow")
    table.add_column("Chars",     style="white")
    table.add_column("L/T×1k",    style="blue")
    table.add_column("Hidden CSS",style="magenta")
    table.add_column("Spam KW",   style="red")
    if results:
        for row in results:
            table.add_row(*row)
        console.print(table)
    else:
        console.print("[yellow][!] No pages analyzed.[/yellow]")

    cloaks = compare_cloak(pages_n, pages_g)
    if cloaks:
        t2 = Table(title="Cloaking Indicators", box=box.MINIMAL)
        t2.add_column("URL",    style="cyan", overflow="fold")
        t2.add_column("Normal", style="green")
        t2.add_column("Bot",    style="yellow")
        t2.add_column("Reason", style="white")
        for u,a,b,reason in cloaks:
            t2.add_row(u, a, b, reason)
        console.print(t2)

    elapsed = time.time() - start
    console.print(Panel(f"[white]Elapsed: {elapsed:.2f}s[/white]", title="Summary", style="bold white"))
    console.print("[green][*] SEO abuse detection completed[/green]")
