#!/usr/bin/env python3
import os
import sys
import re
import requests
import warnings
import urllib3
from urllib.parse import urljoin, urlparse
from collections import deque
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

console = Console()
pat_href    = re.compile(r'href=["\']([^"\']+)["\']', re.I)
pat_src     = re.compile(r'src=["\']([^"\']+)["\']', re.I)
pat_comment = re.compile(r'<!--(.*?)-->', re.S)
sus_keywords = (
    "todo","fixme","api","key","secret","pass",
    "staging","debug","test","internal","tmp"
)
MAX_PAGES = 30

def banner():
    console.print("""
    ==============================================
      Ah-Puch – Link Crawler & HTML Comments Extractor
    ==============================================
    """)

def get_page(url):
    target = str(url or "").strip()
    if not target or not urlparse(target).netloc:
        return "ERR", "", url
    try:
        r = requests.get(target, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        return r.status_code, r.text, r.url
    except (requests.RequestException, OSError, ValueError):
        return "ERR", "", url

def crawl(domain):
    if not str(domain or "").strip():
        return []
    start = None
    for scheme in ("https", "http"):
        code, html, final = get_page(f"{scheme}://{domain}")
        if code != "ERR":
            start = final
            break
    if not start:
        return []

    netloc = urlparse(start).netloc
    queue  = deque([start])
    seen   = {start}
    pages  = []

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Crawling pages…", total=MAX_PAGES)
        while queue and len(pages) < MAX_PAGES:
            url = queue.popleft()
            code, html, resolved = get_page(url)
            pages.append((resolved, code, html))
            progress.advance(task)
            if code == "ERR" or not html:
                continue
            for pat in (pat_href, pat_src):
                for m in pat.finditer(html):
                    link = urljoin(resolved, m.group(1))
                    if link.startswith("http") and urlparse(link).netloc == netloc and link not in seen:
                        seen.add(link)
                        queue.append(link)
    return pages

def extract_comments(html):
    comments = []
    for m in pat_comment.finditer(html):
        text = m.group(1).strip()
        if not text:
            continue
        flag = "Yes" if any(k in text.lower() for k in sus_keywords) else "No"
        snippet = text if len(text) <= 200 else text[:197] + "..."
        comments.append((snippet, flag))
    return comments

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided[/red]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    pages = crawl(domain)
    findings = []

    for url, code, html in pages:
        if code == "ERR" or not html:
            continue
        for txt, flag in extract_comments(html):
            findings.append((url, txt, flag))

    table = Table(
        title=f"HTML Comments on {domain}",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("Page URL",           style="cyan", overflow="fold")
    table.add_column("Comment Snippet",    style="green", overflow="fold")
    table.add_column("Suspicious",         style="yellow")

    if findings:
        for row in findings:
            table.add_row(*row)
        console.print(table)
    else:
        console.print("[yellow][!] No comments found or crawl blocked[/yellow]")

    console.print("[white][*] Extraction complete[/white]")
