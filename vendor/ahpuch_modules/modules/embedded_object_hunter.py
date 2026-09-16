import os
import sys
import re
import requests
from urllib.parse import urljoin, urlparse
from collections import deque
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

MAX_PAGES = 30
PAT_LINK = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)
PAT_EMBED = re.compile(r'<(?:iframe|embed|object|img|source|video|audio)[^>]+src=["\']([^"\']+)["\']', re.I)
PAT_DATA = re.compile(r'data:[^"\'\s>]+', re.I)
SUSPICIOUS_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".swf", ".zip", ".gz", ".sql", ".bak", ".tar", ".tgz",
    ".7z", ".rar", ".cfg", ".conf", ".ini", ".log", ".pcap",
    ".json", ".yaml", ".yml", ".txt"
}

def banner():
    console.print("""
    =============================================
      Ah-Puch - Embedded Object Hunter
    =============================================
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
    for scheme in ("https", "http"):
        start = f"{scheme}://{domain}"
        status, html, final_url = get_page(start)
        if status != "ERR":
            break
    else:
        return []

    netloc = urlparse(final_url).netloc
    queue = deque([final_url])
    seen = {final_url}
    pages = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Crawling pages", total=MAX_PAGES)
        while queue and len(pages) < MAX_PAGES:
            current = queue.popleft()
            status, html, resolved = get_page(current)
            pages.append((resolved, status, html))
            progress.advance(task)
            if status == "ERR" or not html:
                continue
            for m in PAT_LINK.finditer(html):
                link = urljoin(resolved, m.group(1))
                parsed = urlparse(link)
                if link.startswith("http") and parsed.netloc == netloc and link not in seen:
                    seen.add(link)
                    queue.append(link)
    return pages

def extract_embeds(page_url, html):
    embeds = []
    for m in PAT_EMBED.finditer(html):
        src = urljoin(page_url, m.group(1).strip())
        ext = os.path.splitext(src.split("?", 1)[0].split("#", 1)[0])[1].lower() or "-"
        flag = "Suspicious" if ext in SUSPICIOUS_EXTENSIONS else "Other"
        embeds.append((page_url, src, ext, flag))
    for m in PAT_DATA.finditer(html):
        data_uri = m.group(0)
        embeds.append((page_url, data_uri, "data:", "Inline"))
    return embeds

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided[/red]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    pages = crawl(domain)
    findings = []

    for url, status, html in pages:
        if status == "ERR" or not html:
            continue
        findings.extend(extract_embeds(url, html))

    table = Table(title=f"Embedded Objects: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Page URL", style="cyan", overflow="fold")
    table.add_column("Object URL", style="green", overflow="fold")
    table.add_column("Ext", style="yellow")
    table.add_column("Flag", style="white")

    for row in findings:
        table.add_row(*row)

    if findings:
        console.print(table)
    else:
        console.print("[yellow][!] No embedded objects found[/yellow]")

    console.print("[white][*] Embedded object hunting completed[/white]")
