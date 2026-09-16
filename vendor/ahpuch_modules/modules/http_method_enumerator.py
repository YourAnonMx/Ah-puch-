import os
import sys
import re
import threading
import queue
import requests
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input

init(autoreset=True)
console = Console()
requests.packages.urllib3.disable_warnings()

DEFAULT_MAX_PAGES = 100
DEFAULT_INCLUDE_SUBDOMAINS = False
TEST_METHODS = ["GET","POST","HEAD","PUT","DELETE","PATCH","OPTIONS","TRACE"]

def banner():
    console.print("""
    =============================================
        Ah-Puch - HTTP Method Enumerator
    =============================================
    """)

def parse_opts(argv):
    max_pages = DEFAULT_MAX_PAGES
    include_subs = DEFAULT_INCLUDE_SUBDOMAINS
    start_path = "/"
    i = 3
    while i < len(argv):
        a = argv[i]
        if a == "--max-pages" and i+1 < len(argv):
            try: max_pages = int(argv[i+1])
            except (TypeError, ValueError): pass
            i += 2
            continue
        if a == "--include-subdomains" and i+1 < len(argv):
            include_subs = argv[i+1] not in ("0","false","False","no","NO")
            i += 2
            continue
        if a == "--start-path" and i+1 < len(argv):
            start_path = argv[i+1]
            i += 2
            continue
        i += 1
    return max_pages, include_subs, start_path

def normalize_base(target):
    if "://" not in target:
        target = "https://" + target
    return target.rstrip("/") + "/"

def same_domain(url, base_netloc, include_subs):
    try:
        n = urlparse(url).netloc.lower()
        if not n:
            return True
        if n == base_netloc:
            return True
        if include_subs and n.endswith("." + base_netloc):
            return True
    except (TypeError, ValueError):
        pass
    return False

def extract_links(html, base):
    out=[]
    for m in re.finditer(r'''href=["']([^"'#]+)''', html, re.I):
        out.append(urljoin(base, m.group(1)))
    for m in re.finditer(r'''src=["']([^"'#]+)''', html, re.I):
        out.append(urljoin(base, m.group(1)))
    return out

def fetch(url):
    if not str(url or "").strip():
        return None
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        return r
    except (requests.RequestException, OSError, ValueError):
        return None

def crawl(start_url, max_pages, include_subs):
    if not str(start_url or "").strip() or max_pages <= 0:
        return []
    base_netloc = urlparse(start_url).netloc.lower()
    seen=set()
    q=[start_url]
    pages=[]
    while q and len(pages) < max_pages:
        u=q.pop(0)
        if u in seen:
            continue
        seen.add(u)
        r=fetch(u)
        if not r:
            continue
        pages.append(u)
        if "text/html" in r.headers.get("Content-Type",""):
            links=extract_links(r.text,u)
            for l in links:
                if same_domain(l,base_netloc,include_subs):
                    if l not in seen:
                        q.append(l)
    return pages

def allow_header_methods(header):
    if not header:
        return []
    return [m.strip().upper() for m in header.split(",") if m.strip()]

def try_method(url, method):
    if not str(url or "").strip():
        return None
    try:
        r = requests.request(method, url, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        return r.status_code
    except (requests.RequestException, OSError, ValueError):
        return None

def enumerate_methods(url):
    if not str(url or "").strip():
        return {method: "ERR" for method in TEST_METHODS}
    r = fetch(url)
    hdrs = r.headers if r else {}
    allow = allow_header_methods(hdrs.get("Allow"))
    results={}
    if allow:
        for m in TEST_METHODS:
            results[m] = "Y" if m in allow else "-"
    else:
        for m in TEST_METHODS:
            sc = try_method(url, m)
            if sc is None:
                results[m] = "ERR"
            elif sc in (200,201,202,204,301,302,304,307,308,401,403,405):
                if sc == 405:
                    results[m] = "-"
                else:
                    results[m] = "Y"
            else:
                results[m] = "-"
    return results

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
    raw_target=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    max_pages, include_subs, start_path = parse_opts(sys.argv)
    domain=clean_domain_input(raw_target)
    base=normalize_base(domain)
    start_url=urljoin(base,start_path.lstrip("/"))
    console.print(f"[white][*] Crawling up to {max_pages} pages (include_subdomains={include_subs}).[/white]")
    pages=crawl(start_url,max_pages,include_subs)
    pages=pages or [start_url]
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Enumerating methods",total=len(pages))
        for u in pages:
            res=enumerate_methods(u)
            rows.append((u,res["GET"],res["POST"],res["HEAD"],res["PUT"],res["DELETE"],res["PATCH"],res["OPTIONS"],res["TRACE"]))
            progress.advance(task)
    table=Table(title=f"HTTP Method Enumerator: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("URL",style="cyan",overflow="fold")
    for m in TEST_METHODS:
        table.add_column(m,style="green" if m in ("GET","POST") else "white")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] HTTP method enumeration completed.[/white]")
