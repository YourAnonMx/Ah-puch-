import os
import sys
import time
import requests
from http.cookies import SimpleCookie
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
   Ah-Puch - Session Cookie Lifetime Checker
    =============================================
    """)

def fetch(url):
    target = str(url or "").strip()
    if not target or not urlparse(target).netloc:
        return None
    try:
        r = requests.get(target, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        return r
    except (requests.RequestException, OSError, ValueError):
        return None

def parse_set_cookie(headers):
    cookies = []
    hdr = headers.get("Set-Cookie")
    if not hdr:
        return cookies
    parts = hdr.split(",")
    tmp = []
    buf = ""
    for p in parts:
        if "=" in p.split(";",1)[0] and buf:
            tmp.append(buf)
            buf = p
        else:
            buf = buf + "," + p if buf else p
    if buf:
        tmp.append(buf)
    for raw in tmp:
        sc = SimpleCookie()
        sc.load(raw)
        for k,m in sc.items():
            attrs = {ak.lower():av for ak,av in m.items()}
            cookies.append((k, m.value, attrs))
    return cookies

def flatten_attrs(attrs):
    out = []
    for k,v in attrs.items():
        if k in ("expires","max-age","domain","path","samesite"):
            out.append(f"{k}={v}")
        elif v == "":
            out.append(k)
    return ";".join(out) if out else "-"

def classify(attrs):
    exp = attrs.get("expires")
    maxage = attrs.get("max-age")
    if exp or maxage:
        return "Persistent"
    return "Session"

def display(domain, first, second):
    table = Table(title=f"Session Cookie Lifetime: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Cookie", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Attrs", style="yellow", overflow="fold")
    table.add_column("Changed", style="white")
    keys = set([c[0] for c in first] + [c[0] for c in second])
    for k in keys:
        a1 = next((c for c in first if c[0]==k), None)
        a2 = next((c for c in second if c[0]==k), None)
        if a1:
            typ1 = classify(a1[2])
            attrs1 = flatten_attrs(a1[2])
        else:
            typ1 = "-"
            attrs1 = "-"
        if a2:
            typ2 = classify(a2[2])
            attrs2 = flatten_attrs(a2[2])
        else:
            typ2 = "-"
            attrs2 = "-"
        changed = "Y" if (attrs1 != attrs2 or typ1 != typ2) else "N"
        table.add_row(k, f"{typ1}->{typ2}", f"{attrs1} | {attrs2}", changed)
    console.print(table)

if __name__ == "__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)
    domain = clean_domain_input(sys.argv[1])
    url_https = f"https://{domain}"
    url_http = f"http://{domain}"
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        t1 = progress.add_task("Initial request", total=1)
        r1 = fetch(url_https) or fetch(url_http)
        progress.advance(t1)
        time.sleep(1)
        t2 = progress.add_task("Follow-up request", total=1)
        r2 = fetch(url_https) or fetch(url_http)
        progress.advance(t2)
    if not r1 or not r2:
        console.print("[red][!] Unable to retrieve pages.[/red]")
        sys.exit(1)
    c1 = parse_set_cookie(r1.headers)
    c2 = parse_set_cookie(r2.headers)
    display(domain, c1, c2)
    console.print("[white][*] Session cookie lifetime check completed.[/white]")
