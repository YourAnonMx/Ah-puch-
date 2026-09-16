#!/usr/bin/env python3
import os
import sys
import json
import urllib.parse
import requests
import urllib3
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

PARAMS = [
    "url","redirect","next","target","dest","destination","return","returnUrl","continue",
    "goto","to","out","r","u","jump","link","path","image","file","forward",
    "redirect_uri","redirect_url","redir","page"
]
VECTORS = [
    "https://evil.example","//evil.example","////evil.example","https:////evil.example",
    "http://%2Fevil.example","%2f%2fevil.example","evil.example","https://attacker.invalid"
]
PATH_PREFIXES = ["/redirect/","/out/","/go/","/goto/","/r/","/jump/","/forward/"]

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]        Ah-Puch - Open Redirect Finder")
    console.print(f"[cyan]{bar}\n")

def reach(domain, timeout):
    if not domain or not str(domain).strip():
        return None
    for scheme in ("https","http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
            return r.url
        except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
            pass
    return None

def test_param(base, param, payload, timeout):
    p = urllib.parse.urlparse(base)
    q = {param: payload}
    url = p._replace(query=urllib.parse.urlencode(q)).geturl()
    try:
        r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        loc = r.headers.get("Location") or "-"
        return ("PARAM", url, loc, str(r.status_code))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return ("PARAM", url, "-", "ERR")

def test_path(base, prefix, payload, timeout):
    url = urllib.parse.urljoin(base, prefix + payload)
    try:
        r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        loc = r.headers.get("Location") or "-"
        return ("PATH", url, loc, str(r.status_code))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return ("PATH", url, "-", "ERR")

def classify(loc):
    if loc == "ERR":
        return "Probe Error"
    if not loc or loc == "-":
        return "No Redirect"
    ll = loc.lower()
    if ll.startswith("http://evil.example") or ll.startswith("https://evil.example") or "attacker.invalid" in ll:
        return "External"
    if ll.startswith("//evil.example"):
        return "Protocol-Relative"
    if "://" in ll and not ll.startswith("http"):
        return "OtherProto"
    return "Internal"

def run(target, threads, opts):
    banner()
    if not target or not str(target).strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 60))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    try:
        thr = max(1, min(int(threads), 32))
    except (TypeError, ValueError):
        thr = 1
    domain  = clean_domain_input(target)
    if not domain:
        return 2
    base    = reach(domain, timeout)
    if not base:
        console.print("[red]✖ Unable to reach domain[/red]")
        return 1

    tests = []
    for p in PARAMS:
        for v in VECTORS:
            tests.append(("param", p, v))
    for pr in PATH_PREFIXES:
        for v in VECTORS:
            tests.append(("path", pr, v))

    console.print(f"[white]* Launching [cyan]{len(tests)}[/cyan] tests with [yellow]{thr}[/yellow] threads (timeout={timeout}s)[/white]")
    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as pg:
        task = pg.add_task("Testing…", total=len(tests))
        with ThreadPoolExecutor(max_workers=thr) as pool:
            futures = []
            for kind, a, b in tests:
                if kind == "param":
                    futures.append(pool.submit(test_param, base, a, b, timeout))
                else:
                    futures.append(pool.submit(test_path, base, a, b, timeout))
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
                    results.append(("ERROR", "-", "-", "ERR"))
                pg.advance(task)

    table = Table(title=f"Open Redirect Findings – {domain}", header_style="bold magenta")
    table.add_column("Type", style="cyan")
    table.add_column("Tested URL", style="green", overflow="fold")
    table.add_column("Location", style="yellow", overflow="fold")
    table.add_column("Status", style="white")
    table.add_column("Class", style="blue")
    for typ, url, loc, code in results:
        table.add_row(typ, url, loc, code, classify(loc))

    console.print(table)
    console.print("[green]* Open redirect testing completed[/green]")
    return 0

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = sys.argv[2] if len(sys.argv) > 2 else "10"
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            pass
    raise SystemExit(run(tgt, thr, opts))
