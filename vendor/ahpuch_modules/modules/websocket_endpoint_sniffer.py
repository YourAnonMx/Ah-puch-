#!/usr/bin/env python3
import os
import sys
import re
import base64
import requests
import urllib3
import warnings
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)
console = Console()

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

pat_script  = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)
pat_ws       = re.compile(r"['\"](wss?://[^'\"\s]+)['\"]", re.I)
pat_path_ws  = re.compile(r"['\"](/[^'\"\s]*socket[^'\"\s]*)['\"]", re.I)

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]   Ah-Puch - WebSocket Endpoint Sniffer")
    console.print(f"[cyan]{bar}\n")

def get_base(domain):
    if not str(domain or "").strip():
        return None, ""
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
            if r.status_code < 400:
                return r.url, r.text
        except (requests.RequestException, OSError, ValueError):
            pass
    return None, ""

def extract_scripts(html, base):
    return list(dict.fromkeys(urljoin(base, m.group(1).strip()) for m in pat_script.finditer(html)))[:75]

def fetch_script(u):
    if not str(u or "").strip():
        return u, ""
    try:
        r = requests.get(u, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        if r.status_code == 200:
            return u, r.text
    except (requests.RequestException, OSError, ValueError):
        pass
    return u, ""

def collect_ws(html, base):
    found = []
    for m in pat_ws.finditer(html):
        found.append(m.group(1).strip())
    for m in pat_path_ws.finditer(html):
        ws = urljoin(base, m.group(1).strip()).replace("http://", "ws://").replace("https://", "wss://")
        found.append(ws)
    return list(dict.fromkeys(found))

def upgrade_test(wsurl):
    if not str(wsurl or "").strip():
        return wsurl, "ERR", "-", "-"
    if wsurl.startswith("ws://"):
        http_url = "http://" + wsurl[5:]
    elif wsurl.startswith("wss://"):
        http_url = "https://" + wsurl[6:]
    else:
        http_url = wsurl
    key = base64.b64encode(os.urandom(16)).decode()
    hdrs = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13"
    }
    try:
        r = requests.get(http_url, headers=hdrs, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False, stream=True)
        return wsurl, str(r.status_code), r.headers.get("Sec-WebSocket-Protocol", "-"), r.headers.get("Sec-WebSocket-Accept", "-")
    except (requests.RequestException, OSError, ValueError):
        return wsurl, "ERR", "-", "-"

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    base, html = get_base(domain)
    if not base:
        console.print("[red][!] Could not reach domain.[/red]")
        sys.exit(1)

    endpoints = collect_ws(html, base)
    scripts   = extract_scripts(html, base)

    if scripts:
        with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total} scripts"), BarColumn(), console=console, transient=True) as prog:
            task = prog.add_task("Fetching scripts…", total=len(scripts))
            with ThreadPoolExecutor(max_workers=25) as exe:
                for fut in as_completed({exe.submit(fetch_script, u): u for u in scripts}):
                    _, txt = fut.result()
                    endpoints.extend(collect_ws(txt, base))
                    prog.advance(task)

    endpoints = list(dict.fromkeys(endpoints))
    results   = []

    if endpoints:
        with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total} endpoints"), BarColumn(), console=console, transient=True) as prog:
            task = prog.add_task("Upgrading…", total=len(endpoints))
            with ThreadPoolExecutor(max_workers=20) as exe:
                for fut in as_completed({exe.submit(upgrade_test, e): e for e in endpoints}):
                    results.append(fut.result())
                    prog.advance(task)

    table = Table(title=f"WebSocket Endpoints – {domain}", box=None)
    table.add_column("WS URL", style="cyan", overflow="fold")
    table.add_column("HTTP Code", style="green")
    table.add_column("Protocol", style="yellow")
    table.add_column("Accept", style="white")

    if results:
        for row in results:
            table.add_row(*row)
        console.print(table)
    else:
        console.print("[yellow][!] No WebSocket endpoints discovered.[/yellow]")

    console.print("[white][*] WebSocket sniffing completed[/white]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_text = Console(record=True, width=console.width)
        export_text.print(table)
        write_to_file(os.path.join(out, "websocket_endpoints.txt"), export_text.export_text())
