#!/usr/bin/env python3

import os
import sys
import json
import requests
import urllib3
import dns.resolver
import dns.name
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

CDN_SIGNATURES = {
    "Cloudflare":       ["cloudflare"],
    "Akamai":           ["akamaiedge", "akamai"],
    "Fastly":           ["fastly"],
    "StackPath":        ["stackpath"],
    "Azure CDN":        ["azureedge", "azurecdn"],
    "MaxCDN":           ["netdna", "maxcdn"],
    "Imperva":          ["incapsula", "imperva"],
    "CacheFly":         ["cachefly"],
    "Amazon CloudFront":["cloudfront"],
    "Generic CDN":      ["cdn."]
}

ADDITIONAL_HEADERS = [
    "Server", "Via", "X-Cache", "CF-RAY", "X-Akamai-Request-ID",
    "X-CDN-Pop", "X-Cache-Status", "X-Edge-IP"
]

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – CDN Fingerprint")
    console.print(f"[{TEAL}]{bar}\n")

def fetch_headers(domain: str, timeout: int) -> dict:
    if not str(domain or "").strip():
        return {}
    headers = {}
    for scheme in ("https://", "http://"):
        try:
            url = scheme + domain
            resp = requests.head(url, timeout=timeout, verify=True, allow_redirects=False)
            headers = resp.headers or {}
            headers["_final_url"] = getattr(resp, "url", url)
            return headers
        except:
            continue
    return {}

def resolve_cname_chain(domain: str, timeout: int) -> list[str]:
    chain = []
    try:
        qname = dns.name.from_text(domain)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        while True:
            answer = resolver.resolve(qname, 'CNAME')
            target = str(answer[0].target).rstrip('.')
            chain.append(target)
            qname = dns.name.from_text(target)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        pass
    return chain

def detect_cdns(headers: dict, cnames: list[str]) -> list[str]:
    found = set()
    for val in headers.values():
        v = str(val).lower()
        for name, sigs in CDN_SIGNATURES.items():
            if any(sig in v for sig in sigs):
                found.add(name)
    for cname in cnames:
        lc = cname.lower()
        for name, sigs in CDN_SIGNATURES.items():
            if any(sig in lc for sig in sigs):
                found.add(name)
    return sorted(found)

def run(target: str, threads: int, opts: dict):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom     = clean_domain_input(target)

    console.print(f"[white]* Fetching headers for [cyan]{dom}[/cyan] (timeout={timeout}s)[/white]")
    headers = fetch_headers(dom, timeout)
    if not headers:
        console.print("[red]✖ Failed to fetch headers[/red]")
        return

    console.print(f"[white]* Resolving CNAME chain[/white]")
    cnames = resolve_cname_chain(dom, timeout)

    console.print(f"[white]* Analyzing CDN signatures[/white]")
    cdns = detect_cdns(headers, cnames)

    tbl_hdr = Table(
        title=f"Response Headers – {dom}",
        header_style="bold magenta",
        box=box.MINIMAL
    )
    tbl_hdr.add_column("Header", style="cyan")
    tbl_hdr.add_column("Value", style="green", overflow="fold")
    for h in ADDITIONAL_HEADERS:
        if h in headers:
            tbl_hdr.add_row(h, headers[h])
    if "_final_url" in headers:
        tbl_hdr.add_row("Final URL", headers["_final_url"])
    console.print(tbl_hdr)

    if cnames:
        tbl_cname = Table(
            title="CNAME Chain",
            header_style="bold magenta",
            box=box.MINIMAL
        )
        tbl_cname.add_column("Alias", style="yellow")
        for cname in cnames:
            tbl_cname.add_row(cname)
        console.print(tbl_cname)

    if cdns:
        console.print(Panel(f"[bold]{', '.join(cdns)}[/bold]", title="Detected CDN(s)", style="bold white"))
    else:
        console.print("[yellow]No CDN signatures detected[/yellow]")

    console.print("[green]* CDN fingerprint completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(tbl_hdr)
        if cnames:
            export_console.print(tbl_cname)
        if cdns:
            export_console.print(Panel(f"{', '.join(cdns)}", title="Detected CDN(s)", style="bold white"))
        write_to_file(
            os.path.join(out_dir, "cdn_fingerprint.txt"),
            export_console.export_text()
        )

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No domain provided. Please pass a domain.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            opts = {}
    run(tgt, thr, opts)
