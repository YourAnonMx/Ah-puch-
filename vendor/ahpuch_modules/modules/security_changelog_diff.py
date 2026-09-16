#!/usr/bin/env python3
import os
import sys
import json
import requests
import urllib3
from datetime import datetime
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

HEADERS_OF_INTEREST = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials"
]

PATHS = ["/", "/login", "/admin", "/api/", "/api/v1/", "/robots.txt", "/sitemap.xml"]

def banner():
    console.print("""
    =============================================
       Ah-Puch - Security Changelog Diff
    =============================================
    """)

def reach(domain: str) -> str | None:
    if not domain or not str(domain).strip():
        return None
    for scheme in ("https", "http"):
        u = f"{scheme}://{domain}"
        try:
            r = requests.get(u, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
            return r.url
        except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
            continue
    return None

def grab_headers(url: str) -> dict[str, str]:
    if not url or not str(url).strip():
        return {}
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        return {k: v for k, v in r.headers.items() if k in HEADERS_OF_INTEREST}
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return {}

def collect(base: str) -> dict[str, dict[str, str]]:
    if not base or not str(base).strip():
        return {}
    out: dict[str, dict[str, str]] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Collecting headers", total=len(PATHS))
        for p in PATHS:
            url = urljoin(base, p.lstrip("/"))
            out[url] = grab_headers(url)
            progress.advance(task)
    return out

def load_baseline(path: str | None) -> dict[str, dict[str, str]]:
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, TypeError, ValueError):
        return {}

def save_current(path: str, data: dict) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except (OSError, TypeError, ValueError):
        return False

def diff_headers(old: dict, new: dict) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    for url, hdrs in new.items():
        oldhdrs = old.get(url, {})
        for k in HEADERS_OF_INTEREST:
            o = oldhdrs.get(k, "-")
            n = hdrs.get(k, "-")
            if o != n:
                rows.append((url, k, o, n))
    return rows

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided. Please pass a domain and optional baseline/output paths.[/red]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    baseline_path = sys.argv[2] if len(sys.argv) > 2 else None
    out_path      = sys.argv[3] if len(sys.argv) > 3 else None

    base = reach(domain)
    if not base:
        console.print("[red][!] Unable to reach domain.[/red]")
        sys.exit(1)

    current  = collect(base)
    baseline = load_baseline(baseline_path)
    rows     = diff_headers(baseline, current) if baseline else []

    table = Table(
        title=f"Security Header Changes: {domain}",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("URL",    style="cyan", overflow="fold")
    table.add_column("Header", style="green")
    table.add_column("Old",    style="yellow", overflow="fold")
    table.add_column("New",    style="white",  overflow="fold")

    for r in rows:
        table.add_row(*r)

    if rows:
        console.print(table)
    elif baseline:
        console.print("[green][*] No changes detected vs baseline.[/green]")
    else:
        console.print("[yellow][!] No baseline provided; showing current snapshot only.[/yellow]")

    if out_path:
        if save_current(out_path, current):
            console.print(f"[white][*] Current snapshot saved to {out_path}[/white]")
        else:
            console.print("[red][!] Failed to save snapshot.[/red]")

    console.print("[white][*] Security changelog diff completed.[/white]")
