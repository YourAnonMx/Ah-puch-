#!/usr/bin/env python3
import os
import sys
import json
import time
import urllib3
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"
_WAYBACK = "https://web.archive.org/cdx/search/cdx"
_CC      = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – Archive History")
    console.print(f"[{TEAL}]{bar}\n")


def fetch_wayback(domain: str, limit: int, status: str, collapse: str, timeout: int) -> list[tuple[str,str]]:
    if not str(domain or "").strip():
        return []
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "limit": limit,
        "filter": f"statuscode:{status}",
        "fl": "timestamp,original",
        "collapse": collapse
    }
    try:
        r = requests.get(_WAYBACK, params=params, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return [
            (item.get("timestamp"), item.get("original"))
            for item in data
            if isinstance(item, dict)
            and item.get("timestamp")
            and item.get("original")
        ]
    except:
        return []


def fetch_cc(domain: str, limit: int, timeout: int) -> list[tuple[str,str]]:
    if not str(domain or "").strip():
        return []
    try:
        rows = []
        r = requests.get(_CC, params={"url": f"{domain}/*", "output": "json", "limit": limit}, timeout=timeout)
        r.raise_for_status()
        for line in r.text.splitlines():
            j = json.loads(line)
            rows.append((j.get("timestamp"), j.get("url")))
        return rows
    except:
        return []


def collect(domain: str, limit: int, status: str, collapse: str, timeout: int) -> tuple[list[tuple[str,str]], str]:
    if not str(domain or "").strip():
        return [], "none"
    wb = fetch_wayback(domain, limit, status, collapse, timeout)
    if wb:
        return wb, "wayback"
    cc = fetch_cc(domain, limit, timeout)
    return cc, "common-crawl"


def run(target: str, threads: int, opts: dict):
    banner()
    domain = clean_domain_input(target)
    if not domain:
        console.print("[yellow]Empty target is not applicable[/yellow]")
        return
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    limit = max(1, int(opts.get("limit", 100)))
    status = opts.get("status_filter", "200")
    collapse = "digest" if int(opts.get("collapse_digest", 1)) else ""

    console.print(f"[white]* Target: [bold]{domain}[/bold]  limit:{limit}  status:{status}  collapse:{collapse or '-'}[/white]\n")

    rows, src = collect(domain, limit, status, collapse, timeout)
    if not rows:
        console.print("[yellow]No history snapshots found[/yellow]")
        return

    table = Table(
        title=f"Archive History – {domain}",
        header_style="bold magenta",
        box=box.MINIMAL
    )
    table.add_column("Timestamp", style="cyan")
    table.add_column("Archived URL", style="green", overflow="fold")
    table.add_column("Source", style="yellow")

    for ts, orig in rows:
        if src == "wayback":
            url = f"https://web.archive.org/web/{ts}/{orig}"
        else:
            url = orig
        table.add_row(ts, url, src)

    console.print(table)
    console.print(f"[green]* {len(rows)} snapshot(s) via {src}[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out_dir, "archive_history.txt"), export_console.export_text())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            opts = {}
    run(tgt, thr, opts)
