#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import urllib3
import datetime
from collections import defaultdict, Counter

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import box

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]        Ah-Puch – CT Log Query")
    console.print(f"[cyan]{bar}\n")

def fetch_ct(domain: str, timeout: int):
    if not isinstance(domain, str) or not domain.strip():
        return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []
    except (AttributeError, KeyError, OSError, requests.exceptions.RequestException, TypeError, ValueError) as e:
        console.print(f"[red][!] CT log query failed for {domain}: {e}[/red]")
        return []

def aggregate(entries, domain, include_wc):
    if not isinstance(entries, list) or not isinstance(domain, str) or not domain.strip():
        return [], 0, Counter()
    agg = defaultdict(lambda: {"first": None, "last": None, "count": 0, "issuers": set()})
    for e in entries:
        if not isinstance(e, dict):
            continue
        for name in e.get("name_value", "").splitlines():
            if not include_wc and name.startswith("*."):
                name = name[2:]
            if not name.endswith(domain):
                continue
            try:
                nb = datetime.datetime.strptime(e["not_before"], "%Y-%m-%dT%H:%M:%S")
                na = datetime.datetime.strptime(e["not_after"],  "%Y-%m-%dT%H:%M:%S")
            except (KeyError, TypeError, ValueError):
                continue
            rec = agg[name]
            rec["first"] = min(filter(None, [rec["first"], nb]))
            rec["last"]  = max(filter(None, [rec["last"], na]))
            rec["count"] += 1
            rec["issuers"].add(e.get("issuer_ca_name", "-"))
    rows = []
    issuers_counter = Counter()
    total_certs = 0
    for name, v in sorted(agg.items(), key=lambda x: x[1]["last"], reverse=True):
        rows.append([
            name,
            str(v["count"]),
            ",".join(sorted(v["issuers"])),
            v["first"].date().isoformat(),
            v["last"].date().isoformat()
        ])
        total_certs += v["count"]
        for issuer in v["issuers"]:
            issuers_counter[issuer] += v["count"]
    return rows, total_certs, issuers_counter

def run(target, threads, opts):
    if not isinstance(target, str) or not target.strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    banner()
    start = time.time()
    try:
        timeout = min(max(int(opts.get("timeout", DEFAULT_TIMEOUT)), 1), 60)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    include_wc   = bool(opts.get("include_wildcard", False))
    domain       = clean_domain_input(target)

    console.print(f"[white][*] Querying CT logs for [cyan]{domain}[/cyan] (include_wildcard={include_wc})[/white]\n")
    with Progress(SpinnerColumn(), TextColumn("Fetching…"), console=console, transient=True) as prog:
        task = prog.add_task("", total=1)
        data = fetch_ct(domain, timeout)
        prog.advance(task)

    if not data:
        console.print("[yellow]No CT data available (or query failed).[/yellow]")
        return

    rows, total_certs, issuers_counter = aggregate(data, domain, include_wc)

    tbl = Table(title=f"CT Log Results – {domain}", header_style="bold magenta", box=box.MINIMAL)
    for col in ["Domain", "TotalCerts", "Issuers", "FirstSeen", "LastSeen"]:
        tbl.add_column(col, overflow="fold")
    for r in rows:
        tbl.add_row(*r)
    console.print(tbl)

    unique = len(rows)
    top_issuers = ", ".join(f"{i}:{c}" for i, c in issuers_counter.most_common(5))
    summary = (
        f"Unique domains: {unique}  "
        f"Total certificates: {total_certs}  "
        f"Top issuers: {top_issuers or '-'}  "
        f"Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] CT Log query completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(tbl)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "ct_log_query.txt"), export_console.export_text())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError):
        opts = {}
    run(tgt, thr, opts)
