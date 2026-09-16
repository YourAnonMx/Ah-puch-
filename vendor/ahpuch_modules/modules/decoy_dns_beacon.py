#!/usr/bin/env python3
import os
import sys
import json
import re
import time
import uuid
import requests
import urllib3
import dns.resolver
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()
resolver = dns.resolver.Resolver()

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]     Ah-Puch – Decoy DNS Beacon")
    console.print(f"[cyan]{bar}\n")

def token_file(domain):
    if not domain or not str(domain).strip():
        return ""
    path = os.path.join(RESULTS_DIR, domain)
    ensure_directory_exists(path)
    return os.path.join(path, "dns_beacons.json")

def load_tokens(path):
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, list) else []
        except (OSError, TypeError, ValueError):
            pass
    return []

def save_tokens(path, tokens):
    if not path:
        return False
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    return True

def generate(domain, count):
    if not domain or not str(domain).strip():
        return []
    count = max(0, min(int(count), 1000))
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
    return [
        {"token": f"{uuid.uuid4().hex[:8]}.{domain}",
         "created": now,
         "resolved": False,
         "timestamp": None}
        for _ in range(count)
    ]

def check(token, dns_server, timeout):
    if not token or not str(token).strip():
        return False
    if dns_server and str(dns_server).strip():
        resolver.nameservers = [str(dns_server).strip()]
    resolver.lifetime = timeout
    try:
        resolver.resolve(token, "A")
        return True
    except (dns.exception.DNSException, OSError, TypeError, ValueError):
        return False

def run(target, threads, opts):
    banner()
    if not target or not str(target).strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    start = time.time()
    domain = clean_domain_input(target)
    if not domain:
        return 2
    try:
        count = max(0, min(int(opts.get("count", 5)), 1000))
    except (TypeError, ValueError):
        count = 5
    verify = opts.get("verify", False) is True
    dns_server = opts.get("dns_server", "")
    try:
        timeout = max(1, min(int(opts.get("timeout", 5)), 60))
    except (TypeError, ValueError):
        timeout = 5
    try:
        threads = max(1, min(int(threads), 32))
    except (TypeError, ValueError):
        threads = 1
    path = token_file(domain)
    if not path:
        return 2
    tokens = load_tokens(path)

    if verify and tokens:
        to_check = [t for t in tokens if not t["resolved"]]
        console.print(f"[white][*] Verifying [cyan]{len(to_check)}[/cyan] tokens[/white]\n")
        with Progress(
            SpinnerColumn(),
            TextColumn("[white]{task.description} {task.completed}/{task.total}"),
            BarColumn(),
            console=console,
            transient=True
        ) as prog:
            task = prog.add_task("Checking DNS…", total=len(to_check))
            with ThreadPoolExecutor(max_workers=threads) as pool:
                checks = {pool.submit(check, t["token"], dns_server, timeout): t for t in to_check}
                for fut in as_completed(checks):
                    t = checks[fut]
                    if fut.result():
                        t["resolved"] = True
                        t["timestamp"] = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
                    prog.advance(task)
        resolved = sum(1 for t in tokens if t["resolved"])
        pending = len(tokens) - resolved
        table = Table(header_style="bold magenta", box=box.MINIMAL)
        table.add_column("Token", style="cyan", overflow="fold")
        table.add_column("Resolved", style="green")
        table.add_column("FirstSeen", style="yellow")
        for t in tokens:
            table.add_row(t["token"], "✔" if t["resolved"] else "-", t["timestamp"] or "-")
        console.print(table)
        summary = f"Total: {len(tokens)}  Resolved: {resolved}  Pending: {pending}  Elapsed: {time.time() - start:.2f}s"
    else:
        console.print(f"[white][*] Generating [green]{count}[/green] DNS beacons for [cyan]{domain}[/cyan][/white]\n")
        new = generate(domain, count)
        tokens.extend(new)
        table = Table(header_style="bold magenta", box=box.MINIMAL)
        table.add_column("Token", style="cyan", overflow="fold")
        for t in new:
            table.add_row(t["token"])
        console.print(table)
        summary = f"Generated: {len(new)}  Total: {len(tokens)}  Elapsed: {time.time() - start:.2f}s"

    save_tokens(path, tokens)
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] DNS beacon operation completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(path, export_console.export_text())

    return 0

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError):
        opts = {}
    raise SystemExit(run(tgt, thr, opts))
