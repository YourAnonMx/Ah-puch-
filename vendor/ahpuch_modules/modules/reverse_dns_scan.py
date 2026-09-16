#!/usr/bin/env python3

import os
import sys
import json
import socket
import ipaddress
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

init(autoreset=True)
console = Console()

from ahpuch_modules.utils.util import ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import RESULTS_DIR, EXPORT_SETTINGS

MAX_WORKERS = 100

def banner():
    console.print("""
    =============================================
        Ah-Puch - Reverse DNS Sweep
    =============================================
    """)

def rev_lookup(ip):
    if not str(ip or "").strip():
        return None
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except:
        return None

def run(target, threads, opts):
    banner()
    try:
        network = ipaddress.ip_network(target, strict=False)
    except:
        console.print("[red][!] Invalid CIDR notation.[/red]")
        return
    hosts = list(network.hosts())
    console.print(f"[white][*] Sweeping {len(hosts)} addresses in {network}[/white]")
    results = []
    max_workers = min(MAX_WORKERS, int(opts.get("workers", threads)))
    with Progress(SpinnerColumn(), TextColumn("{task.fields[ip]}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("", total=len(hosts), ip="")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(rev_lookup, ip): ip for ip in hosts}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                name = future.result()
                if name:
                    results.append((str(ip), name))
                progress.update(task, ip=str(ip), advance=1)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="cyan")
    table.add_column("Hostname", style="green")
    for ip, host in results:
        table.add_row(ip, host)
    if results:
        console.print(table)
    else:
        console.print("[yellow][!] No PTR records found[/yellow]")
    console.print("[white][*] Reverse DNS sweep completed.[/white]")
    if EXPORT_SETTINGS.get("enable_txt_export", False):
        out_dir = os.path.join(RESULTS_DIR, str(network))
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        if results:
            export_console.print(table)
        else:
            export_console.print("[yellow]No PTR records found[/yellow]")
        text = export_console.export_text()
        write_to_file(os.path.join(out_dir, "reverse_dns_sweep.txt"), text)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red][!] No CIDR provided. Please pass a range like 192.168.1.0/24.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = MAX_WORKERS
    if len(sys.argv) > 2 and sys.argv[2].isdigit():
        thr = int(sys.argv[2])
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            pass
    run(tgt, thr, opts)
