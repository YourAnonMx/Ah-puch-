#!/usr/bin/env python3
import sys, os
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

init(autoreset=True)
console = Console()

def banner():
    console.print("""
=============================================
        Ah-Puch - IP Range Scanner
=============================================
""")

def ping(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0

def display_table(results):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="cyan")
    table.add_column("Status", style="green")
    for ip, up in results:
        table.add_row(str(ip), "Up" if up else "Down")
    console.print(table)

def main():
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No network or IP provided. Pass a CIDR or single IP.[/red]")
        sys.exit(1)
    cidr = sys.argv[1]
    if "/" not in cidr:
        cidr += "/32"
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        console.print("[red][!] Invalid CIDR or IP notation.[/red]")
        sys.exit(1)
    hosts = list(net.hosts())
    console.print(f"[white][*] Scanning {len(hosts)} host(s) in {net}[/white]")
    results = []
    if len(hosts) == 1:
        up = ping(hosts[0])
        results.append((hosts[0], up))
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Scanning…", total=len(hosts))
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(ping, ip): ip for ip in hosts}
                for fut in as_completed(futures):
                    ip = futures[fut]
                    up = fut.result()
                    results.append((ip, up))
                    progress.update(task, description=str(ip), advance=1)
    results.sort(key=lambda x: not x[1])
    display_table(results)
    up_count = sum(1 for _,up in results if up)
    down_count = len(results) - up_count
    console.print(f"[white][*] Completed: {up_count} up, {down_count} down[/white]")

if __name__ == "__main__":
    main()
