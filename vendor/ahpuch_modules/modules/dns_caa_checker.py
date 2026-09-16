#!/usr/bin/env python3
import os
import sys
import json
import time
import dns.resolver
import urllib3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import box

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
MAX_TIMEOUT = 300

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]           Ah-Puch – DNS CAA Check")
    console.print(f"[cyan]{bar}\n")

def run(target, threads, opts):
    banner()
    start = time.time()
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    check_sub = bool(options.get("check_subdomains", False))
    domain = clean_domain_input(target)
    if not domain:
        console.print("[red]✖ No target domain provided.[/red]")
        return 2
    zones = [domain] + ([f"www.{domain}"] if check_sub else [])
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[zone]}", justify="right"),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Querying CAA records", total=len(zones), zone=zones[0])
        for zone in zones:
            prog.update(task, zone=zone)
            try:
                answers = resolver.resolve(zone, "CAA")
                for r in answers:
                    results.append((zone, r.flags, r.tag, r.value))
            except (dns.exception.DNSException, OSError, ValueError):
                results.append((zone, "-", "-", "-"))
            prog.advance(task)

    table = Table(title=f"DNS CAA Records – {domain}", header_style="bold magenta", box=box.MINIMAL)
    table.add_column("Zone", style="cyan")
    table.add_column("Flags", style="green")
    table.add_column("Tag", style="yellow")
    table.add_column("Value", style="white", overflow="fold")
    for row in results:
        table.add_row(*map(str, row))
    console.print(table)

    found = sum(1 for r in results if r[1] != "-")
    summary = (
        f"Zones checked: {len(zones)}  "
        f"Records found: {found}  "
        f"Elapsed: {time.time()-start:.2f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] DNS CAA check completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out_dir, "dns_caa.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    opts = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    raise SystemExit(run(tgt, 1, opts))
