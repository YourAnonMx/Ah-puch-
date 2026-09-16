#!/usr/bin/env python3
import os
import sys
import json
import requests
import urllib3
import dns.resolver
import concurrent.futures
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

REL_TYPES = ("peers", "upstreams", "downstreams")


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – Autonomous Neighbor Peering Map")
    console.print(f"[{TEAL}]{bar}\n")


def resolve_ips(domain, timeout):
    if not str(domain or "").strip():
        return []
    ips = []
    for rtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=timeout)
            ips.extend([r.address for r in answers])
        except:
            pass
    return list(dict.fromkeys(ips))


def ip_to_asn(ip, timeout):
    if not str(ip or "").strip():
        return "-"
    try:
        r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=timeout, verify=True)
        if r.ok:
            prefixes = r.json().get("data", {}).get("prefixes", [])
            if prefixes:
                return str(prefixes[0].get("asn", "-"))
    except:
        pass
    return "-"


def fetch_relations(asn, rel, timeout):
    if not str(asn or "").strip() or rel not in REL_TYPES:
        return []
    try:
        r = requests.get(f"https://api.bgpview.io/asn/{asn}/{rel}", timeout=timeout, verify=True)
        if r.ok:
            items = r.json().get("data", {}).get(rel, [])
            rows = []
            for e in items:
                rows.append((
                    rel,
                    f"AS{e.get('asn','-')}",
                    e.get("prefixes_count", 0),
                    e.get("name", "-"),
                    e.get("country_code", "-"),
                    e.get("ipv4_prefixes_count", 0) + e.get("ipv6_prefixes_count", 0)
                ))
            return rows
    except:
        pass
    return []


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    domain = clean_domain_input(target)
    threads = max(1, int(threads))
    if not domain:
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return
    start = datetime.now(timezone.utc)

    console.print(f"[white][*] Resolving {domain}[/white]")
    ips = resolve_ips(domain, timeout)
    if not ips:
        console.print("[red]✖ No IPs found[/red]")
        return

    asn = "-"
    for ip in ips:
        candidate = ip_to_asn(ip, timeout)
        if candidate not in ("-", "0"):
            asn = candidate
            break
    if asn in ("-", "0"):
        console.print("[yellow]✖ ASN not identified[/yellow]")
        return

    console.print(f"[white][*] Domain {domain} -> ASN AS{asn}[/white]\n")

    relations = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.fields[rel]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Fetching relations", total=len(REL_TYPES), rel="")
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(REL_TYPES)) as pool:
            futures = {pool.submit(fetch_relations, asn, rel, timeout): rel for rel in REL_TYPES}
            for fut in concurrent.futures.as_completed(futures):
                rel = futures[fut]
                prog.update(task, advance=1, rel=rel)
                relations.extend(fut.result())

    if not relations:
        console.print("[yellow]No peering data available[/yellow]")
        return

    table = Table(title=f"Peering Map – AS{asn}", header_style="bold magenta")
    table.add_column("Rel", style="cyan")
    table.add_column("ASN", style="green")
    table.add_column("#Prefixes", justify="right", style="yellow")
    table.add_column("Name", style="white", overflow="fold")
    table.add_column("CC", style="magenta")
    table.add_column("Total IPs", justify="right", style="blue")

    stats = {r: 0 for r in REL_TYPES}
    for rel, asn2, prefixes, name, cc, ips_count in relations:
        table.add_row(rel, asn2, str(prefixes), name, cc, str(ips_count))
        stats[rel] += 1

    console.print(table)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    console.print(f"[white][*] Peers: {stats['peers']}  Upstreams: {stats['upstreams']}  Downstreams: {stats['downstreams']}  Elapsed: {elapsed:.2f}s[/white]")
    console.print("[white][*] Peering map completed[/white]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(f"[white][*] Peers: {stats['peers']}  Upstreams: {stats['upstreams']}  Downstreams: {stats['downstreams']}  Elapsed: {elapsed:.2f}s[/white]")
        write_to_file(os.path.join(out_dir, "peering_map.txt"), export_console.export_text())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 3, opts)
