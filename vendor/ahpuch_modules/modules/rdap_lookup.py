#!/usr/bin/env python3
import os
import sys
import json
import requests
import urllib3
import ipaddress
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"

from ahpuch_modules.utils.util import clean_domain_input, resolve_to_ip, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – RDAP Lookup")
    console.print(f"[{TEAL}]{bar}")

def fetch_rdap(endpoint: str, timeout: int) -> dict:
    try:
        r = requests.get(endpoint, timeout=timeout, verify=True)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return {}

def parse_network(data: dict) -> list[tuple[str,str]]:
    net = data.get("network", {})
    return [
        ("Handle",     net.get("handle", "-")),
        ("Name",       net.get("name",   "-")),
        ("Type",       net.get("type",   "-")),
        ("Country",    net.get("country","-")),
        ("Start Addr", net.get("startAddress","-")),
        ("End Addr",   net.get("endAddress",  "-")),
    ]

def parse_entities(data: dict) -> list[tuple[str,str,str]]:
    rows = []
    for ent in data.get("entities", []):
        roles = ",".join(ent.get("roles", [])) or "-"
        vcard = ent.get("vcardArray", [[], []])[1]
        fn = next((item[3] for item in vcard if item[0] == "fn"), "-")
        emails = [item[3] for item in vcard if item[0] == "email"]
        rows.append((roles, fn, ",".join(emails) or "-"))
    return rows

def parse_events(data: dict) -> list[tuple[str,str]]:
    rows = []
    for ev in data.get("events", []):
        rows.append((ev.get("eventAction", "-"), ev.get("eventDate", "-")))
    return rows

def run(target: str, threads: int, opts):
    if not isinstance(opts, dict):
        opts = {"timeout": opts}
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom = clean_domain_input(target)
    if not dom:
        console.print("[yellow]No target[/yellow]")
        return
    try:
        ipaddress.ip_address(dom)
        is_ip = True
    except:
        is_ip = False

    ip = dom if is_ip else resolve_to_ip(dom)
    if not ip:
        console.print("[red]✖ IP resolution failed[/red]")
        return

    console.print(f"[white]* Target: {dom} ({ip})[/white]")

    url = f"https://rdap.org/{'ip' if is_ip else 'domain'}/{ip if is_ip else dom}"
    data = fetch_rdap(url, timeout)
    if not data and not is_ip:
        data = fetch_rdap(f"https://rdap.org/ip/{ip}", timeout)

    if not data:
        console.print("[yellow]No RDAP data[/yellow]")
        return

    tbl_net = Table(
        title=f"RDAP Lookup – {ip}",
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL
    )
    tbl_net.add_column("Field", style="magenta")
    tbl_net.add_column("Value", style="cyan", overflow="fold")
    for f, v in parse_network(data):
        tbl_net.add_row(f, v)
    console.print(tbl_net)

    ent = parse_entities(data)
    if ent:
        tbl_ent = Table(
            title=f"Entities – {ip}",
            show_header=True,
            header_style="bold magenta",
            box=box.MINIMAL
        )
        tbl_ent.add_column("Roles", style="cyan")
        tbl_ent.add_column("Name",  style="green")
        tbl_ent.add_column("Email", style="yellow", overflow="fold")
        for r, n, e in ent:
            tbl_ent.add_row(r, n, e)
        console.print(tbl_ent)

    ev = parse_events(data)
    if ev:
        tbl_ev = Table(
            title=f"Events – {ip}",
            show_header=True,
            header_style="bold magenta",
            box=box.MINIMAL
        )
        tbl_ev.add_column("Action", style="cyan")
        tbl_ev.add_column("Date",   style="green")
        for a, d in ev:
            tbl_ev.add_row(a, d)
        console.print(tbl_ev)

    console.print("[green]* RDAP lookup completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, ip)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(tbl_net)
        if ent:
            export_console.print(tbl_ent)
        if ev:
            export_console.print(tbl_ev)
        write_to_file(os.path.join(out, "rdap.txt"), export_console.export_text())

if __name__ == "__main__":
    tgt = sys.argv[1]
    thr = 1
    opts = {}
    if len(sys.argv) > 2:
        try:
            opts = json.loads(sys.argv[2])
        except:
            opts = {"timeout": opts}
    run(tgt, thr, opts)
