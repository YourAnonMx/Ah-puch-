import os
import sys
import json
import socket
import requests
from rich.console import Console
from rich.table import Table
from colorama import init

from ahpuch_modules.utils.util import resolve_to_ip
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()
MAX_TIMEOUT = 300

def banner():
    console.print("""
    =============================================
    Ah-Puch - IRR / Routing Registry Analyzer
    =============================================
    """)

def get_asn(ip, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(f"https://ip-api.com/json/{ip}?fields=as", timeout=timeout)
        if r.status_code == 200:
            val = r.json().get("as")
            if val:
                return val.split()[0]
    except (requests.RequestException, TypeError, ValueError):
        pass
    return None

def radb_query(asn, timeout=DEFAULT_TIMEOUT):
    out = []
    try:
        with socket.create_connection(("whois.radb.net", 43), timeout=timeout) as connection:
            q = f"AS{asn}\n" if not asn.upper().startswith("AS") else f"{asn}\n"
            connection.sendall(q.encode())
            data = b""
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
        for block in data.decode(errors="ignore").split("\n\n"):
            route = None
            descr = None
            origin = None
            source = None
            for line in block.splitlines():
                if line.lower().startswith("route6:") or line.lower().startswith("route:"):
                    route = line.split(":",1)[1].strip()
                elif line.lower().startswith("descr:"):
                    descr = (descr+" " if descr else "") + line.split(":",1)[1].strip()
                elif line.lower().startswith("origin:"):
                    origin = line.split(":",1)[1].strip()
                elif line.lower().startswith("source:"):
                    source = line.split(":",1)[1].strip()
            if route:
                out.append((route,descr or "",origin or "",source or "RADB"))
    except (OSError, TypeError, ValueError):
        pass
    return out

def ripe_query(asn, timeout=DEFAULT_TIMEOUT):
    try:
        q = asn if asn.upper().startswith("AS") else f"AS{asn}"
        r = requests.get(f"https://rest.db.ripe.net/search.json?query-string={q}&type-filter=route&type-filter=route6", timeout=timeout)
        if r.status_code == 200:
            objs = r.json().get("objects",{}).get("object",[])
            out=[]
            for o in objs:
                attrs = {a["name"].lower():a["value"] for a in o.get("attributes",{}).get("attribute",[])}
                route = attrs.get("route") or attrs.get("route6")
                if route:
                    out.append((route,attrs.get("descr",""),attrs.get("origin",""),"RIPE"))
            return out
    except (requests.RequestException, TypeError, ValueError):
        pass
    return []

def display(asn, records):
    table = Table(title=f"IRR Routes for {asn}", show_header=True, header_style="bold magenta")
    table.add_column("Prefix", style="cyan")
    table.add_column("Descr", style="green", overflow="fold")
    table.add_column("Origin", style="yellow")
    table.add_column("Source", style="white")
    for r in records:
        table.add_row(r[0], r[1], r[2], r[3])
    console.print(table if records else "[yellow][!] No IRR route objects found[/yellow]")


def run(target, threads=1, opts=None):
    """Resolve a target, retrieve its ASN, and compare public IRR sources."""
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    cleaned_target = str(target or "").strip()
    if not cleaned_target:
        console.print("[red][!] No target provided. Pass a domain or IP.[/red]")
        return 2
    console.print(f"[white][*] Resolving target for IRR analysis: {cleaned_target}[/white]")
    ip = resolve_to_ip(cleaned_target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        return 2
    asn = get_asn(ip, timeout)
    if not asn:
        console.print("[red][!] Could not determine ASN[/red]")
        return 1
    console.print(f"[white][*] ASN: {asn}[/white]")
    merged = {}
    for route, descr, origin, source in radb_query(asn, timeout) + ripe_query(asn, timeout):
        merged[route] = (route, descr, origin, source)
    display(asn, list(merged.values()))
    console.print("[white][*] IRR routing registry analysis completed.[/white]")
    return 0

if __name__ == "__main__":
    banner()
    try:
        options = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError):
        options = {}
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else "", 1, options))
