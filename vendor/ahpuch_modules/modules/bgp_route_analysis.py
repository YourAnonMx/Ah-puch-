#!/usr/bin/env python3
import os, sys, json, requests, concurrent.futures, urllib3
from rich.console import Console
from rich.table import Table

from ahpuch_modules.utils.util import resolve_to_ip, clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

def banner():
    console.print("[cyan]" + "="*45)
    console.print("[cyan]       Ah-Puch - BGP Route Analysis")
    console.print("[cyan]" + "="*45)

def get_asn(ip, t):
    try:
        r = requests.get(f"https://ip-api.com/json/{ip}?fields=as", timeout=t, verify=True)
        if r.ok:
            return r.json().get("as", "").split()[0]
    except:
        pass
    return ""

def fetch_prefixes(asn, version, t):
    try:
        d = requests.get(f"https://api.bgpview.io/asn/{asn}/prefixes", timeout=t, verify=True).json().get("data", {})
        return d.get(f"ipv{version}_prefixes", [])
    except:
        return []

def display(rows):
    tbl = Table(show_header=True, header_style="bold white")
    tbl.add_column("Prefix", justify="left", min_width=22)
    tbl.add_column("Type",   justify="left", min_width=6)
    tbl.add_column("Status", justify="left", min_width=10)
    for r in rows:
        tbl.add_row(*r)
    console.print(tbl)

def run(target, threads, opts):
    banner()
    t = int(opts.get("timeout", DEFAULT_TIMEOUT))
    if not clean_domain_input(target):
        console.print("[yellow][!] No target provided")
        return
    ip = resolve_to_ip(target)
    if not ip:
        console.print("[red][!] IP resolution failed")
        return
    console.print(f"[white][*] IP: [cyan]{ip}")
    asn = get_asn(ip, t)
    if not asn:
        console.print("[red][!] ASN fetch failed")
        return
    console.print(f"[white][*] ASN: [cyan]{asn}")
    console.print("[white][*] Fetching prefixes…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        ipv4, ipv6 = pool.map(lambda v: fetch_prefixes(asn, v, t), (4, 6))
    rows = [[p.get("prefix", ""), "IPv4", p.get("status", "")] for p in ipv4] + \
           [[p.get("prefix", ""), "IPv6", p.get("status", "")] for p in ipv6]
    console.print(f"[white][*] Total prefixes: [cyan]{len(rows)}")
    display(rows)
    console.print("[green][*] BGP route analysis completed")
    if EXPORT_SETTINGS["enable_txt_export"]:
        path = os.path.join(RESULTS_DIR, clean_domain_input(target))
        ensure_directory_exists(path)
        write_to_file(os.path.join(path, "bgp_route_analysis.txt"), "\n".join("\t".join(r) for r in rows))

if __name__ == "__main__":
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 2
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            pass
    run(tgt, thr, opts)
