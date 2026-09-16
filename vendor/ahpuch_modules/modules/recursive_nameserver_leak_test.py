#!/usr/bin/env python3
import os
import sys
import json
import random
import string
import ipaddress
import concurrent.futures
import dns.resolver
import dns.message
import dns.query
import dns.flags
import dns.rcode
import urllib3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"
TEST_EXTERNAL = "www.google.com."

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS
from ahpuch_modules.utils.util import clean_domain_input, resolve_to_ip, ensure_directory_exists, write_to_file

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – Recursive NS Leak Test")
    console.print(f"[{TEAL}]{bar}")

def rand_label(length=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def get_ns(domain: str, timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    if not str(domain or "").strip():
        return []
    try:
        ans = dns.resolver.resolve(domain, "NS", lifetime=timeout)
        return [str(r.target).rstrip(".") for r in ans]
    except:
        return []

def get_ips(host: str, timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    if not str(host or "").strip():
        return []
    ips = []
    try:
        for r in dns.resolver.resolve(host, "A", lifetime=timeout):
            ips.append(r.address)
    except:
        pass
    try:
        for r in dns.resolver.resolve(host, "AAAA", lifetime=timeout):
            ips.append(r.address)
    except:
        pass
    return ips

def do_query(ns_ip: str, qname: str, rd_flag: bool, timeout: int = DEFAULT_TIMEOUT):
    if not str(ns_ip or "").strip() or not str(qname or "").strip():
        return None
    try:
        query = dns.message.make_query(qname, "A", use_edns=True)
        if not rd_flag:
            query.flags &= ~dns.flags.RD
        return dns.query.udp(query, ns_ip, timeout=timeout)
    except:
        return None

def analyze_response(resp) -> tuple[str,str]:
    if not resp:
        return "NORESP", "-"
    code = dns.rcode.to_text(resp.rcode())
    ra = "Y" if resp.flags & dns.flags.RA else "N"
    ans_count = sum(len(sec.items) for sec in resp.answer)
    add_count = sum(len(sec.items) for sec in resp.additional)
    return code, f"{ra}/{ans_count}/{add_count}"

def probe_ns(ns_host: str, domain: str, timeout: int = DEFAULT_TIMEOUT) -> tuple:
    if not str(ns_host or "").strip() or not str(domain or "").strip():
        return (ns_host or "-", "-", "-", "-", "-", "-", "-")
    ips = get_ips(ns_host, timeout)
    if not ips:
        return (ns_host, "-", "-", "-", "-", "-", "-")
    ip = ips[0]
    sub = f"{rand_label()}.{domain}"
    r1 = do_query(ip, sub, rd_flag=True, timeout=timeout)
    r2 = do_query(ip, TEST_EXTERNAL, rd_flag=True, timeout=timeout)
    r3 = do_query(ip, TEST_EXTERNAL, rd_flag=False, timeout=timeout)
    c1, d1 = analyze_response(r1)
    c2, d2 = analyze_response(r2)
    c3, d3 = analyze_response(r3)
    recursion = "Open" if d2.startswith("Y") and c2 in ("NOERROR", "NXDOMAIN") else "Closed"
    leak      = "Y"    if recursion == "Open" and d3.startswith("N")         else "N"
    return (ns_host, ip, c1, c2, c3, recursion, leak)

def run(target: str, threads: int, opts: dict):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT)) if isinstance(opts, dict) else DEFAULT_TIMEOUT
    domain  = clean_domain_input(target)
    threads = max(1, int(threads))
    if not domain:
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return
    try:
        ipaddress.ip_address(domain)
        is_ip = True
    except:
        is_ip = False

    ip = domain if is_ip else resolve_to_ip(domain)
    if not ip:
        console.print("[red]✖ IP resolution failed[/red]")
        return

    ns_hosts = get_ns(domain, timeout)
    if not ns_hosts:
        console.print("[yellow]✖ No NS records found[/yellow]")
        return

    console.print(f"[white]* Testing {len(ns_hosts)} NS servers for {domain}[/white]")
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}", style="white"),
        BarColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Scanning", total=len(ns_hosts))
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ns_hosts), threads)) as executor:
            futures = {executor.submit(probe_ns, ns, domain, timeout): ns for ns in ns_hosts}
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())
                progress.advance(task)

    table = Table(
        title=f"Recursive NS Leak Test – {domain}",
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL
    )
    table.add_column("NS",        style="cyan",  overflow="fold")
    table.add_column("IP",        style="green")
    table.add_column("TestSub",   style="yellow")
    table.add_column("ExtRD",     style="white")
    table.add_column("ExtNoRD",   style="white")
    table.add_column("Recursion", style="blue")
    table.add_column("Leak",      style="magenta")

    for row in results:
        table.add_row(*row)

    if results:
        console.print(table)
    else:
        console.print("[yellow]No data[/yellow]")
    console.print("[white][*] Recursive NS leak testing completed[/white]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        if results:
            export_console.print(table)
        else:
            export_console.print("[yellow]No data[/yellow]")
        write_to_file(
            os.path.join(out_dir, "recursive_ns_leak_test.txt"),
            export_console.export_text()
        )

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 10
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            opts = {}
    run(tgt, thr, opts)
