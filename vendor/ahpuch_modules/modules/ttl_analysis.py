import os
import sys
import re
import socket
import subprocess
import dns.resolver
import dns.exception
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from ahpuch_modules.utils.util import clean_domain_input, resolve_to_ip
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()
MAX_TIMEOUT = 300

def banner():
    console.print("""
    =============================================
           Ah-Puch - TTL Analysis
    =============================================
    """)

def dns_min_ttl(domain, timeout=DEFAULT_TIMEOUT):
    ttl_vals = []
    for rtype in ["A", "AAAA", "MX", "NS"]:
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=timeout)
            ttl_vals.append(ans.rrset.ttl)
        except (dns.exception.DNSException, OSError, ValueError):
            pass
    return min(ttl_vals) if ttl_vals else None

def icmp_ttl(ip, timeout=DEFAULT_TIMEOUT):
    try:
        proc = subprocess.Popen(
            ["ping","-c","1","-W","1",ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        out,_ = proc.communicate(timeout=timeout)
        m = re.search(r"ttl[=|:](\d+)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass
    return None

def guess_start_ttl(observed):
    if observed is None:
        return None,"Unknown"
    bases = [32,60,64,128,255]
    nearest = min(bases, key=lambda b: abs(b-observed))
    fam = "Unix/Linux" if nearest in (60,64) else ("Windows" if nearest==128 else ("Network/Embedded" if nearest==255 else "Other"))
    return nearest,fam

def display(domain, ip, dns_ttl, icmp_val, guess_val, fam):
    table = Table(title=f"TTL Analysis: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Domain", domain)
    table.add_row("IP", ip)
    table.add_row("Min DNS TTL", str(dns_ttl) if dns_ttl is not None else "N/A")
    table.add_row("Observed ICMP TTL", str(icmp_val) if icmp_val is not None else "N/A")
    table.add_row("Guessed Start TTL", str(guess_val) if guess_val is not None else "N/A")
    table.add_row("Likely OS Family", fam)
    console.print(table)


def run(target, threads=1, opts=None):
    """Compare DNS and ICMP TTL values for one resolvable target."""
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    domain = clean_domain_input(str(target or ""))
    if not domain:
        console.print("[red][!] No domain provided.[/red]")
        return 2
    ip = resolve_to_ip(domain)
    if not ip:
        console.print("[red][!] Could not resolve domain.[/red]")
        return 2
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        dns_task = progress.add_task("DNS TTL", total=1)
        dns_ttl = dns_min_ttl(domain, timeout)
        progress.advance(dns_task)
        icmp_task = progress.add_task("ICMP TTL", total=1)
        observed_ttl = icmp_ttl(ip, timeout)
        progress.advance(icmp_task)
    guessed_ttl, family = guess_start_ttl(observed_ttl)
    display(domain, ip, dns_ttl, observed_ttl, guessed_ttl, family)
    console.print("[white][*] TTL analysis completed.[/white]")
    return 0

if __name__ == "__main__":
    banner()
    try:
        options = __import__("json").loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, KeyError):
        options = {}
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else "", 1, options))
