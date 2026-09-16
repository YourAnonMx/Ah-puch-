import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, API_KEYS

init(autoreset=True)
console = Console()
MAX_TIMEOUT = 300

def banner():
    console.print("""
    =============================================
        Ah-Puch - Passive DNS History
    =============================================
    """)

def fetch_securitytrails(domain, timeout=DEFAULT_TIMEOUT):
    key = API_KEYS.get("SECURITYTRAILS_API_KEY")
    if not key:
        return []
    try:
        r = requests.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": key},
            timeout=timeout
        )
        if r.status_code == 200:
            data = r.json()
            out = []
            for recset in data.get("records", []):
                values = recset.get("values", [])
                first_seen = recset.get("first_seen")
                last_seen = recset.get("last_seen")
                for v in values:
                    out.append((v.get("ip"), first_seen, last_seen, "SecurityTrails"))
            return out
    except (requests.RequestException, OSError, TypeError, ValueError):
        pass
    return []

def fetch_threatcrowd(domain, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            ips = data.get("ips", [])
            out = []
            for ip in ips:
                out.append((ip, None, None, "ThreatCrowd"))
            return out
    except (requests.RequestException, OSError, TypeError, ValueError):
        pass
    return []

def fetch_hackertarget(domain, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=timeout)
        if r.status_code == 200 and "error" not in r.text.lower():
            out = []
            for line in r.text.splitlines():
                if "A\t" in line:
                    try:
                        ip = line.split("\t")[-1].strip()
                        out.append((ip, None, None, "HackerTarget"))
                    except (IndexError, TypeError, ValueError):
                        pass
            return out
    except (requests.RequestException, OSError, TypeError, ValueError):
        pass
    return []

def display_records(domain, records):
    table = Table(title=f"Passive DNS History: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("IP", style="cyan")
    table.add_column("First Seen", style="green")
    table.add_column("Last Seen", style="yellow")
    table.add_column("Source", style="white")
    for ip, first_seen, last_seen, src in records:
        table.add_row(ip or "N/A", str(first_seen) if first_seen else "?", str(last_seen) if last_seen else "?", src)
    console.print(table)


def run(target, threads=1, opts=None):
    """Retrieve and merge passive DNS observations from configured public sources."""
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    domain = clean_domain_input(str(target or ""))
    if not domain:
        console.print("[red][!] No domain provided. Please pass a domain.[/red]")
        return 2
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        securitytrails_task = progress.add_task("SecurityTrails", total=1)
        securitytrails = fetch_securitytrails(domain, timeout)
        progress.advance(securitytrails_task)
        threatcrowd_task = progress.add_task("ThreatCrowd", total=1)
        threatcrowd = fetch_threatcrowd(domain, timeout)
        progress.advance(threatcrowd_task)
        hackertarget_task = progress.add_task("HackerTarget", total=1)
        hackertarget = fetch_hackertarget(domain, timeout)
        progress.advance(hackertarget_task)
    merged = {}
    for ip, first_seen, last_seen, source in securitytrails + threatcrowd + hackertarget:
        record = merged.setdefault(ip, [ip, first_seen, last_seen, source])
        if not record[1] and first_seen:
            record[1] = first_seen
        if not record[2] and last_seen:
            record[2] = last_seen
    records = [tuple(record) for record in merged.values()]
    display_records(domain, records)
    console.print("[white][*] Passive DNS history lookup completed.[/white]")
    return 0

if __name__ == "__main__":
    banner()
    try:
        options = __import__("json").loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, KeyError):
        options = {}
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else "", 1, options))
