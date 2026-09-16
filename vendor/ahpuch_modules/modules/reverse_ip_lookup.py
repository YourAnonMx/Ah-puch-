import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import init

from ahpuch_modules.utils.util import resolve_to_ip
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, API_KEYS

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
      Ah-Puch - Reverse IP Lookup
    =============================================
    """)

def fetch_shodan(ip):
    if not str(ip or "").strip():
        return []
    key = API_KEYS.get("SHODAN_API_KEY")
    if key:
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                timeout=DEFAULT_TIMEOUT
            )
            if resp.status_code == 200:
                return resp.json().get("hostnames", [])
        except:
            pass
    return []

def fetch_hackertarget(ip):
    if not str(ip or "").strip():
        return []
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=DEFAULT_TIMEOUT
        )
        if resp.status_code == 200 and "error" not in resp.text.lower():
            return resp.text.splitlines()
    except:
        pass
    return []

def display_results(results):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Domain", style="cyan")
    table.add_column("Source", style="green")
    for domain, source in results:
        table.add_row(domain, source)
    console.print(table)

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Please pass a domain or IP.[/red]")
        sys.exit(1)
    target = sys.argv[1]
    console.print(f"[white][*] Resolving target for reverse IP lookup: {target}[/white]")
    ip = resolve_to_ip(target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        sys.exit(1)
    shodan_hosts = [(d, "Shodan") for d in fetch_shodan(ip)]
    ht_hosts = [(d, "HackerTarget") for d in fetch_hackertarget(ip)]
    unique = {}
    for domain, src in shodan_hosts + ht_hosts:
        unique.setdefault(domain, src)
    display_results(unique.items())
    console.print("[white][*] Reverse IP lookup completed.[/white]")
