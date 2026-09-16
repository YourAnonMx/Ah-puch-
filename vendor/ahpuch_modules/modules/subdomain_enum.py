import os
import sys
import requests
from colorama import Fore, init
from rich.console import Console
from rich.table import Table


init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Ah-Puch - Subdomain Enumeration (crt.sh)
    =============================================
    """)

def fetch_subdomains(domain):
    if not isinstance(domain, str) or not domain.strip():
        return []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10, verify=True, allow_redirects=False)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomains.add(entry['name_value'])
            return list(subdomains)
        else:
            console.print(Fore.RED + f"[!] Error fetching data from crt.sh: {response.status_code}")
            return []
    except (OSError, requests.RequestException, TypeError, ValueError, KeyError) as e:
        console.print(Fore.RED + f"[!] Error fetching subdomains: {e}")
        return []

def display_subdomains(subdomains):
    if not subdomains:
        console.print(Fore.YELLOW + "[!] No subdomains found.")
    else:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Subdomains", style="cyan", justify="left")
        for sub in subdomains:
            table.add_row(sub)
        console.print(table)

def main(domain):
    if not isinstance(domain, str) or not domain.strip():
        return 2
    banner()
    console.print(Fore.WHITE + f"[*] Fetching subdomains for: {domain}")
    subdomains = fetch_subdomains(domain)
    display_subdomains(subdomains)
    console.print(Fore.WHITE + "[*] Subdomain enumeration completed.")
    return 0

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_domain = sys.argv[1]
        try:
            main(target_domain)
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No domain provided. Please pass a domain.")
        sys.exit(1)
