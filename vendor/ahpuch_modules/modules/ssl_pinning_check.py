import sys
import requests
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from colorama import Fore, init
import argparse
import concurrent.futures

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10

def banner():
    console.print(Fore.GREEN + """
=============================================
      Ah-Puch - Advanced SSL Pinning Check
=============================================
""")

def clean_domain_input(domain: str) -> str:
    if not isinstance(domain, str) or not domain.strip():
        return ""
    domain = domain.strip()
    parsed_url = urlparse(domain)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return parsed_url.path

def check_ssl_pinning(domain):
    if not isinstance(domain, str) or not domain.strip():
        return None
    try:
        response = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        pinning_headers = [value for key, value in response.headers.items() if 'Public-Key-Pins' in key]
        if pinning_headers:
            return True
        return False
    except (OSError, requests.RequestException, TypeError, ValueError) as e:
        console.print(Fore.RED + f"[!] Error checking SSL pinning for {domain}: {e}")
        return None

def display_ssl_pinning_result(domain, result):
    table = Table(title=f"SSL Pinning Check for {domain}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Domain", style="cyan", justify="left")
    table.add_column("SSL Pinning Status", style="green", justify="left")
    status = "Enabled" if result else "Not Enabled"
    table.add_row(domain, status)
    console.print(table)

def process_domain(domain):
    domain = clean_domain_input(domain)
    if not domain:
        return False
    console.print(Fore.WHITE + f"[*] Checking SSL pinning for: {domain}")
    pinning_status = check_ssl_pinning(domain)
    if pinning_status is not None:
        display_ssl_pinning_result(domain, pinning_status)
        return True
    else:
        console.print(Fore.RED + f"[!] Could not retrieve SSL pinning information for {domain}.")
        return False

def main():
    banner()

    parser = argparse.ArgumentParser(description='Ah-Puch - Advanced SSL Pinning Check')
    parser.add_argument('domains', nargs='+', help='Domain(s) to check for SSL pinning')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    args = parser.parse_args()

    domains = args.domains

    failures = 0
    workers = min(max(args.threads, 1), 32)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(process_domain, domain): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                if future.result() is not True:
                    failures += 1
            except (OSError, TypeError, ValueError) as e:
                console.print(Fore.RED + f"[!] Error processing {domain}: {e}")
                failures += 1

    if failures:
        console.print(Fore.RED + f"[!] SSL pinning check incomplete: {failures} domain(s) failed.")
        return 1
    console.print(Fore.CYAN + "[*] SSL pinning check completed.")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
