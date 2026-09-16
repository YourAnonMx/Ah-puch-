import argparse
import concurrent.futures
import sys
import time
from urllib.parse import urlparse

import requests
from colorama import Fore, init
from rich import box
from rich.console import Console
from rich.table import Table

init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10
MAX_POLL_ATTEMPTS = 6
POLL_INTERVAL_SECONDS = 2


def banner():
    console.print(Fore.GREEN + """
    =============================================
          Ah-Puch - Advanced SSL Labs Scanner
    =============================================
    """)


def clean_domain_input(domain: str) -> str:
    if not isinstance(domain, str) or not domain.strip():
        return ""
    domain = domain.strip()
    parsed_url = urlparse(domain)
    if parsed_url.netloc:
        return parsed_url.hostname or parsed_url.netloc
    return parsed_url.path.strip("/")


def fetch_ssl_labs_report(domain, use_cache=True, max_polls=MAX_POLL_ATTEMPTS):
    """Fetch one bounded SSL Labs analysis result.

    SSL Labs may return a processing state for several requests.  The legacy
    implementation polled forever; this contract caps follow-up requests so the
    catalog subprocess has deterministic terminal behavior.
    """
    try:
        poll_limit = int(max_polls)
    except (TypeError, ValueError):
        return None
    if poll_limit < 0:
        return None
    poll_limit = min(poll_limit, 10)
    if not isinstance(domain, str) or not domain.strip():
        return None

    base_url = "https://api.ssllabs.com/api/v3/analyze"
    params = {
        "host": domain,
        "fromCache": "on" if use_cache else "off",
        "all": "done",
    }
    processing = {"DNS", "IN_PROGRESS", "RUNNING"}

    for attempt in range(poll_limit + 1):
        try:
            response = requests.get(base_url, params=params, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        except (OSError, requests.RequestException, TypeError, ValueError) as exc:
            console.print(Fore.RED + f"[!] Error fetching SSL Labs report for {domain}: {exc}")
            return None
        if response.status_code != 200:
            console.print(Fore.RED + f"[!] Error fetching SSL Labs report for {domain}: HTTP {response.status_code}")
            return None
        try:
            data = response.json()
        except (ValueError, TypeError) as exc:
            console.print(Fore.RED + f"[!] Invalid SSL Labs response for {domain}: {type(exc).__name__}")
            return None
        if not isinstance(data, dict):
            console.print(Fore.RED + f"[!] Invalid SSL Labs response for {domain}: expected object")
            return None

        status = str(data.get("status", ""))
        if status == "READY":
            return data
        if status not in processing:
            console.print(Fore.RED + f"[!] Analysis failed for {domain}. Status: {status or 'UNKNOWN'}")
            return None
        if attempt >= poll_limit:
            console.print(Fore.RED + f"[!] SSL Labs analysis did not become READY within {poll_limit} follow-up polls for {domain}.")
            return None
        console.print(Fore.YELLOW + f"[*] Analysis in progress for {domain}. Waiting for results...")
        time.sleep(POLL_INTERVAL_SECONDS)
    return None


def display_ssl_labs_report(domain, data):
    endpoints = data.get("endpoints", [])
    if not endpoints:
        console.print(Fore.RED + f"[!] No endpoints found for {domain}.")
        return

    for endpoint in endpoints:
        ip_address = endpoint.get("ipAddress", "N/A")
        grade = endpoint.get("grade", "N/A")
        details = endpoint.get("details", {})
        protocols = details.get("protocols", [])
        suites_data = details.get("suites", {})
        suites = suites_data.get("list", []) if isinstance(suites_data, dict) else []

        server_signature = details.get("serverSignature", "N/A")
        ocsp_stapling = "Yes" if details.get("ocspStapling", False) else "No"

        hsts_policy_data = details.get("hstsPolicy", {})
        hsts_status = hsts_policy_data.get("status", "N/A") if isinstance(hsts_policy_data, dict) else "N/A"

        vuln_beast = "Yes" if details.get("vulnBeast", False) else "No"
        poodle_tls = details.get("poodleTls", 0)
        heartbleed = "Yes" if details.get("heartbleed", False) else "No"
        supports_rc4 = "Yes" if details.get("supportsRc4", False) else "No"

        protocols_supported = (
            ", ".join(f"{p.get('name', 'N/A')} {p.get('version', 'N/A')}" for p in protocols)
            if isinstance(protocols, list)
            else "N/A"
        )
        cipher_suites = (
            ", ".join(suite.get("name", "") for suite in suites)
            if isinstance(suites, list)
            else "N/A"
        )

        table = Table(
            title=f"SSL Labs Report for {domain} [{ip_address}]",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
        )
        table.add_column("Field", style="cyan", justify="left")
        table.add_column("Details", style="green")
        table.add_row("Grade", str(grade))
        table.add_row("Protocols Supported", protocols_supported)
        table.add_row("Cipher Suites", cipher_suites)
        table.add_row("Server Signature", str(server_signature))
        table.add_row("OCSP Stapling", ocsp_stapling)
        table.add_row("HSTS Policy", str(hsts_status))
        table.add_row("Vulnerable to BEAST", vuln_beast)
        table.add_row("POODLE TLS", str(poodle_tls))
        table.add_row("Heartbleed Vulnerability", heartbleed)
        table.add_row("Supports RC4", supports_rc4)
        console.print(table)


def process_domain(domain, use_cache):
    domain = clean_domain_input(domain)
    if not domain:
        console.print(Fore.RED + "[!] Empty domain after normalization.")
        return False
    console.print(Fore.WHITE + f"[*] Fetching SSL Labs report for: {domain}")
    ssl_labs_data = fetch_ssl_labs_report(domain, use_cache=use_cache)
    if ssl_labs_data:
        display_ssl_labs_report(domain, ssl_labs_data)
        return True
    console.print(Fore.RED + f"[!] No SSL Labs data found for {domain}.")
    return False


def main(argv=None):
    banner()
    parser = argparse.ArgumentParser(description="Ah-Puch - Advanced SSL Labs Scanner")
    parser.add_argument("domains", nargs="+", help="Domain(s) to analyze")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--no-cache", action="store_true", help="Force a new analysis (do not use cached results)")
    args = parser.parse_args(argv)
    if args.threads < 1:
        parser.error("--threads must be positive")

    failures = 0
    use_cache = not args.no_cache
    workers = min(max(args.threads, 1), 32)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(process_domain, domain, use_cache): domain for domain in args.domains}
        for future in concurrent.futures.as_completed(futures):
            domain = futures[future]
            try:
                if future.result() is not True:
                    failures += 1
            except (OSError, TypeError, ValueError) as exc:
                console.print(Fore.RED + f"[!] Error processing {domain}: {exc}")
                failures += 1

    if failures:
        console.print(Fore.RED + f"[!] SSL analysis incomplete: {failures} domain(s) failed.")
        return 1
    console.print(Fore.CYAN + "[*] SSL analysis completed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
