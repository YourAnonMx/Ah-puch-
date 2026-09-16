import sys
import ssl
import socket
import argparse
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box
from colorama import Fore, init
import concurrent.futures
import threading
from datetime import datetime

init(autoreset=True)
console = Console()
lock = threading.Lock()

def banner():
    console.print(Fore.GREEN + """
    =============================================
        Ah-Puch - Advanced Certificate Recon
    =============================================
    """)

def clean_domain_input(domain: str) -> str:
    if not isinstance(domain, str) or not domain.strip():
        return ""
    domain = domain.strip()
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    parsed_url = urlparse(domain)
    return parsed_url.hostname

def _certificate_sans(cert_details):
    """Return SAN values from either stdlib or legacy parsed certificate shapes."""
    values = []
    direct = cert_details.get("subjectAltName", ()) if isinstance(cert_details, dict) else ()
    for kind, value in direct or ():
        if kind in {"DNS", "IP Address", "URI"} and value:
            values.append(str(value))
    for ext in cert_details.get("extensions", ()) if isinstance(cert_details, dict) else ():
        if ext.get("shortName") != "subjectAltName":
            continue
        values.extend(str(item[1]) for item in ext.get("value", ()) if len(item) > 1 and item[1])
    return tuple(dict.fromkeys(values))


def certificate_attribution(cert_details, peer_address=None, peer_port=None):
    """Normalize certificate identity and peer attribution for downstream consumers."""
    if not isinstance(cert_details, dict):
        return {}
    result = dict(cert_details)
    sans = _certificate_sans(cert_details)
    if sans:
        result["subjectAltName"] = sans
    if peer_address:
        result["peer_address"] = str(peer_address)
    if peer_port and peer_address:
        result["peer_port"] = int(peer_port)
    return result


def get_certificate_details(domain, port=443, timeout=10):
    """Fetch a verified peer certificate while preserving the address/port used."""
    try:
        parsed = urlparse(domain if "://" in domain else f"https://{domain}")
        host = parsed.hostname
        if not host:
            raise ValueError("certificate target has no host")
        target_port = parsed.port or int(port)
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, target_port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # ``getpeercert(binary_form=True)`` returns DER bytes, while
                # the private ``_test_decode_cert`` helper expects a filename
                # and therefore always fails with a real certificate.  The
                # default form is already the parsed certificate mapping.
                peer_address = None
                try:
                    peer_address = ssock.getpeername()[0]
                except (AttributeError, OSError, IndexError, TypeError):
                    pass
                return certificate_attribution(ssock.getpeercert(), peer_address, target_port)
    except (AttributeError, OSError, TypeError, ValueError, ssl.SSLError) as e:
        with lock:
            console.print(Fore.RED + f"[!] Error retrieving certificate from {domain}: {e}")
        return None

def display_certificate_info(domain, cert_details):
    table = Table(title=f"Certificate Details for {domain}", show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Field", style="cyan", justify="left")
    table.add_column("Value", style="green")

    subject = dict(x[0] for x in cert_details.get('subject', []))
    issuer = dict(x[0] for x in cert_details.get('issuer', []))
    serial_number = cert_details.get('serialNumber', '')
    version = cert_details.get('version', '')
    not_before = cert_details.get('notBefore', '')
    not_after = cert_details.get('notAfter', '')
    signature_algorithm = cert_details.get('signatureAlgorithm', '')

    table.add_row("Common Name (CN)", subject.get('commonName', 'N/A'))
    table.add_row("Organization (O)", subject.get('organizationName', 'N/A'))
    table.add_row("Organizational Unit (OU)", subject.get('organizationalUnitName', 'N/A'))
    table.add_row("Country (C)", subject.get('countryName', 'N/A'))
    table.add_row("State (ST)", subject.get('stateOrProvinceName', 'N/A'))
    table.add_row("Locality (L)", subject.get('localityName', 'N/A'))

    table.add_row("Issuer CN", issuer.get('commonName', 'N/A'))
    table.add_row("Issuer O", issuer.get('organizationName', 'N/A'))
    table.add_row("Issuer C", issuer.get('countryName', 'N/A'))

    table.add_row("Serial Number", serial_number)
    table.add_row("Version", str(version))
    table.add_row("Signature Algorithm", signature_algorithm)
    table.add_row("Valid From", not_before)
    table.add_row("Valid To", not_after)

    san_list = _certificate_sans(cert_details)
    table.add_row("Subject Alternative Names", ', '.join(san_list))

    console.print(table)

def process_domain(domain):
    domain = clean_domain_input(domain)
    with lock:
        console.print(Fore.WHITE + f"[*] Fetching certificate details for: {domain}")
    cert_details = get_certificate_details(domain)
    if cert_details:
        display_certificate_info(domain, cert_details)
    else:
        with lock:
            console.print(Fore.RED + f"[!] No certificate details found for {domain}.")

def main():
    banner()
    parser = argparse.ArgumentParser(description='Ah-Puch - Advanced Certificate Recon')
    parser.add_argument('domains', nargs='+', help='Domain(s) to analyze')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    args = parser.parse_args()

    domains = args.domains

    workers = max(1, min(args.threads, 32))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(process_domain, domain): domain for domain in domains}
        for future in concurrent.futures.as_completed(futures):
            pass  # Results are handled in process_domain

    console.print(Fore.CYAN + "[*] Certificate Authority Recon completed.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        sys.exit(1)
