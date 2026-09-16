#!/usr/bin/env python3
import os
import sys
import json
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

from ahpuch_modules.utils.util import clean_url, clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

init(autoreset=True)
console = Console()

GDPR_KEYWORDS = [
    "gdpr", "general data protection regulation", "data controller",
    "data processor", "consent", "data subject", "data protection officer",
    "privacy rights", "right to be forgotten", "data breach"
]

PRIVACY_KEYWORDS = [
    "personal data", "data collection", "data usage", "information we collect",
    "how we use your information", "data sharing", "third-party services",
    "data retention", "user rights", "privacy statement"
]

COOKIE_KEYWORDS = [
    "cookie policy", "cookies", "tracking technologies", "third-party cookies",
    "cookie consent", "manage cookies", "cookie settings"
]

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Ah-Puch – Privacy & GDPR Compliance
    =============================================
    """)

def find_policy_links(session, base, timeout=DEFAULT_TIMEOUT):
    if not isinstance(base, str) or not base.strip():
        return (None, None, None)
    try:
        r = session.get(base, timeout=timeout, verify=True, allow_redirects=False)
    except (OSError, requests.RequestException, TypeError, ValueError):
        return (None, None, None)
    soup = BeautifulSoup(r.text, "html.parser")
    privacy = gdpr = cookie = None
    texts = {
        "privacy": ["privacy policy", "privacy statement", "data protection policy"],
        "gdpr": ["gdpr", "data protection regulation"],
        "cookie": ["cookie policy", "cookie consent", "manage cookies"]
    }
    for a in soup.find_all("a", href=True):
        t = a.get_text(strip=True).lower()
        href = urljoin(base, a["href"])
        if not privacy and any(x in t for x in texts["privacy"]):
            privacy = href
        if not gdpr and any(x in t for x in texts["gdpr"]):
            gdpr = href
        if not cookie and any(x in t for x in texts["cookie"]):
            cookie = href
        if privacy and gdpr and cookie:
            break
    host = urlparse(base).netloc
    if not privacy: privacy = f"{base.rstrip('/')}/privacy-policy"
    if not gdpr:    gdpr    = f"{base.rstrip('/')}/gdpr-compliance"
    if not cookie:  cookie  = f"{base.rstrip('/')}/cookie-policy"
    return privacy, gdpr, cookie

def check_policy(url, keywords, timeout=DEFAULT_TIMEOUT):
    if not isinstance(url, str) or not url.strip():
        return "Error", False, url or ""
    try:
        r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        found = r.status_code == 200 and any(k in r.text.lower() for k in keywords)
        status = "Configured" if r.status_code == 200 else f"Missing ({r.status_code})"
        return status, found, url
    except (OSError, requests.RequestException, TypeError, ValueError):
        return "Error", False, url

def display_results(res_privacy, res_gdpr, res_cookie):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Compliant", style="yellow")
    table.add_column("URL", overflow="fold")
    for name, res in [
        ("Privacy Policy", res_privacy),
        ("GDPR Compliance", res_gdpr),
        ("Cookie Policy", res_cookie)
    ]:
        status, compliant, url = res
        table.add_row(name, status, "Yes" if compliant else "No", url)
    console.print(table)
    return table

def run(target, threads, opts):
    if not isinstance(target, str) or not target.strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    banner()
    try:
        timeout = min(max(int(opts.get("timeout", DEFAULT_TIMEOUT)), 1), 60)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    tgt = clean_domain_input(target)
    base = clean_url(tgt)
    if not urlparse(base).scheme:
        base = "https://" + base
    session = requests.Session()
    privacy, gdpr, cookie = find_policy_links(session, base, timeout)
    if not privacy:
        return 1
    res_privacy = check_policy(privacy, PRIVACY_KEYWORDS, timeout)
    res_gdpr    = check_policy(gdpr, GDPR_KEYWORDS, timeout)
    res_cookie  = check_policy(cookie, COOKIE_KEYWORDS, timeout)
    table = display_results(res_privacy, res_gdpr, res_cookie)

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, tgt)
        ensure_directory_exists(out)
        from rich.console import Console as _C
        export_console = _C(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out, "privacy_gdpr.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(Fore.RED + "[!] Usage: privacy_gdpr.py <domain_or_url> [json-opts]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = 1
    opts = {}
    if len(sys.argv) > 2:
        try:
            opts = json.loads(sys.argv[2])
        except (TypeError, ValueError):
            pass
    raise SystemExit(run(tgt, thr, opts))
