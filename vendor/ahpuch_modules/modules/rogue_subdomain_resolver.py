#!/usr/bin/env python3
import os
import sys
import random
import string
import warnings
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

try:
    import idna
except ImportError:
    idna = None

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

DEFAULT_WORDS = [
    "www","mail","smtp","pop","imap","ftp","admin","portal","cpanel","dev","test","stage",
    "staging","beta","api","app","cdn","static","assets","files","img","image","images","media",
    "m","blog","help","support","status","docs","doc","jira","git","gitlab","code","ci","build",
    "sso","auth","login","store","shop","secure","vpn"
]

TAKEOVER_PATTERNS = {
    "AWS_S3":           "NoSuchBucket",
    "Azure_Frontdoor":  "The resource you are looking for has been removed",
    "GitHub_Pages":     "There isn't a GitHub Pages site here",
    "Heroku":           "no such app",
    "Unbounce":         "The requested URL was not found on this server",
    "Fastly":           "Fastly error: unknown domain",
    "Cloudfront":       "ERROR: The request could not be satisfied",
    "DigitalOcean_Spaces":"NoSuchKey",
    "Shopify":          "Sorry, this shop is currently unavailable",
    "Pantheon":         "The gods are wise. Unknown site"
}

def banner():
    console.print("""
    =============================================
      Ah-Puch - Rogue Subdomain Resolver
    =============================================
    """)

def rand_label(n=12):
    return "".join(random.choices(string.ascii_lowercase+string.digits, k=n))

def wildcard_detect(domain):
    if not domain or not str(domain).strip():
        return False, "-"
    label = rand_label()
    test = f"{label}.{domain}"
    try:
        ans = requests.get(f"https://{test}", timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        if ans.ok:
            return True, test
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        pass
    return False, "-"

def resolve_record(name, rtype):
    import dns.resolver
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=DEFAULT_TIMEOUT)
        return [str(rdata) for rdata in answers]
    except (dns.exception.DNSException, OSError, TypeError, ValueError):
        return []

def http_fingerprint(host):
    if not host or not str(host).strip():
        return "ERR", "-"
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
            snippet = r.text[:400].lower()
            for label, sig in TAKEOVER_PATTERNS.items():
                if sig.lower() in snippet:
                    return str(r.status_code), label
            return str(r.status_code), "-"
        except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
            continue
    return "ERR", "-"

def build_candidates(domain, wordlist):
    if not domain or not str(domain).strip():
        return []
    wordlist = wordlist if wordlist is not None else DEFAULT_WORDS
    return [f"{w.strip()}.{domain}" for w in wordlist][:5000]

def classify_dns(a, cname):
    if a and not cname: return "A"
    if cname and not a: return "CNAME"
    if a and cname: return "A+CNAME"
    return "NX"

def check_host(host):
    if not host or not str(host).strip():
        return host, "NX", "-", "-", "", "", "N"
    a = resolve_record(host, "A")
    cname = resolve_record(host, "CNAME")
    dns_cat = classify_dns(a, cname)
    ip = ",".join(a[:3]) if a else "-"
    cn = cname[0] if cname else "-"
    status, fp = ("", "")
    if dns_cat != "NX":
        status, fp = http_fingerprint(host)
    takeover = "Y" if fp and fp != "-" else "N"
    return host, dns_cat, ip, cn, status, fp, takeover

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    if not domain:
        sys.exit(2)
    wordlist = DEFAULT_WORDS
    if len(sys.argv) > 2 and os.path.isfile(sys.argv[2]):
        with open(sys.argv[2], encoding="utf-8", errors="ignore") as f:
            wordlist = [l.strip() for l in f if l.strip()]

    wildcard, ip_wild = wildcard_detect(domain)
    console.print(f"[white][*] Wildcard DNS: {'Yes' if wildcard else 'No'} ({ip_wild})[/white]")

    candidates = build_candidates(domain, wordlist)
    results = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Resolving subdomains", total=len(candidates))
        with ThreadPoolExecutor(max_workers=100) as pool:
            futures = {pool.submit(check_host, sub): sub for sub in candidates}
            for fut in as_completed(futures):
                results.append(fut.result())
                progress.advance(task)

    table = Table(title=f"Rogue Subdomain Resolver: {domain}", header_style="bold magenta")
    for col, style in [
        ("Subdomain", "cyan"), ("DNS", "green"), ("IP", "yellow"),
        ("CNAME", "white"), ("HTTP", "blue"), ("Fingerprint", "magenta"),
        ("Takeover", "red")
    ]:
        table.add_column(col, style=style, overflow="fold")

    for row in results:
        table.add_row(*[str(x) for x in row])

    if results:
        console.print(table)
    else:
        console.print("[yellow][!] No subdomains resolved.[/yellow]")

    console.print("[white][*] Rogue subdomain resolution completed.[/white]")
