import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from ahpuch_modules.utils.util import resolve_to_ip
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, API_KEYS

init(autoreset=True)
console = Console()
MAX_TIMEOUT = 300

def banner():
    console.print("""
    =============================================
         Ah-Puch - IP Reputation Check
    =============================================
    """)

def fetch_abuseipdb(ip, timeout=DEFAULT_TIMEOUT):
    key = API_KEYS.get("ABUSEIPDB_API_KEY")
    if not key:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=timeout
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "score": d.get("abuseConfidenceScore"),
                "reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "usage": d.get("usageType"),
                "source": "AbuseIPDB"
            }
    except (requests.RequestException, OSError, TypeError, ValueError):
        pass
    return None

def fetch_ipqualityscore(ip, timeout=DEFAULT_TIMEOUT):
    key = API_KEYS.get("IPQUALITYSCORE_API_KEY")
    if not key:
        return None
    try:
        r = requests.get(
            f"https://ipqualityscore.com/api/json/ip/{key}/{ip}",
            timeout=timeout
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "score": d.get("fraud_score"),
                "proxy": d.get("proxy"),
                "bot_status": d.get("bot_status"),
                "isp": d.get("ISP"),
                "country": d.get("country_code"),
                "source": "IPQualityScore"
            }
    except (requests.RequestException, OSError, TypeError, ValueError):
        pass
    return None

def fetch_otx(ip, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(f"https://otx.alienvault.com/api/indicators/IPv4/{ip}/general", timeout=timeout)
        if r.status_code == 200:
            pulse_count = r.json().get("pulse_info", {}).get("count")
            return {
                "score": None,
                "reports": pulse_count,
                "source": "AlienVault OTX"
            }
    except (requests.RequestException, OSError, TypeError, ValueError):
        pass
    return None

def display_results(ip, results):
    table = Table(title=f"IP Reputation: {ip}", show_header=True, header_style="bold magenta")
    table.add_column("Source", style="cyan")
    table.add_column("Score", style="green")
    table.add_column("Reports", style="yellow")
    table.add_column("Country", style="white")
    table.add_column("ISP/Usage", style="blue", overflow="fold")
    for r in results:
        table.add_row(
            r.get("source", "N/A"),
            str(r.get("score")) if r.get("score") is not None else "?",
            str(r.get("reports")) if r.get("reports") is not None else "?",
            r.get("country", "N/A"),
            (r.get("isp") or r.get("usage") or "")[:80]
        )
    console.print(table)


def run(target, threads=1, opts=None):
    """Collect configured public reputation observations for one target."""
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    cleaned_target = str(target or "").strip()
    if not cleaned_target:
        console.print("[red][!] No target provided. Please pass a domain or IP.[/red]")
        return 2
    ip = resolve_to_ip(cleaned_target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        return 2
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True)
    with progress:
        abuse_task = progress.add_task("AbuseIPDB", total=1)
        abuse = fetch_abuseipdb(ip, timeout)
        progress.advance(abuse_task)
        ipqs_task = progress.add_task("IPQualityScore", total=1)
        ipqs = fetch_ipqualityscore(ip, timeout)
        progress.advance(ipqs_task)
        otx_task = progress.add_task("AlienVault OTX", total=1)
        otx = fetch_otx(ip, timeout)
        progress.advance(otx_task)
    results = [result for result in (abuse, ipqs, otx) if result]
    if results:
        display_results(ip, results)
    else:
        console.print("[yellow][!] No reputation data available from configured sources[/yellow]")
    console.print("[white][*] IP reputation check completed.[/white]")
    return 0

if __name__ == "__main__":
    banner()
    try:
        options = __import__("json").loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, KeyError):
        options = {}
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else "", 1, options))
