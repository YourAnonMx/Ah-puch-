#!/usr/bin/env python3
"""Read URL reputation reports through the current VirusTotal API."""

import asyncio
import base64
import sys

import aiohttp
from colorama import Fore, init
from rich.box import ROUNDED
from rich.console import Console
from rich.table import Table

from ahpuch_modules.config.settings import API_KEYS
from ahpuch_modules.utils.util import clean_url, validate_url

init(autoreset=True)
console = Console()
API_ROOT = "https://www.virustotal.com/api/v3"


def banner() -> None:
    console.print(Fore.GREEN + """
    =============================================
           Ah-Puch - VirusTotal Scan Module
    =============================================
    """)


def url_identifier(url: str) -> str:
    """Return the unpadded URL-safe identifier accepted by the URL endpoint."""
    if not isinstance(url, str):
        return ""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


async def fetch_url_report(session: aiohttp.ClientSession, url: str, api_key: str) -> dict:
    endpoint = f"{API_ROOT}/urls/{url_identifier(url)}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        async with session.get(endpoint, headers=headers, timeout=15) as response:
            payload = await response.json(content_type=None)
            if response.status != 200:
                detail = payload.get("error", {}).get("message", "provider request failed") if isinstance(payload, dict) else "provider request failed"
                return {"_status": response.status, "_error": detail}
            return payload if isinstance(payload, dict) else {"_status": response.status, "_error": "invalid JSON response"}
    except asyncio.TimeoutError:
        return {"_status": 504, "_error": "provider timeout"}
    except (aiohttp.ClientError, OSError, TypeError, ValueError) as exc:
        return {"_status": 502, "_error": f"provider request failed: {type(exc).__name__}"}


def display_report(report: dict, url: str) -> bool:
    if report.get("_status"):
        console.print(Fore.RED + f"[!] VirusTotal request failed for {url}: {report.get('_error', 'unknown error')}")
        return False
    data = report.get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    results = attributes.get("last_analysis_results") or {}
    if not isinstance(stats, dict) or not isinstance(results, dict):
        console.print(Fore.YELLOW + f"[!] VirusTotal returned no analysis details for {url}")
        return True

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(value or 0) for value in stats.values() if isinstance(value, (int, float)))
    console.print(Fore.WHITE + f"[*] URL: {url}")
    console.print(Fore.WHITE + f"[*] Malicious: {malicious}; suspicious: {suspicious}; engines: {total}")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Scan Engine", style="cyan", justify="left")
    table.add_column("Category", style="green", justify="left")
    table.add_column("Result", style="yellow", justify="left")
    for engine, result in sorted(results.items()):
        table.add_row(engine, str(result.get("category", "-")), str(result.get("result") or "-"))
    if results:
        console.print(table)
    return True


def generate_stats(reports: list[dict]) -> None:
    successful = [report for report in reports if not report.get("_status")]
    failures = len(reports) - len(successful)
    malicious = 0
    suspicious = 0
    engines = 0
    for report in successful:
        stats = ((report.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        malicious += int(stats.get("malicious", 0) or 0)
        suspicious += int(stats.get("suspicious", 0) or 0)
        engines += sum(int(value or 0) for value in stats.values() if isinstance(value, (int, float)))
    table = Table(title="VirusTotal Scan Statistics", box=ROUNDED)
    table.add_column("Metric", style="cyan", justify="left")
    table.add_column("Value", style="green", justify="left")
    table.add_row("Total URLs", str(len(reports)))
    table.add_row("Successful reports", str(len(successful)))
    table.add_row("Provider failures", str(failures))
    table.add_row("Malicious detections", str(malicious))
    table.add_row("Suspicious detections", str(suspicious))
    table.add_row("Engine results", str(engines))
    console.print(table)


async def run_scans(targets: list[str], api_key: str) -> int:
    if not targets:
        return 1
    targets = [target for target in targets if isinstance(target, str) and target.strip()][:100]
    if not targets:
        return 1
    async with aiohttp.ClientSession() as session:
        reports = await asyncio.gather(*(fetch_url_report(session, url, api_key) for url in targets))
    for url, report in zip(targets, reports):
        display_report(report, url)
    generate_stats(reports)
    return 0 if reports and all(not report.get("_status") for report in reports) else 1


def main(targets: list[str]) -> int:
    if not targets:
        return 1
    banner()
    api_key = API_KEYS.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        console.print(Fore.RED + "[!] VirusTotal API key is not configured.")
        return 1
    cleaned_targets = []
    for target in targets:
        cleaned = clean_url(target)
        if validate_url(cleaned):
            cleaned_targets.append(cleaned)
        else:
            console.print(Fore.RED + f"[!] Invalid URL format: {target}")
    if not cleaned_targets:
        console.print(Fore.RED + "[!] No valid URLs to scan.")
        return 1
    console.print(Fore.WHITE + f"[*] Querying VirusTotal URL reports for {len(cleaned_targets)} URL(s)...")
    return asyncio.run(run_scans(cleaned_targets, api_key))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(Fore.RED + "[!] No target provided. Please pass one or more URLs.")
        raise SystemExit(1)
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        console.print(Fore.RED + "\n[!] Process interrupted by user.")
        raise SystemExit(130)
