#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from colorama import Fore, Style, init
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input

console = Console()
PARTIAL_EXIT_CODE = 3

DEFAULT_PROVIDERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google": "https://dns.google/resolve",
    "Quad9": "https://dns.quad9.net:5053/dns-query",
    "AdGuard": "https://dns.adguard.com/dns-query",
}
QTYPE_CODES = {"A": 1, "AAAA": 28}


def banner() -> None:
    console.print(f"{Fore.GREEN}{'=' * 44}")
    console.print(f"{Fore.GREEN}        Ah-Puch - DoH Resolver Check")
    console.print(f"{Fore.GREEN}{'=' * 44}{Style.RESET_ALL}\n")


def _validated_providers(raw: Any) -> dict[str, str]:
    if raw in (None, "", {}):
        return dict(DEFAULT_PROVIDERS)
    if not isinstance(raw, dict):
        raise ValueError("providers must be a JSON object of name -> HTTPS URL")
    if not 1 <= len(raw) <= 16:
        raise ValueError("providers must contain between 1 and 16 entries")
    providers: dict[str, str] = {}
    for name, value in raw.items():
        label = str(name or "").strip()[:80]
        url = str(value or "").strip()
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise ValueError(f"invalid provider URL for {label or '<unnamed>'}") from exc
        if not label or parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("every DoH provider requires a name and HTTPS URL")
        providers[label] = url
    return providers


def _clean_answers(payload: dict[str, Any], qtype: str) -> list[str]:
    wanted = QTYPE_CODES[qtype]
    answers: set[str] = set()
    rows = payload.get("Answer", [])
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict) or row.get("type") != wanted:
            continue
        value = str(row.get("data", "")).strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if (qtype == "A" and address.version == 4) or (qtype == "AAAA" and address.version == 6):
            answers.add(str(address))
    return sorted(answers)


def query(name: str, url: str, domain: str, qtype: str, timeout: int) -> dict[str, Any]:
    params = {"name": domain, "type": qtype}
    headers = {"Accept": "application/dns-json"}
    started = time.monotonic()
    try:
        response = requests.get(url, params=params, headers=headers, timeout=timeout, verify=True)
    except requests.RequestException as exc:
        return {
            "provider": name,
            "state": "transport-error",
            "http_status": None,
            "dns_status": None,
            "answers": [],
            "latency_ms": -1,
            "error": type(exc).__name__,
        }

    latency = int((time.monotonic() - started) * 1000)
    if not response.ok:
        return {
            "provider": name,
            "state": "http-error",
            "http_status": response.status_code,
            "dns_status": None,
            "answers": [],
            "latency_ms": latency,
            "error": "",
        }
    try:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("DoH response is not an object")
        dns_status = int(payload.get("Status", 0))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return {
            "provider": name,
            "state": "parse-error",
            "http_status": response.status_code,
            "dns_status": None,
            "answers": [],
            "latency_ms": latency,
            "error": type(exc).__name__,
        }

    return {
        "provider": name,
        "state": "success" if dns_status == 0 else "dns-negative",
        "http_status": response.status_code,
        "dns_status": dns_status,
        "answers": _clean_answers(payload, qtype),
        "latency_ms": latency,
        "error": "",
    }


def _render(domain: str, qtype: str, results: list[dict[str, Any]]) -> tuple[Table, str]:
    table = Table(
        title=f"DoH Resolver Results – {domain}",
        header_style="bold magenta",
        box=box.MINIMAL,
    )
    table.add_column("Provider", style="cyan")
    table.add_column("State", style="white")
    table.add_column("HTTP", style="green", justify="right")
    table.add_column("DNS", style="green", justify="right")
    table.add_column(f"{qtype} Records", style="yellow", overflow="fold")
    table.add_column("Latency(ms)", style="white", justify="right")

    latencies: list[int] = []
    completed = failed = 0
    for row in sorted(results, key=lambda value: str(value["provider"])):
        state = str(row["state"])
        latency = int(row.get("latency_ms", -1))
        if state in {"success", "dns-negative"}:
            completed += 1
            if latency >= 0:
                latencies.append(latency)
        else:
            failed += 1
        table.add_row(
            str(row["provider"]),
            state,
            str(row.get("http_status") if row.get("http_status") is not None else "ERR"),
            str(row.get("dns_status") if row.get("dns_status") is not None else "-"),
            ",".join(str(value) for value in row.get("answers", [])) or "-",
            str(latency),
        )

    average = f"{sum(latencies) / len(latencies):.2f}" if latencies else "-"
    fastest = str(min(latencies)) if latencies else "-"
    slowest = str(max(latencies)) if latencies else "-"
    summary = (
        f"Providers: {len(results)}  Completed: {completed}  Failure: {failed}  "
        f"Avg: {average}ms  Fastest: {fastest}ms  Slowest: {slowest}ms"
    )
    return table, summary


def _export(domain: str, results: list[dict[str, Any]], table: Table, summary: str) -> None:
    destination = Path(RESULTS_DIR) / domain
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    json_path = destination / "dns_doh.json"
    json_path.write_text(json.dumps(results, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass

    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        text_path = destination / "dns_doh.txt"
        text_path.write_text(export_console.export_text(), encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    init(autoreset=True)
    banner()
    started = time.monotonic()
    domain = clean_domain_input(target).strip().lower().rstrip(".")
    if not domain:
        console.print("[red]A domain target is required[/red]")
        return 2
    try:
        timeout = max(1, int(opts.get("timeout", DEFAULT_TIMEOUT)))
        qtype = str(opts.get("qtype", "A")).strip().upper()
        if qtype not in QTYPE_CODES:
            raise ValueError("qtype must be A or AAAA")
        providers = _validated_providers(opts.get("providers"))
        workers = max(1, min(int(threads), len(providers), 32))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid module options: {exc}[/red]")
        return 2

    results: list[dict[str, Any]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[provider]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying DoH", total=len(providers), provider="")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(query, name, url, domain, qtype, timeout): name
                for name, url in providers.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    row = future.result()
                except Exception as exc:  # defensive isolation between providers
                    row = {
                        "provider": name,
                        "state": "internal-error",
                        "http_status": None,
                        "dns_status": None,
                        "answers": [],
                        "latency_ms": -1,
                        "error": type(exc).__name__,
                    }
                results.append(row)
                progress.update(task, advance=1, provider=name)

    table, summary = _render(domain, qtype, results)
    console.print(table)
    elapsed = time.monotonic() - started
    summary_with_elapsed = summary + f"  Elapsed: {elapsed:.2f}s"
    console.print(Panel(summary_with_elapsed, title="Summary", style="bold white"))

    completed = [row for row in results if row.get("state") in {"success", "dns-negative"}]
    failures = [row for row in results if row.get("state") not in {"success", "dns-negative"}]
    if not completed:
        console.print("[red]No DoH provider completed successfully[/red]\n")
        return 2

    _export(domain, results, table, summary_with_elapsed)
    if failures:
        console.print("[yellow]DoH resolver check completed with provider errors[/yellow]\n")
        return PARTIAL_EXIT_CODE
    console.print("[green][*] DoH resolver check completed[/green]\n")
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    try:
        parsed = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid options JSON: {exc}[/red]")
        raise SystemExit(2)
    if not isinstance(parsed, dict):
        console.print("[red]Options JSON must be an object[/red]")
        raise SystemExit(2)
    raise SystemExit(run(target, threads, parsed))
