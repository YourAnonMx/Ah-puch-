#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input

console = Console()
DEFAULT_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
SUPPORTED_TYPES = frozenset(DEFAULT_TYPES)
PARTIAL_EXIT_CODE = 3


def banner() -> None:
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]         Ah-Puch - DNS Records Check")
    console.print(f"[cyan]{bar}\n")


def _selected_types(raw: Any) -> list[str]:
    if raw in (None, "", []):
        return list(DEFAULT_TYPES)
    if isinstance(raw, str):
        values = [value.strip().upper() for value in raw.split(",") if value.strip()]
    elif isinstance(raw, (list, tuple, set)):
        values = [str(value).strip().upper() for value in raw if str(value).strip()]
    else:
        raise ValueError("types must be a comma-separated string or list")
    values = list(dict.fromkeys(values))
    unsupported = [value for value in values if value not in SUPPORTED_TYPES]
    if unsupported:
        raise ValueError("unsupported DNS record type(s): " + ",".join(unsupported))
    return values or list(DEFAULT_TYPES)


def get_records(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> dict[str, Any]:
    try:
        answers = resolver.resolve(domain, record_type)
        values = sorted({str(record.to_text()).strip() for record in answers if str(record.to_text()).strip()})
        return {"type": record_type, "state": "success", "values": values, "error": ""}
    except dns.resolver.NXDOMAIN:
        return {"type": record_type, "state": "nxdomain", "values": [], "error": ""}
    except dns.resolver.NoAnswer:
        return {"type": record_type, "state": "no-answer", "values": [], "error": ""}
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
        return {"type": record_type, "state": "timeout", "values": [], "error": type(exc).__name__}
    except dns.resolver.NoNameservers as exc:
        return {"type": record_type, "state": "resolver-error", "values": [], "error": type(exc).__name__}
    except (dns.exception.DNSException, ValueError, TypeError) as exc:
        return {"type": record_type, "state": "resolver-error", "values": [], "error": type(exc).__name__}


def _render(domain: str, results: list[dict[str, Any]]) -> tuple[Table, str]:
    table = Table(title=f"DNS Records – {domain}", header_style="bold magenta", box=box.MINIMAL)
    table.add_column("Type", style="cyan")
    table.add_column("State", style="white")
    table.add_column("Value(s)", style="green", overflow="fold")

    total_values = 0
    completed = failed = 0
    for row in sorted(results, key=lambda value: str(value["type"])):
        state = str(row["state"])
        values = [str(value) for value in row.get("values", [])]
        total_values += len(values)
        if state in {"success", "no-answer", "nxdomain"}:
            completed += 1
        else:
            failed += 1
        table.add_row(str(row["type"]), state, "; ".join(values) or "-")

    summary = (
        f"Types queried: {len(results)}  Completed: {completed}  "
        f"Failure: {failed}  Total records: {total_values}"
    )
    return table, summary


def _export(domain: str, results: list[dict[str, Any]], table: Table, summary: str) -> None:
    destination = Path(RESULTS_DIR) / domain
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    json_path = destination / "dns_records.json"
    json_path.write_text(json.dumps(results, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass

    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        text_path = destination / "dns_records.txt"
        text_path.write_text(export_console.export_text(), encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    banner()
    started = time.monotonic()
    domain = clean_domain_input(target).strip().lower().rstrip(".")
    if not domain:
        console.print("[red]A domain target is required[/red]")
        return 2

    try:
        timeout = max(1, int(opts.get("timeout", DEFAULT_TIMEOUT)))
        record_types = _selected_types(opts.get("types"))
        workers = max(1, min(int(threads), len(record_types), 32))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid module options: {exc}[/red]")
        return 2

    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = min(float(timeout), 5.0)

    results: list[dict[str, Any]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[rtype]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying records…", total=len(record_types), rtype="")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(get_records, resolver, domain, record_type): record_type
                for record_type in record_types
            }
            for future in as_completed(futures):
                record_type = futures[future]
                try:
                    row = future.result()
                except Exception as exc:  # isolate an unexpected worker failure
                    row = {
                        "type": record_type,
                        "state": "internal-error",
                        "values": [],
                        "error": type(exc).__name__,
                    }
                results.append(row)
                progress.update(task, advance=1, rtype=record_type)

    table, summary = _render(domain, results)
    elapsed = time.monotonic() - started
    summary_with_elapsed = summary + f"  Elapsed: {elapsed:.2f}s"
    console.print(table)
    console.print(Panel(summary_with_elapsed, title="Summary", style="bold white"))

    completed = [row for row in results if row.get("state") in {"success", "no-answer", "nxdomain"}]
    failures = [row for row in results if row.get("state") not in {"success", "no-answer", "nxdomain"}]
    if not completed:
        console.print("[red]No DNS record query completed successfully[/red]\n")
        return 2

    _export(domain, results, table, summary_with_elapsed)
    if failures:
        console.print("[yellow]DNS records check completed with resolver errors[/yellow]\n")
        return PARTIAL_EXIT_CODE
    console.print("[green][*] DNS records check completed[/green]\n")
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
