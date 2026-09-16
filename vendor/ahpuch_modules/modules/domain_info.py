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
import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input

console = Console()
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")
DNS_COMPLETED_STATES = {"success", "no-answer", "nxdomain"}
SECONDARY_COMPLETED_STATES = {"success", "provider-negative", "not-found"}
PARTIAL_EXIT_CODE = 3


def banner() -> None:
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]        Ah-Puch – Domain Information")
    console.print(f"[cyan]{bar}\n")


def _resolver(timeout: int) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = min(float(timeout), 5.0)
    return resolver


def _dns_query(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> dict[str, Any]:
    try:
        answers = resolver.resolve(domain, record_type)
        values = sorted({str(answer.to_text()).strip('"').strip() for answer in answers if str(answer.to_text()).strip()})
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


def fetch_dns_records(domain: str, timeout: int) -> dict[str, dict[str, Any]]:
    resolver = _resolver(timeout)
    return {record_type: _dns_query(resolver, domain, record_type) for record_type in DNS_TYPES}


def fetch_ip_info(ip: str, timeout: int) -> dict[str, Any]:
    url = f"https://ip-api.com/json/{ip}?fields=status,country,org,as,lat,lon"
    try:
        response = requests.get(url, timeout=timeout, verify=True)
    except requests.RequestException as exc:
        return {"ip": ip, "state": "transport-error", "country": "", "org": "", "asn": "", "lat": None, "lon": None, "error": type(exc).__name__}
    if not response.ok:
        return {"ip": ip, "state": "http-error", "country": "", "org": "", "asn": "", "lat": None, "lon": None, "error": str(response.status_code)}
    try:
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("GeoIP response is not an object")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"ip": ip, "state": "parse-error", "country": "", "org": "", "asn": "", "lat": None, "lon": None, "error": type(exc).__name__}
    if data.get("status") != "success":
        return {"ip": ip, "state": "provider-negative", "country": "", "org": "", "asn": "", "lat": None, "lon": None, "error": ""}
    return {
        "ip": ip,
        "state": "success",
        "country": str(data.get("country", "") or ""),
        "org": str(data.get("org", "") or ""),
        "asn": str(data.get("as", "") or ""),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "error": "",
    }


def fetch_rdap(domain: str, timeout: int) -> dict[str, Any]:
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout, verify=True)
    except requests.RequestException as exc:
        return {"state": "transport-error", "http_status": None, "data": {}, "error": type(exc).__name__}
    if response.status_code == 404:
        return {"state": "not-found", "http_status": 404, "data": {}, "error": ""}
    if not response.ok:
        return {"state": "http-error", "http_status": response.status_code, "data": {}, "error": ""}
    try:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("RDAP response is not an object")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"state": "parse-error", "http_status": response.status_code, "data": {}, "error": type(exc).__name__}
    return {"state": "success", "http_status": response.status_code, "data": payload, "error": ""}


def parse_rdap_network(data: dict[str, Any]) -> list[tuple[str, str]]:
    network = data.get("network", {})
    if not isinstance(network, dict):
        network = {}
    return [
        ("Handle", str(network.get("handle", "-") or "-")),
        ("Name", str(network.get("name", "-") or "-")),
        ("Type", str(network.get("type", "-") or "-")),
        ("Country", str(network.get("country", "-") or "-")),
        ("Start", str(network.get("startAddress", "-") or "-")),
        ("End", str(network.get("endAddress", "-") or "-")),
    ]


def parse_rdap_entities(data: dict[str, Any]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    entities = data.get("entities", [])
    if not isinstance(entities, list):
        return rows
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles_raw = entity.get("roles", [])
        roles = ",".join(str(value) for value in roles_raw) if isinstance(roles_raw, list) else "-"
        roles = roles or "-"
        vcard_array = entity.get("vcardArray", [[], []])
        vcard = vcard_array[1] if isinstance(vcard_array, list) and len(vcard_array) > 1 and isinstance(vcard_array[1], list) else []
        name = next((str(item[3]) for item in vcard if isinstance(item, list) and len(item) > 3 and item[0] == "fn"), "-")
        emails = [str(item[3]) for item in vcard if isinstance(item, list) and len(item) > 3 and item[0] == "email"]
        rows.append((roles, name, ",".join(emails) or "-"))
    return rows


def parse_rdap_events(data: dict[str, Any]) -> list[tuple[str, str]]:
    events = data.get("events", [])
    if not isinstance(events, list):
        return []
    return [
        (str(event.get("eventAction", "-") or "-"), str(event.get("eventDate", "-") or "-"))
        for event in events if isinstance(event, dict)
    ]


def _dns_values(records: dict[str, dict[str, Any]], record_type: str) -> list[str]:
    row = records.get(record_type, {})
    values = row.get("values", []) if isinstance(row, dict) else []
    return [str(value) for value in values] if isinstance(values, list) else []


def _render(domain: str, dns_records: dict[str, dict[str, Any]], ip_info: list[dict[str, Any]], rdap: dict[str, Any]) -> tuple[list[Any], str]:
    rdap_data = rdap.get("data", {}) if isinstance(rdap.get("data"), dict) else {}
    whois_table = Table(title="WHOIS & DNS Records", header_style="bold magenta", box=box.MINIMAL)
    whois_table.add_column("Key", style="cyan")
    whois_table.add_column("State", style="white")
    whois_table.add_column("Value", style="green", overflow="fold")
    for key, value in parse_rdap_network(rdap_data):
        whois_table.add_row(key, str(rdap.get("state", "unknown")), value)
    for record_type in DNS_TYPES:
        row = dns_records[record_type]
        whois_table.add_row(record_type, str(row["state"]), ",".join(_dns_values(dns_records, record_type)) or "-")

    tables: list[Any] = [whois_table]
    if ip_info:
        ip_table = Table(title="IP Geolocation", header_style="bold magenta", box=box.MINIMAL)
        for column in ("IP", "State", "Country", "Org", "ASN", "Lat", "Lon"):
            ip_table.add_column(column, justify="center")
        for row in sorted(ip_info, key=lambda value: str(value["ip"])):
            ip_table.add_row(
                str(row["ip"]), str(row["state"]), str(row.get("country") or "-"), str(row.get("org") or "-"),
                str(row.get("asn") or "-"), str(row.get("lat") if row.get("lat") is not None else "-"),
                str(row.get("lon") if row.get("lon") is not None else "-"),
            )
        tables.append(ip_table)

    entities = parse_rdap_entities(rdap_data)
    if entities:
        entity_table = Table(title="RDAP Entities", header_style="bold magenta", box=box.MINIMAL)
        entity_table.add_column("Roles", style="cyan")
        entity_table.add_column("Name", style="green")
        entity_table.add_column("Email", style="yellow", overflow="fold")
        for row in entities:
            entity_table.add_row(*row)
        tables.append(entity_table)

    events = parse_rdap_events(rdap_data)
    if events:
        event_table = Table(title="RDAP Events", header_style="bold magenta", box=box.MINIMAL)
        event_table.add_column("Action", style="cyan")
        event_table.add_column("Date", style="green")
        for row in events:
            event_table.add_row(*row)
        tables.append(event_table)

    dns_completed = sum(row.get("state") in DNS_COMPLETED_STATES for row in dns_records.values())
    geo_success = sum(row.get("state") == "success" for row in ip_info)
    summary = (
        f"A records: {len(_dns_values(dns_records, 'A'))}  AAAA: {len(_dns_values(dns_records, 'AAAA'))}  "
        f"DNS completed: {dns_completed}/{len(DNS_TYPES)}  GeoIP success: {geo_success}/{len(ip_info)}  "
        f"RDAP: {rdap.get('state', 'unknown')}  Entities: {len(entities)}  Events: {len(events)}"
    )
    return tables, summary


def _export(domain: str, payload: dict[str, Any], tables: list[Any], summary: str) -> None:
    destination = Path(RESULTS_DIR) / domain
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    json_path = destination / "domain_info.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass

    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=console.width)
        for table in tables:
            export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        text_path = destination / "domain_info.txt"
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
        workers = max(1, min(int(threads), 32))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid module options: {exc}[/red]")
        return 2

    console.print(f"[white] [*] Gathering info for [cyan]{domain}[/cyan]\n")
    dns_records = fetch_dns_records(domain, timeout)
    ips = sorted(set(_dns_values(dns_records, "A") + _dns_values(dns_records, "AAAA")))

    ip_info: list[dict[str, Any]] = []
    if ips:
        with Progress(
            SpinnerColumn(), TextColumn("[white]GeoIP: {task.completed}/{task.total}"), BarColumn(),
            console=console, transient=True,
        ) as progress:
            task = progress.add_task("Resolving IP info", total=len(ips))
            with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as pool:
                futures = {pool.submit(fetch_ip_info, ip, timeout): ip for ip in ips}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        row = future.result()
                    except Exception as exc:  # isolate secondary provider failure
                        row = {"ip": ip, "state": "internal-error", "country": "", "org": "", "asn": "", "lat": None, "lon": None, "error": type(exc).__name__}
                    ip_info.append(row)
                    progress.advance(task)

    rdap = fetch_rdap(domain, timeout)
    tables, summary = _render(domain, dns_records, ip_info, rdap)
    elapsed = time.monotonic() - started
    summary_with_elapsed = summary + f"  Elapsed: {elapsed:.2f}s"
    for table in tables:
        console.print(table)
    console.print(Panel(summary_with_elapsed, title="Summary", style="bold white"))

    payload = {
        "domain": domain,
        "dns": dns_records,
        "ip_info": sorted(ip_info, key=lambda value: str(value["ip"])),
        "rdap": rdap,
        "elapsed_sec": round(elapsed, 3),
    }
    _export(domain, payload, tables, summary_with_elapsed)

    dns_completed = any(row.get("state") in DNS_COMPLETED_STATES for row in dns_records.values())
    rdap_completed = rdap.get("state") in {"success", "not-found"}
    if not dns_completed and not rdap_completed:
        console.print("[red]Domain information gathering failed before any primary source completed[/red]\n")
        return 2

    dns_failed = any(row.get("state") not in DNS_COMPLETED_STATES for row in dns_records.values())
    ip_failed = any(row.get("state") not in SECONDARY_COMPLETED_STATES for row in ip_info)
    rdap_failed = rdap.get("state") not in {"success", "not-found"}
    if dns_failed or ip_failed or rdap_failed:
        console.print("[yellow]Domain information gathered with source errors[/yellow]\n")
        return PARTIAL_EXIT_CODE

    console.print("[green][*] Domain information gathered[/green]\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No domain provided.[/red]")
        raise SystemExit(2)
    target = sys.argv[1]
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
