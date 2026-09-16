#!/usr/bin/env python3
from __future__ import annotations

import datetime
import json
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input

console = Console()
TEAL = "#2EC4B6"
CORE_TYPES = ("DNSKEY", "DS", "RRSIG")
CLEAN_STATES = {"success", "no-answer", "nxdomain"}


def _width() -> int:
    columns = shutil.get_terminal_size().columns
    return columns if columns > 0 else console.width


def banner() -> None:
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – DNSSEC Checker")
    console.print(f"[{TEAL}]{bar}\n")


def make_table(title: str) -> Table:
    table = Table(
        title=title,
        title_style="bold magenta",
        show_header=True,
        header_style="bold white",
        box=box.HEAVY,
        expand=True,
        width=_width(),
        pad_edge=True,
        show_lines=False,
        row_styles=["none", "dim"],
    )
    table.add_column("Zone", justify="left", style="cyan", ratio=4, no_wrap=False)
    table.add_column("DNSKEY", justify="center", style="green", ratio=2, no_wrap=True)
    table.add_column("DS", justify="center", style="yellow", ratio=2, no_wrap=True)
    table.add_column("RRSIG", justify="center", style="blue", ratio=2, no_wrap=True)
    table.add_column("Status", justify="center", style="bold", ratio=4, no_wrap=False)
    return table


def full_panel(text: str, title: str) -> None:
    console.print(Panel(text, title=title, border_style="white", box=box.HEAVY, expand=True, width=_width()))


def style_status(text: str) -> str:
    styles = {
        "Fully signed": "bold green",
        "Signed (no DS)": "yellow",
        "Delegation signed only": "yellow",
        "Has keys only": "cyan",
        "Not signed": "bold red",
        "NXDOMAIN": "dim",
        "Indeterminate": "bold red",
    }
    style = styles.get(text, "white")
    return f"[{style}]{text}[/{style}]"


def _resolver(timeout: int) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = min(float(timeout), 5.0)
    return resolver


def resolve_records(zone: str, record_type: str, timeout: int) -> dict[str, Any]:
    try:
        records = list(_resolver(timeout).resolve(zone, record_type))
        return {"state": "success", "records": records, "error": ""}
    except dns.resolver.NXDOMAIN:
        return {"state": "nxdomain", "records": [], "error": ""}
    except dns.resolver.NoAnswer:
        return {"state": "no-answer", "records": [], "error": ""}
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
        return {"state": "timeout", "records": [], "error": type(exc).__name__}
    except dns.resolver.NoNameservers as exc:
        return {"state": "resolver-error", "records": [], "error": type(exc).__name__}
    except (dns.exception.DNSException, ValueError, TypeError) as exc:
        return {"state": "resolver-error", "records": [], "error": type(exc).__name__}


def parent_zone(name: str) -> str:
    parts = name.split(".", 1)
    return parts[1] if len(parts) == 2 else ""


def algo_name(num: int) -> str:
    mapping = {
        1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1",
        8: "RSASHA256", 10: "RSASHA512", 12: "ECC-GOST", 13: "ECDSAP256SHA256",
        14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448",
    }
    return mapping.get(int(num), str(num))


def ds_digest_name(num: int) -> str:
    return {1: "SHA-1", 2: "SHA-256", 3: "GOST", 4: "SHA-384"}.get(int(num), str(num))


def human_time(ts: int) -> str:
    try:
        value = datetime.datetime.strptime(str(ts), "%Y%m%d%H%M%S")
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(ts)


def sig_window_days(now: datetime.datetime, inception: int, expiration: int) -> tuple[float | None, float | None]:
    try:
        inc = datetime.datetime.strptime(str(inception), "%Y%m%d%H%M%S")
        exp = datetime.datetime.strptime(str(expiration), "%Y%m%d%H%M%S")
    except (TypeError, ValueError):
        return None, None
    until = (exp - now).total_seconds() / 86400.0
    age = (now - inc).total_seconds() / 86400.0
    return round(max(until, 0.0), 2), round(max(age, 0.0), 2)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    raise ValueError("check_subdomains must be boolean-like")


def _status_for(core: dict[str, dict[str, Any]]) -> str:
    states = {record_type: str(core[record_type]["state"]) for record_type in CORE_TYPES}
    if any(state not in CLEAN_STATES for state in states.values()):
        return "Indeterminate"
    if all(state == "nxdomain" for state in states.values()):
        return "NXDOMAIN"
    counts = {record_type: len(core[record_type]["records"]) for record_type in CORE_TYPES}
    dnskey, ds, rrsig = counts["DNSKEY"], counts["DS"], counts["RRSIG"]
    if dnskey and ds and rrsig:
        return "Fully signed"
    if dnskey and rrsig and not ds:
        return "Signed (no DS)"
    if ds and rrsig and not dnskey:
        return "Delegation signed only"
    if dnskey and not (ds or rrsig):
        return "Has keys only"
    return "Not signed"


def _record_details(zone: str, core: dict[str, dict[str, Any]], timeout: int, now: datetime.datetime) -> dict[str, Any]:
    details: dict[str, Any] = {
        "zone": zone,
        "status": _status_for(core),
        "query_states": {record_type: core[record_type]["state"] for record_type in CORE_TYPES},
        "dnskey": [],
        "ds": [],
        "rrsig": [],
        "denial": {},
    }
    for record in core["DNSKEY"]["records"]:
        try:
            details["dnskey"].append({
                "flags": int(record.flags),
                "sep": bool(int(record.flags) & 0x0100),
                "alg_num": int(record.algorithm),
                "algorithm": algo_name(int(record.algorithm)),
                "protocol": int(record.protocol),
            })
        except (AttributeError, TypeError, ValueError):
            continue
    for record in core["DS"]["records"]:
        try:
            details["ds"].append({
                "key_tag": int(record.key_tag),
                "alg_num": int(record.algorithm),
                "algorithm": algo_name(int(record.algorithm)),
                "digest_type_num": int(record.digest_type),
                "digest_type": ds_digest_name(int(record.digest_type)),
            })
        except (AttributeError, TypeError, ValueError):
            continue
    for record in core["RRSIG"]["records"]:
        try:
            if record.type_covered != dns.rdatatype.DNSKEY:
                continue
            until, age = sig_window_days(now, int(record.inception), int(record.expiration))
            details["rrsig"].append({
                "type_covered": "DNSKEY",
                "alg_num": int(record.algorithm),
                "algorithm": algo_name(int(record.algorithm)),
                "key_tag": int(record.key_tag),
                "inception": human_time(int(record.inception)),
                "expiration": human_time(int(record.expiration)),
                "age_days": age,
                "expires_in_days": until,
            })
        except (AttributeError, TypeError, ValueError):
            continue

    for record_type in ("NSEC", "NSEC3"):
        result = resolve_records(zone, record_type, timeout)
        details["denial"][record_type.lower()] = {
            "state": result["state"],
            "present": bool(result["records"]) if result["state"] == "success" else False,
        }
    return details


def _export(domain: str, payload: dict[str, Any], table: Table, summary: str) -> None:
    destination = Path(RESULTS_DIR) / domain
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    json_path = destination / "dnssec.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass

    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=_width())
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", border_style="white", box=box.HEAVY, expand=True, width=_width()))
        text_path = destination / "dnssec.txt"
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
        check_subdomains = _as_bool(opts.get("check_subdomains", False))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid module options: {exc}[/red]")
        return 2

    zones = [domain] + ([f"www.{domain}"] if check_subdomains else [])
    total_tasks = len(zones) * len(CORE_TYPES)
    workers = max(1, min(int(threads), total_tasks, 32))
    core: dict[str, dict[str, dict[str, Any]]] = {
        zone: {record_type: {} for record_type in CORE_TYPES} for zone in zones
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]Checking: {task.fields[cur_zone]}[/white]", justify="right"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("DNSSEC lookups…", total=total_tasks, cur_zone=zones[0])
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(resolve_records, zone, record_type, timeout): (zone, record_type)
                for zone in zones for record_type in CORE_TYPES
            }
            for future in as_completed(futures):
                zone, record_type = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # defensive isolation between DNS queries
                    result = {"state": "internal-error", "records": [], "error": type(exc).__name__}
                core[zone][record_type] = result
                progress.update(task, advance=1, cur_zone=zone)

    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    details = {zone: _record_details(zone, core[zone], timeout, now) for zone in zones}
    table = make_table(f"DNSSEC Check – {domain}")
    status_counter: dict[str, int] = {}
    for zone in zones:
        status = details[zone]["status"]
        status_counter[status] = status_counter.get(status, 0) + 1
        table.add_row(
            zone,
            str(len(core[zone]["DNSKEY"]["records"])),
            str(len(core[zone]["DS"]["records"])),
            str(len(core[zone]["RRSIG"]["records"])),
            style_status(status),
        )
    console.print(table)

    parent = parent_zone(domain)
    apex_ds = core[domain]["DS"]
    if apex_ds["state"] not in CLEAN_STATES:
        parent_note = "unknown"
    else:
        parent_note = "present" if apex_ds["records"] else "missing"
    full_panel(f"[bold]Parent DS[/bold]: {parent_note}   [bold]Parent[/bold]: {parent or '—'}", "Delegation")

    elapsed = time.monotonic() - started
    parts = [f"[bold]{status}[/bold]: {count}" for status, count in sorted(status_counter.items())]
    parts.append(f"[bold]Parent DS[/bold]: {parent_note}")
    parts.append(f"[bold]Elapsed[/bold]: {elapsed:.2f}s")
    summary = "   ".join(parts)
    full_panel(summary, "Summary")

    payload = {
        "domain": domain,
        "parent": parent or None,
        "parent_ds_state": apex_ds["state"],
        "parent_ds_present": bool(apex_ds["records"]) if apex_ds["state"] in CLEAN_STATES else None,
        "summary": status_counter,
        "zones": details,
        "elapsed_sec": round(elapsed, 3),
    }
    _export(domain, payload, table, summary)

    apex_completed = all(core[domain][record_type]["state"] in CLEAN_STATES for record_type in CORE_TYPES)
    if not apex_completed:
        console.print("[red]DNSSEC status is indeterminate because core DNS queries failed[/red]\n")
        return 2
    console.print("[green][*] DNSSEC check completed[/green]\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
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
