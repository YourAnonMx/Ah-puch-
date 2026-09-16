#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from tabulate import tabulate

from ahpuch_modules.config.settings import API_KEYS, DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input, resolve_to_ip

console = Console()
TEAL = "#2EC4B6"
SOURCE_NAMES = ("shodan", "crtsh", "passive_dns")
PARTIAL_EXIT_CODE = 3


def banner() -> None:
    border = "=" * 44
    console.print(f"[{TEAL}]{border}")
    console.print(f"[{TEAL}] Ah-Puch – Associated Hosts")
    console.print(f"[{TEAL}]{border}")


def _clean_hosts(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    result: set[str] = set()
    for value in values:
        host = str(value or "").strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        if not host or any(character.isspace() for character in host):
            continue
        result.add(host)
    return sorted(result)


def _shodan(ip: str, timeout: int) -> tuple[list[str], str]:
    key = API_KEYS.get("SHODAN_API_KEY")
    if not key:
        return [], "skipped:no-api-key"
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={key}",
            timeout=timeout,
            verify=True,
        )
        if response.status_code != 200:
            return [], f"http-error:{response.status_code}"
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Shodan response is not an object")
        return _clean_hosts(payload.get("hostnames", [])), "success"
    except (requests.RequestException, ValueError, TypeError) as exc:
        return [], f"error:{type(exc).__name__}"


def _crtsh(ip: str, timeout: int) -> tuple[list[str], str]:
    try:
        response = requests.get(f"https://crt.sh/?q={ip}&output=json", timeout=timeout, verify=True)
        if response.status_code != 200:
            return [], f"http-error:{response.status_code}"
        payload = response.json()
        if not isinstance(payload, list):
            raise ValueError("crt.sh response is not a list")
        values: list[str] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            common_name = row.get("common_name")
            if common_name:
                values.append(str(common_name))
            name_value = row.get("name_value")
            if name_value:
                values.extend(str(name_value).splitlines())
        return _clean_hosts(values), "success"
    except (requests.RequestException, ValueError, TypeError) as exc:
        return [], f"error:{type(exc).__name__}"


def _passive_dns(ip: str, timeout: int) -> tuple[list[str], str]:
    try:
        response = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=timeout,
            verify=True,
        )
        if response.status_code != 200:
            return [], f"http-error:{response.status_code}"
        text = response.text
        if "error" in text.lower():
            return [], "error:provider-response"
        return _clean_hosts(text.splitlines()), "success"
    except requests.RequestException as exc:
        return [], f"error:{type(exc).__name__}"


def _selected_sources(raw: Any) -> list[str]:
    if raw in (None, "", []):
        return list(SOURCE_NAMES)
    if isinstance(raw, str):
        values = [value.strip().lower() for value in raw.split(",") if value.strip()]
    elif isinstance(raw, (list, tuple, set)):
        values = [str(value).strip().lower() for value in raw if str(value).strip()]
    else:
        raise ValueError("sources must be a comma-separated string or list")
    values = list(dict.fromkeys(values))
    unknown = [value for value in values if value not in SOURCE_NAMES]
    if unknown:
        raise ValueError("unknown associated-host source(s): " + ",".join(unknown))
    if not values:
        return list(SOURCE_NAMES)
    return values


def collect(ip: str, timeout: int, sources: list[str]) -> tuple[list[str], dict[str, str]]:
    hosts: set[str] = set()
    states: dict[str, str] = {}
    with Progress(SpinnerColumn(), TextColumn("[cyan]Enumerating[/cyan]"), console=console, transient=True) as progress:
        task = progress.add_task("", total=len(sources))
        for source in sources:
            handler = {"shodan": _shodan, "crtsh": _crtsh, "passive_dns": _passive_dns}[source]
            values, state = handler(ip, timeout)
            states[source] = state
            hosts.update(values)
            progress.advance(task)
    return sorted(hosts), states


def render(hosts: list[str]) -> str:
    return tabulate([[host] for host in hosts], ["Associated Host"], tablefmt="grid")


def export(domain: str, hosts: list[str], rendered: str, states: dict[str, str] | None = None) -> None:
    destination = Path(RESULTS_DIR) / domain
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    json_path = destination / "associated_hosts.json"
    json_path.write_text(json.dumps(hosts, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass

    state_path = destination / "associated_hosts_sources.json"
    state_path.write_text(json.dumps(states or {}, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        state_path.chmod(0o600)
    except OSError:
        pass

    if EXPORT_SETTINGS.get("enable_txt_export"):
        text_path = destination / "associated_hosts.txt"
        text_path.write_text(rendered + "\n", encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    del threads  # This module is source-bounded rather than worker-bounded.
    banner()
    domain = clean_domain_input(target)
    try:
        timeout = max(1, int(opts.get("timeout", DEFAULT_TIMEOUT)))
        sources = _selected_sources(opts.get("sources"))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid module options: {exc}[/red]")
        return 2

    ip = resolve_to_ip(domain)
    if not ip:
        console.print("[red]DNS failure[/red]")
        return 2

    hosts, states = collect(ip, timeout, sources)
    completed = [source for source, state in states.items() if state == "success"]
    failures = {source: state for source, state in states.items() if state.startswith("error:")}
    for source, state in sorted(failures.items()):
        console.print(f"[yellow]{source}: {state}[/yellow]")

    if not completed:
        console.print("[red]No associated-host source completed successfully[/red]")
        return 2

    rendered = render(hosts)
    export(domain, hosts, rendered, states)
    if not hosts:
        console.print("[yellow]No hosts found[/yellow]")
    else:
        console.print(rendered)
        console.print(f"[green]* {len(hosts)} host(s)[/green]")

    if failures:
        console.print("[yellow]Associated-host collection completed with provider errors[/yellow]")
        return PARTIAL_EXIT_CODE
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("target is required")
    target = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    options: dict[str, Any] = {}
    if len(sys.argv) > 3:
        try:
            parsed = json.loads(sys.argv[3])
        except json.JSONDecodeError as exc:
            console.print(f"[red]Invalid options JSON: {exc}[/red]")
            raise SystemExit(2)
        if not isinstance(parsed, dict):
            console.print("[red]Options JSON must be an object[/red]")
            raise SystemExit(2)
        options = parsed
    raise SystemExit(run(target, threads, options))
