#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import socket
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from rich.console import Console
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

console = Console()

PROVIDER_NAME = "ipapi.co"
PROVIDER_FIELDS = (
    "city",
    "region",
    "country",
    "country_name",
    "latitude",
    "longitude",
    "timezone",
    "asn",
    "org",
)


def banner() -> None:
    console.print(
        "[green]=============================================\n"
        "          Ah-Puch - IP Information\n"
        "=============================================[/green]\n"
    )


def _canonical_hostname(value: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(character.isspace() for character in host):
        raise ValueError("target must be an IP address or hostname")
    if host.startswith("[") or host.endswith("]") or ":" in host or "/" in host or "@" in host:
        raise ValueError("target must be an IP address or hostname")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise ValueError("invalid hostname")
    return ascii_host


def normalize_target(target: str) -> tuple[str, str]:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("target is required")
    if "://" in raw:
        raise ValueError("IP Info accepts an IP address or hostname, not a URL")
    bracketless = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        return "ip", str(ipaddress.ip_address(bracketless))
    except ValueError:
        return "hostname", _canonical_hostname(raw)


def resolve_target(target: str) -> dict[str, Any]:
    kind, value = normalize_target(target)
    if kind == "ip":
        return {
            "state": "success",
            "kind": "ip",
            "target": value,
            "host": "",
            "ip": value,
            "addresses": [value],
            "error": "",
        }

    try:
        answers = socket.getaddrinfo(
            value,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        return {
            "state": "resolution-error",
            "kind": "hostname",
            "target": value,
            "host": value,
            "ip": "",
            "addresses": [],
            "error": type(exc).__name__,
        }

    addresses: set[str] = set()
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
            continue
        try:
            addresses.add(str(ipaddress.ip_address(str(sockaddr[0]).strip())))
        except ValueError:
            continue
    ordered = sorted(
        addresses,
        key=lambda address: (
            ipaddress.ip_address(address).version,
            ipaddress.ip_address(address).packed,
        ),
    )
    if not ordered:
        return {
            "state": "resolution-error",
            "kind": "hostname",
            "target": value,
            "host": value,
            "ip": "",
            "addresses": [],
            "error": "no-addresses",
        }
    return {
        "state": "success",
        "kind": "hostname",
        "target": value,
        "host": value,
        "ip": ordered[0],
        "addresses": ordered,
        "error": "",
    }


def get_ip_info(ip: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    canonical_ip = str(ipaddress.ip_address(str(ip).strip()))
    try:
        response = requests.get(
            f"https://ipapi.co/{quote(canonical_ip, safe=':')}/json/",
            timeout=max(1, int(timeout)),
            verify=True,
            headers={"User-Agent": USER_AGENT},
        )
    except (requests.RequestException, TypeError, ValueError) as exc:
        return {
            "state": "transport-error",
            "ip": canonical_ip,
            "provider": PROVIDER_NAME,
            "data": {},
            "error": type(exc).__name__,
        }

    if response.status_code != 200:
        return {
            "state": "http-error",
            "ip": canonical_ip,
            "provider": PROVIDER_NAME,
            "data": {},
            "http_status": response.status_code,
            "error": "",
        }

    try:
        raw = response.json()
        if not isinstance(raw, dict):
            raise ValueError("provider response is not an object")
    except (ValueError, TypeError) as exc:
        return {
            "state": "parse-error",
            "ip": canonical_ip,
            "provider": PROVIDER_NAME,
            "data": {},
            "error": type(exc).__name__,
        }

    if raw.get("error") is True:
        return {
            "state": "provider-error",
            "ip": canonical_ip,
            "provider": PROVIDER_NAME,
            "data": {},
            "error": str(raw.get("reason") or raw.get("message") or "provider-error"),
        }

    provider_ip = str(raw.get("ip", "") or "").strip()
    if provider_ip:
        try:
            if str(ipaddress.ip_address(provider_ip)) != canonical_ip:
                return {
                    "state": "provider-error",
                    "ip": canonical_ip,
                    "provider": PROVIDER_NAME,
                    "data": {},
                    "error": "provider-ip-mismatch",
                }
        except ValueError:
            return {
                "state": "parse-error",
                "ip": canonical_ip,
                "provider": PROVIDER_NAME,
                "data": {},
                "error": "invalid-provider-ip",
            }

    data = {field: raw.get(field) for field in PROVIDER_FIELDS if raw.get(field) not in (None, "")}
    return {
        "state": "success",
        "ip": canonical_ip,
        "provider": PROVIDER_NAME,
        "data": data,
        "error": "",
    }


def display_ip_info(payload: dict[str, Any]) -> None:
    table = Table(show_header=True, header_style="bold white")
    table.add_column("Key", style="white", justify="left", min_width=15)
    table.add_column("Value", style="white", justify="left", min_width=32)
    table.add_row("IP", str(payload.get("ip", "")))
    table.add_row("Provider", str(payload.get("provider", "")))
    for key, value in sorted((payload.get("data") or {}).items()):
        table.add_row(str(key), str(value))
    console.print(table)


def _safe_result_key(resolution: dict[str, Any]) -> str:
    value = str(resolution.get("host") or resolution.get("ip") or "unknown").strip().lower()
    return "".join(character if character.isalnum() or character in ".-_" else "_" for character in value) or "unknown"


def export(resolution: dict[str, Any], payload: dict[str, Any]) -> None:
    destination = Path(RESULTS_DIR) / _safe_result_key(resolution)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass

    json_path = destination / "ip_info.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass

    if EXPORT_SETTINGS.get("enable_txt_export"):
        text_path = destination / "ip_info.txt"
        lines = [
            f"state={payload.get('state', '')}",
            f"target={payload.get('target', '')}",
            f"host={payload.get('host', '')}",
            f"ip={payload.get('ip', '')}",
            f"provider={payload.get('provider', '')}",
        ]
        for key, value in sorted((payload.get("data") or {}).items()):
            lines.append(f"{key}={value}")
        text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    banner()
    try:
        workers = int(threads)
    except (TypeError, ValueError):
        console.print("[red]Invalid worker value[/red]")
        return 2
    if workers < 1:
        console.print("[red]Worker value must be positive[/red]")
        return 2
    if not isinstance(opts, dict):
        console.print("[red]Options JSON must be an object[/red]")
        return 2
    if opts:
        console.print("[red]IP Info does not accept module-specific options[/red]")
        return 2

    try:
        resolution = resolve_target(target)
    except ValueError as exc:
        console.print(f"[red]Invalid target: {exc}[/red]")
        return 2

    if resolution["state"] != "success":
        payload = {**resolution, "provider": PROVIDER_NAME, "data": {}}
        export(resolution, payload)
        console.print("[red]Unable to resolve target to an IP address[/red]")
        return 2

    provider = get_ip_info(str(resolution["ip"]), DEFAULT_TIMEOUT)
    payload = {
        "state": str(provider.get("state", "provider-error")),
        "target": str(resolution["target"]),
        "kind": str(resolution["kind"]),
        "host": str(resolution["host"]),
        "ip": str(resolution["ip"]),
        "resolved_addresses": list(resolution["addresses"]),
        "provider": PROVIDER_NAME,
        "data": provider.get("data", {}) if isinstance(provider.get("data"), dict) else {},
        "error": str(provider.get("error", "") or ""),
    }
    if "http_status" in provider:
        payload["http_status"] = provider["http_status"]
    export(resolution, payload)

    if payload["state"] != "success":
        console.print(f"[red]IP information provider did not complete successfully: {payload['state']}[/red]")
        return 2

    display_ip_info(payload)
    console.print("[green][*] IP info retrieval completed[/green]")
    return 0


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        console.print("[red]No target provided. Pass an IP address or hostname.[/red]")
        return 2
    target = values[0]
    if len(values) > 1:
        try:
            threads = int(values[1])
        except ValueError:
            console.print("[red]Invalid worker value[/red]")
            return 2
    else:
        threads = 1
    if len(values) > 2:
        try:
            options = json.loads(values[2])
        except json.JSONDecodeError as exc:
            console.print(f"[red]Invalid options JSON: {exc}[/red]")
            return 2
        if not isinstance(options, dict):
            console.print("[red]Options JSON must be an object[/red]")
            return 2
    else:
        options = {}
    return run(target, threads, options)


if __name__ == "__main__":
    raise SystemExit(main())
