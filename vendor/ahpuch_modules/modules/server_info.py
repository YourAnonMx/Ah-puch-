#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests
from rich.console import Console
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT

console = Console()
INTERESTING_HEADERS = (
    "server",
    "via",
    "x-powered-by",
    "content-type",
    "location",
    "strict-transport-security",
    "alt-svc",
)


def banner() -> None:
    console.print(
        "[green]=============================================\n"
        "          Ah-Puch - Server Information\n"
        "=============================================[/green]\n"
    )


def _canonical_host(value: str) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw:
        raise ValueError("hostname is required")
    bracketless = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        return str(ipaddress.ip_address(bracketless))
    except ValueError:
        pass
    if any(character.isspace() for character in raw) or "/" in raw or "@" in raw or ":" in raw:
        raise ValueError("invalid hostname")
    try:
        host = raw.lower().encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    labels = host.split(".")
    if len(host) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise ValueError("invalid hostname")
    return host


def normalize_target(target: str) -> dict[str, Any]:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("target is required")
    if "://" not in raw:
        if "/" in raw or "@" in raw:
            raise ValueError("bare target must be a hostname; use a full URL for paths")
        raw = f"https://{raw}/"
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP(S) URL or hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentialed URLs are not accepted")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    host = _canonical_host(parsed.hostname)
    authority_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    authority = authority_host if port in (None, default_port) else f"{authority_host}:{port}"
    origin = urlunsplit((parsed.scheme, authority, "/", "", ""))
    return {
        "scheme": parsed.scheme,
        "host": host,
        "port": port or default_port,
        "origin": origin,
    }


def probe_server(origin: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    try:
        response = requests.head(
            origin,
            timeout=max(1, int(timeout)),
            verify=True,
            allow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
    except requests.exceptions.SSLError as exc:
        return {"state": "tls-error", "origin": origin, "error": type(exc).__name__}
    except requests.Timeout as exc:
        return {"state": "timeout", "origin": origin, "error": type(exc).__name__}
    except requests.RequestException as exc:
        return {"state": "transport-error", "origin": origin, "error": type(exc).__name__}

    headers = {
        name: str(response.headers.get(name, "") or "").strip()
        for name in INTERESTING_HEADERS
        if str(response.headers.get(name, "") or "").strip()
    }
    return {
        "state": "success",
        "origin": origin,
        "status_code": int(response.status_code),
        "headers": headers,
        "error": "",
    }


def display_server_info(payload: dict[str, Any]) -> None:
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", justify="left")
    table.add_column("Details", style="green")
    table.add_row("Origin", str(payload.get("origin", "")))
    table.add_row("Status", str(payload.get("status_code", "")))
    for key, value in sorted((payload.get("headers") or {}).items()):
        table.add_row(str(key), str(value))
    console.print(table)


def _safe_result_key(target: dict[str, Any]) -> str:
    value = str(target.get("host") or "unknown")
    if target.get("port") not in (80, 443):
        value += f"_{target['port']}"
    return "".join(character if character.isalnum() or character in ".-_" else "_" for character in value)


def export(target: dict[str, Any], payload: dict[str, Any]) -> None:
    destination = Path(RESULTS_DIR) / _safe_result_key(target)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass
    json_path = destination / "server_info.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass
    if EXPORT_SETTINGS.get("enable_txt_export"):
        text_path = destination / "server_info.txt"
        lines = [
            f"state={payload.get('state', '')}",
            f"origin={payload.get('origin', '')}",
            f"status_code={payload.get('status_code', '')}",
        ]
        for key, value in sorted((payload.get("headers") or {}).items()):
            lines.append(f"{key}={value}")
        text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    banner()
    try:
        worker_value = int(threads)
    except (TypeError, ValueError):
        console.print("[red]Invalid worker value[/red]")
        return 2
    if worker_value < 1:
        console.print("[red]Worker value must be positive[/red]")
        return 2
    if not isinstance(opts, dict) or opts:
        console.print("[red]Server Info does not accept module-specific options[/red]")
        return 2
    try:
        normalized = normalize_target(target)
    except ValueError as exc:
        console.print(f"[red]Invalid target: {exc}[/red]")
        return 2

    probe = probe_server(str(normalized["origin"]), DEFAULT_TIMEOUT)
    payload = {
        "state": str(probe.get("state", "transport-error")),
        "host": str(normalized["host"]),
        "port": int(normalized["port"]),
        "origin": str(normalized["origin"]),
        "status_code": probe.get("status_code"),
        "headers": probe.get("headers", {}) if isinstance(probe.get("headers"), dict) else {},
        "error": str(probe.get("error", "") or ""),
    }
    export(normalized, payload)
    if payload["state"] != "success":
        console.print(f"[red]Server information request failed: {payload['state']}[/red]")
        return 2
    display_server_info(payload)
    console.print("[white][*] Server information retrieval completed[/white]")
    return 0


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        console.print("[red]No target provided. Pass a domain or HTTP(S) URL.[/red]")
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
