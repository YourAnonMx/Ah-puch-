#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from rich import box
from rich.console import Console
from rich.table import Table

try:
    from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, HEADERS, RESULTS_DIR
except ImportError:
    DEFAULT_TIMEOUT = 10
    EXPORT_SETTINGS = {"enable_txt_export": True}
    HEADERS = {}
    RESULTS_DIR = "results"

console = Console()
PARTIAL_EXIT_CODE = 3
_ERROR_STATES = {
    "timeout",
    "resolver-error",
    "transport-error",
    "transport-or-protocol-error",
    "tls-error",
    "tls-verification-error",
    "http-error",
    "parse-error",
    "internal-error",
    "error",
}


def banner() -> None:
    console.print(
        """
==================================================
    Ah-Puch - HTTP/2 & HTTP/3 Support Checker
==================================================
"""
    )


def parse_target(raw: str) -> tuple[str, int, str]:
    value = str(raw or "").strip()
    if not value:
        raise ValueError("target is required")
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("HTTP/2 and HTTP/3 TLS probing requires an HTTPS URL or bare host")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("invalid target port") from exc
    if not 1 <= int(port) <= 65535:
        raise ValueError("target port out of range")
    host = parsed.hostname.lower().rstrip(".")
    display = f"[{host}]" if ":" in host else host
    authority = display if port == 443 else f"{display}:{port}"
    return host, int(port), f"https://{authority}/"


def resolve_host(host: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        ips = sorted({str(ipaddress.ip_address(row[4][0])) for row in infos})
        return {"state": "success", "ips": ips, "latency_ms": int((time.monotonic() - started) * 1000), "error": ""}
    except (socket.gaierror, OSError, ValueError) as exc:
        return {"state": "resolver-error", "ips": [], "latency_ms": int((time.monotonic() - started) * 1000), "error": type(exc).__name__}


def _certificate_details(tls: ssl.SSLSocket) -> dict[str, Any]:
    der = tls.getpeercert(binary_form=True)
    peer = tls.getpeercert() or {}
    subject = peer.get("subject", [])
    issuer = peer.get("issuer", [])
    common_name = next((value for row in subject for key, value in row if key == "commonName"), "")
    issuer_name = next((value for row in issuer for key, value in row if key == "commonName"), "")
    return {
        "sha256": hashlib.sha256(der).hexdigest() if der else "",
        "common_name": str(common_name or ""),
        "issuer_common_name": str(issuer_name or ""),
        "expires": str(peer.get("notAfter", "") or ""),
    }


def test_http2(host: str, port: int, origin: str, timeout: int) -> dict[str, Any]:
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls:
                handshake_ms = int((time.monotonic() - started) * 1000)
                alpn = tls.selected_alpn_protocol() or ""
                version = tls.version() or ""
                cipher = tls.cipher()[0] if tls.cipher() else ""
                certificate = _certificate_details(tls)
    except ssl.SSLCertVerificationError as exc:
        return {"state": "tls-verification-error", "supported": None, "handshake_ms": -1, "alpn": "", "tls": "", "cipher": "", "certificate": {}, "http": {}, "error": type(exc).__name__}
    except ssl.SSLError as exc:
        return {"state": "tls-error", "supported": None, "handshake_ms": -1, "alpn": "", "tls": "", "cipher": "", "certificate": {}, "http": {}, "error": type(exc).__name__}
    except (socket.timeout, TimeoutError) as exc:
        return {"state": "timeout", "supported": None, "handshake_ms": -1, "alpn": "", "tls": "", "cipher": "", "certificate": {}, "http": {}, "error": type(exc).__name__}
    except OSError as exc:
        return {"state": "transport-error", "supported": None, "handshake_ms": -1, "alpn": "", "tls": "", "cipher": "", "certificate": {}, "http": {}, "error": type(exc).__name__}

    try:
        response = requests.get(origin, headers=HEADERS, timeout=timeout, verify=True, allow_redirects=False)
        http_result: dict[str, Any] = {
            "state": "success",
            "status": response.status_code,
            "bytes": len(response.content),
            "server": str(response.headers.get("server", "") or ""),
        }
    except requests.RequestException as exc:
        http_result = {"state": "error", "status": None, "bytes": None, "server": "", "error": type(exc).__name__}

    return {
        "state": "success",
        "supported": alpn == "h2",
        "handshake_ms": handshake_ms,
        "alpn": alpn,
        "tls": version,
        "cipher": cipher,
        "certificate": certificate,
        "http": http_result,
        "error": "",
    }


async def _http3_handshake(host: str, port: int) -> int:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_REQUIRED
    started = time.monotonic()
    async with connect(host, port, configuration=configuration, wait_connected=True):
        return int((time.monotonic() - started) * 1000)


def test_http3(host: str, port: int, timeout: int) -> dict[str, Any]:
    try:
        handshake_ms = asyncio.run(asyncio.wait_for(_http3_handshake(host, port), timeout=float(timeout)))
        return {"state": "success", "supported": True, "handshake_ms": handshake_ms, "error": ""}
    except (asyncio.TimeoutError, TimeoutError) as exc:
        return {"state": "timeout", "supported": None, "handshake_ms": -1, "error": type(exc).__name__}
    except ssl.SSLCertVerificationError as exc:
        return {"state": "tls-verification-error", "supported": None, "handshake_ms": -1, "error": type(exc).__name__}
    except Exception as exc:
        return {"state": "transport-or-protocol-error", "supported": None, "handshake_ms": -1, "error": type(exc).__name__}


def _is_error_state(value: object) -> bool:
    state = str(value or "").strip().lower()
    return bool(state in _ERROR_STATES or state.endswith("-error"))


def _has_partial_failure(http2: dict[str, Any], http3: dict[str, Any]) -> bool:
    if _is_error_state(http2.get("state")) or _is_error_state(http3.get("state")):
        return True
    nested_http = http2.get("http", {})
    return isinstance(nested_http, dict) and _is_error_state(nested_http.get("state"))


def _render(origin: str, dns_result: dict[str, Any], http2: dict[str, Any], http3: dict[str, Any]) -> Table:
    table = Table(title=f"Protocol Support – {origin}", box=box.ASCII, header_style="bold")
    for column in ("Proto", "State", "Support", "DNS(ms)", "IPs", "HS(ms)", "ALPN", "TLSv", "Cipher", "HTTP", "Server"):
        table.add_column(column, overflow="fold")
    http = http2.get("http", {}) if isinstance(http2.get("http"), dict) else {}
    table.add_row(
        "HTTP/2",
        str(http2.get("state", "unknown")),
        str(http2.get("supported") if http2.get("supported") is not None else "indeterminate"),
        str(dns_result.get("latency_ms", "-")),
        ",".join(str(value) for value in dns_result.get("ips", [])) or "-",
        str(http2.get("handshake_ms", "-")),
        str(http2.get("alpn") or "-"),
        str(http2.get("tls") or "-"),
        str(http2.get("cipher") or "-"),
        str(http.get("status") if http.get("status") is not None else "-"),
        str(http.get("server") or "-"),
    )
    table.add_row(
        "HTTP/3",
        str(http3.get("state", "unknown")),
        str(http3.get("supported") if http3.get("supported") is not None else "indeterminate"),
        str(dns_result.get("latency_ms", "-")),
        ",".join(str(value) for value in dns_result.get("ips", [])) or "-",
        str(http3.get("handshake_ms", "-")),
        "-", "-", "-", "-", "-",
    )
    return table


def _export(host: str, payload: dict[str, Any], table: Table) -> None:
    destination = Path(RESULTS_DIR) / host.replace(":", "_")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass
    json_path = destination / "http2_http3.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass
    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        text_path = destination / "http2_http3.txt"
        text_path.write_text(export_console.export_text(), encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    del threads
    banner()
    try:
        host, port, origin = parse_target(target)
        timeout = max(1, int(opts.get("timeout", DEFAULT_TIMEOUT)))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid input/options: {exc}[/red]")
        return 2

    dns_result = resolve_host(host)
    if dns_result["state"] != "success":
        payload = {"target": target, "host": host, "port": port, "origin": origin, "dns": dns_result, "http2": {}, "http3": {}}
        table = _render(origin, dns_result, {}, {})
        console.print(table)
        _export(host, payload, table)
        return 2

    http2 = test_http2(host, port, origin, timeout)
    http3 = test_http3(host, port, timeout)
    payload = {"target": target, "host": host, "port": port, "origin": origin, "dns": dns_result, "http2": http2, "http3": http3}
    table = _render(origin, dns_result, http2, http3)
    console.print(table)
    _export(host, payload, table)

    completed = http2.get("state") == "success" or http3.get("state") == "success"
    if not completed:
        console.print("[red]Neither protocol probe completed successfully[/red]")
        return 2
    if _has_partial_failure(http2, http3):
        console.print("[yellow][*] Protocol support check completed with partial probe failures[/yellow]")
        return PARTIAL_EXIT_CODE
    console.print("[green][*] Protocol support check completed[/green]")
    return 0


def main(raw: str) -> int:
    return run(raw, 1, {})


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]No target provided[/red]")
        raise SystemExit(2)
    target = sys.argv[1]
    try:
        parsed = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid options JSON: {exc}[/red]")
        raise SystemExit(2)
    if not isinstance(parsed, dict):
        console.print("[red]Options JSON must be an object[/red]")
        raise SystemExit(2)
    try:
        raise SystemExit(run(target, 1, parsed))
    except KeyboardInterrupt:
        console.print("[red]Interrupted[/red]")
        raise SystemExit(130)
