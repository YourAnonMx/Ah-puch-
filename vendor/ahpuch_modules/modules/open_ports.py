#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import API_KEYS, DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, USER_AGENT
from ahpuch_modules.utils.util import resolve_to_ip

console = Console()
TEAL = "#2EC4B6"
SHODAN_API = "https://api.shodan.io/shodan/host/{ip}"
MAX_WORKERS = 256


def banner() -> None:
    console.print(f"[{TEAL}]" + "=" * 44)
    console.print("[cyan]      Ah-Puch - Open Ports Scanner")
    console.print(f"[{TEAL}]" + "=" * 44)


def _canonical_hostname(value: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(character.isspace() for character in host):
        raise ValueError("target must be an IP address or hostname")
    if "://" in host or ":" in host or "/" in host or "@" in host:
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


def resolve_target(target: str) -> dict[str, Any]:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("target is required")
    bracketless = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        literal = str(ipaddress.ip_address(bracketless))
        host = ""
    except ValueError:
        literal = ""
        host = _canonical_hostname(raw)

    primary = resolve_to_ip(raw)
    if not primary:
        return {
            "state": "resolution-error",
            "target": host or bracketless,
            "host": host,
            "ip": "",
            "addresses": [],
            "error": "no-addresses",
        }
    try:
        primary = str(ipaddress.ip_address(primary))
    except ValueError:
        return {
            "state": "resolution-error",
            "target": host or bracketless,
            "host": host,
            "ip": "",
            "addresses": [],
            "error": "invalid-resolver-address",
        }
    if literal:
        return {"state": "success", "target": literal, "host": "", "ip": primary, "addresses": [primary], "error": ""}

    try:
        answers = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return {"state": "resolution-error", "target": host, "host": host, "ip": "", "addresses": [], "error": type(exc).__name__}

    addresses: set[str] = {primary}
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or not sockaddr:
            continue
        try:
            addresses.add(str(ipaddress.ip_address(str(sockaddr[0]).strip())))
        except ValueError:
            continue
    ordered = sorted(
        addresses,
        key=lambda address: (ipaddress.ip_address(address).version, ipaddress.ip_address(address).packed),
    )
    if not ordered:
        return {"state": "resolution-error", "target": host, "host": host, "ip": "", "addresses": [], "error": "no-addresses"}
    return {"state": "success", "target": host, "host": host, "ip": ordered[0], "addresses": ordered, "error": ""}


def parse_ports(portspec: str) -> list[int]:
    text = str(portspec or "").strip()
    if not text:
        raise ValueError("port expression is empty")
    ports: set[int] = set()
    for raw in text.split(","):
        token = raw.strip()
        if not token:
            raise ValueError("empty port token")
        if "-" in token:
            fields = token.split("-")
            if len(fields) != 2:
                raise ValueError(f"invalid port range: {token}")
            try:
                start, end = (int(value) for value in fields)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {token}") from exc
            if start > end:
                raise ValueError(f"descending port range: {token}")
            if start < 1 or end > 65535:
                raise ValueError(f"port out of range: {token}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise ValueError(f"invalid port: {token}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range: {token}")
            ports.add(port)
    return sorted(ports)


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def scan_port(ip: str, port: int, timeout: float) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((ip, port))
        if code == 0:
            banner_text = "-"
            try:
                data = sock.recv(1024)
                if data:
                    banner_text = data.decode("utf-8", "replace").strip() or "-"
            except (socket.timeout, OSError):
                pass
            return {"port": port, "state": "open", "service": _service_name(port), "banner": banner_text, "error": ""}
        if code == errno.ECONNREFUSED:
            return {"port": port, "state": "closed", "service": "", "banner": "", "error": ""}
        if code in {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}:
            return {"port": port, "state": "filtered", "service": "", "banner": "", "error": ""}
        return {"port": port, "state": "error", "service": "", "banner": "", "error": f"connect-ex:{code}"}
    except socket.timeout:
        return {"port": port, "state": "filtered", "service": "", "banner": "", "error": ""}
    except OSError as exc:
        return {"port": port, "state": "error", "service": "", "banner": "", "error": f"{type(exc).__name__}:{exc.errno}"}
    finally:
        sock.close()


def shodan_lookup(ip: str, key: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if not key:
        return {"state": "skipped", "ports": [], "error": "no-api-key"}
    try:
        response = requests.get(
            SHODAN_API.format(ip=ip),
            params={"key": key},
            timeout=max(1.0, float(timeout)),
            verify=True,
            headers={"User-Agent": USER_AGENT},
        )
    except (requests.RequestException, TypeError, ValueError) as exc:
        return {"state": "transport-error", "ports": [], "error": type(exc).__name__}
    if response.status_code != 200:
        return {"state": "http-error", "ports": [], "http_status": response.status_code, "error": ""}
    try:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Shodan response is not an object")
    except (ValueError, TypeError) as exc:
        return {"state": "parse-error", "ports": [], "error": type(exc).__name__}

    rows: dict[int, dict[str, Any]] = {}
    data = payload.get("data", [])
    if isinstance(data, list):
        for raw in data:
            if not isinstance(raw, dict):
                continue
            try:
                port = int(raw.get("port", 0))
            except (TypeError, ValueError):
                continue
            if not 1 <= port <= 65535:
                continue
            shodan_meta = raw.get("_shodan", {}) if isinstance(raw.get("_shodan"), dict) else {}
            product = str(raw.get("product", "") or shodan_meta.get("module", "") or "-")
            rows[port] = {"port": port, "service": product, "source": "Shodan", "verified_current": False}
    listed_ports = payload.get("ports", [])
    if isinstance(listed_ports, list):
        for raw in listed_ports:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                rows.setdefault(port, {"port": port, "service": "-", "source": "Shodan", "verified_current": False})
    return {"state": "success", "ports": [rows[port] for port in sorted(rows)], "error": ""}


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
    json_path = destination / "open_ports.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass
    if EXPORT_SETTINGS.get("enable_txt_export"):
        text_path = destination / "open_ports.txt"
        lines = [
            f"state={payload.get('state', '')}",
            f"target={payload.get('target', '')}",
            f"ip={payload.get('ip', '')}",
        ]
        for row in payload.get("open_ports", []):
            lines.append(
                f"{row.get('port')}\t{row.get('service', '-')}\t{row.get('source', '')}\t"
                f"verified_current={str(bool(row.get('verified_current'))).lower()}"
            )
        text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def _render(payload: dict[str, Any]) -> None:
    rows = payload.get("open_ports", [])
    if not rows:
        console.print("[yellow]No open ports found[/yellow]")
        return
    table = Table(title=f"Open Ports – {payload.get('target')} ({payload.get('ip')})", header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="green")
    table.add_column("Banner", style="white", overflow="fold")
    table.add_column("Source", style="yellow")
    for row in rows:
        table.add_row(
            str(row.get("port", "")),
            str(row.get("service", "-") or "-"),
            str(row.get("banner", "-") or "-"),
            str(row.get("source", "")),
        )
    console.print(table)


def run(target: str, ports_spec: str, threads: int, timeout: float, no_fallback: bool = False) -> int:
    banner()
    try:
        resolution = resolve_target(target)
        ports = parse_ports(ports_spec)
        workers = max(1, min(int(threads), MAX_WORKERS))
        per_port_timeout = float(timeout)
        if per_port_timeout <= 0 or per_port_timeout > 60:
            raise ValueError("timeout must be >0 and <=60 seconds")
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid scan contract: {exc}[/red]")
        return 2

    if resolution["state"] != "success":
        payload = {
            "state": "failed",
            "target": resolution["target"],
            "host": resolution["host"],
            "ip": "",
            "shodan": {"state": "skipped", "ports": [], "error": "unresolved-target"},
            "scan": {"enabled": not no_fallback, "requested_ports": len(ports), "counts": {}},
            "open_ports": [],
            "error": resolution["error"],
        }
        export(resolution, payload)
        console.print("[red]Failed to resolve target[/red]")
        return 2

    ip = str(resolution["ip"])
    shodan = shodan_lookup(ip, API_KEYS.get("SHODAN_API_KEY", ""), min(float(DEFAULT_TIMEOUT), max(per_port_timeout, 1.0)))
    seen: dict[int, dict[str, Any]] = {
        int(row["port"]): dict(row)
        for row in shodan.get("ports", [])
        if isinstance(row, dict) and isinstance(row.get("port"), int)
    }

    scan_rows: list[dict[str, Any]] = []
    if not no_fallback:
        with Progress(
            SpinnerColumn(),
            TextColumn("[white]{task.description}"),
            BarColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning ports", total=len(ports))
            with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as pool:
                futures = {pool.submit(scan_port, ip, port, per_port_timeout): port for port in ports}
                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        row = future.result()
                    except Exception as exc:  # isolate one worker from the scan ledger
                        row = {"port": port, "state": "error", "service": "", "banner": "", "error": type(exc).__name__}
                    if not isinstance(row, dict):
                        row = {"port": port, "state": "error", "service": "", "banner": "", "error": "invalid-worker-result"}
                    scan_rows.append(row)
                    if row.get("state") == "open":
                        previous = seen.get(port, {})
                        seen[port] = {
                            "port": port,
                            "service": str(row.get("service") or previous.get("service") or "-"),
                            "banner": str(row.get("banner") or "-"),
                            "source": "Both" if previous else "Scan",
                            "verified_current": True,
                        }
                    progress.advance(task)

    counts: dict[str, int] = {}
    for row in scan_rows:
        state_value = str(row.get("state", "error"))
        counts[state_value] = counts.get(state_value, 0) + 1

    if no_fallback:
        state = "success" if shodan.get("state") == "success" else "failed"
    elif counts.get("error", 0):
        state = "partial"
    else:
        terminal = sum(counts.get(name, 0) for name in ("open", "closed", "filtered"))
        state = "success" if terminal == len(ports) else "failed"

    payload = {
        "state": state,
        "target": str(resolution["target"]),
        "host": str(resolution["host"]),
        "ip": ip,
        "resolved_addresses": list(resolution["addresses"]),
        "shodan": shodan,
        "scan": {
            "enabled": not no_fallback,
            "requested_ports": len(ports),
            "counts": counts,
        },
        "open_ports": [seen[port] for port in sorted(seen)],
        "error": "",
    }
    export(resolution, payload)
    _render(payload)

    if state != "success":
        console.print(f"[red]Port scan did not complete cleanly: {state}[/red]")
        return 2
    console.print("[white][*] Port scanning completed[/white]")
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("target")
    value.add_argument("-p", "--ports", default="1-1024")
    value.add_argument("-t", "--threads", type=int, default=100)
    value.add_argument("-T", "--timeout", type=float, default=1.0)
    value.add_argument("--no-fallback", action="store_true")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    return run(args.target, args.ports, args.threads, args.timeout, args.no_fallback)


if __name__ == "__main__":
    raise SystemExit(main())
