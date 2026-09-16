#!/usr/bin/env python3
"""Bounded SSH banner and host-key observation for Ah-Puch catalog module 42."""
from __future__ import annotations

import base64
import ipaddress
import itertools
import json
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import md5, sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
from rich.console import Console
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR

try:
    import paramiko
except ImportError:  # optional fallback is ssh-keyscan
    paramiko = None

console = Console()

PARTIAL_EXIT_CODE = 3
DEFAULT_PORTS = (22,)
MAX_PORTS = 128
DEFAULT_MAX_HOSTS = 10
MAX_HOSTS = 4096
MAX_THREADS = 64
MAX_TIMEOUT = 120
COMPLETED_STATES = {"success", "not-ssh", "no-banner", "refused"}
ERROR_STATES = {"timeout", "transport-error", "resolver-error", "internal-error"}


def _safe_target_name(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value).strip()).strip("._-")
    return text[:160] or "target"


def _fingerprints(raw: bytes) -> tuple[str, str]:
    legacy = ":".join(f"{byte:02x}" for byte in md5(raw).digest())
    modern = base64.b64encode(sha256(raw).digest()).decode("ascii").rstrip("=")
    return legacy, modern


def parse_ports(value: Any, *, max_ports: int = MAX_PORTS) -> list[int]:
    """Parse a bounded comma/range port expression without materializing huge ranges."""
    if value in (None, ""):
        return list(DEFAULT_PORTS)
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if isinstance(value, (list, tuple)):
        value = ",".join(str(item) for item in value)
    text = str(value).strip()
    if not text:
        return list(DEFAULT_PORTS)

    result: set[int] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            raise ValueError("empty port token")
        if "-" in token:
            left, separator, right = token.partition("-")
            if not separator or not left.isdigit() or not right.isdigit():
                raise ValueError(f"invalid port range: {token}")
            start, end = int(left), int(right)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"invalid port range: {token}")
            if end - start + 1 > max_ports or len(result) + (end - start + 1) > max_ports:
                raise ValueError(f"port selection exceeds limit {max_ports}")
            result.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"invalid port: {token}")
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {token}")
            result.add(port)
        if len(result) > max_ports:
            raise ValueError(f"port selection exceeds limit {max_ports}")
    return sorted(result)


def _target_identity(value: str) -> str:
    raw = str(value).strip()
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        return (parsed.hostname or "").strip().lower().rstrip(".")
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")]
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        return raw.rsplit(":", 1)[0].strip().lower().rstrip(".")
    return raw.strip("[]").lower().rstrip(".")


def expand_target(value: str, timeout: int, max_hosts: int) -> dict[str, Any]:
    """Resolve one target into a deterministic bounded address list."""
    target = _target_identity(value)
    if not target:
        return {"state": "invalid", "input": value, "identity": "", "addresses": [], "truncated": False, "error": "empty target"}

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        network = None
    if network is not None:
        iterator = network.hosts()
        values = list(itertools.islice(iterator, max_hosts + 1))
        truncated = len(values) > max_hosts
        addresses = [str(address) for address in values[:max_hosts]]
        return {
            "state": "success",
            "input": value,
            "identity": str(network),
            "addresses": addresses,
            "truncated": truncated,
            "max_hosts": max_hosts,
            "error": "",
        }

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None
    if address is not None:
        return {"state": "success", "input": value, "identity": str(address), "addresses": [str(address)], "truncated": False, "max_hosts": max_hosts, "error": ""}

    if target == "localhost":
        return {"state": "success", "input": value, "identity": target, "addresses": ["127.0.0.1", "::1"][:max_hosts], "truncated": max_hosts < 2, "max_hosts": max_hosts, "error": ""}

    labels = target.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[A-Za-z0-9-]{1,63}", label) for label in labels):
        return {"state": "invalid", "input": value, "identity": target, "addresses": [], "truncated": False, "error": "target is not a hostname, IP, or CIDR"}

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = min(float(timeout), 5.0)
    resolver.lifetime = float(timeout)
    addresses: set[str] = set()
    clean_negative = 0
    errors: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(target, record_type)
            for answer in answers:
                try:
                    addresses.add(str(ipaddress.ip_address(str(answer).strip())))
                except ValueError:
                    continue
        except dns.resolver.NXDOMAIN:
            return {"state": "nxdomain", "input": value, "identity": target, "addresses": [], "truncated": False, "max_hosts": max_hosts, "error": ""}
        except dns.resolver.NoAnswer:
            clean_negative += 1
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
            errors.append(type(exc).__name__)
        except dns.resolver.NoNameservers as exc:
            errors.append(type(exc).__name__)
        except dns.exception.DNSException as exc:
            errors.append(type(exc).__name__)

    ordered = sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))
    truncated = len(ordered) > max_hosts
    ordered = ordered[:max_hosts]
    if ordered:
        return {"state": "partial" if errors else "success", "input": value, "identity": target, "addresses": ordered, "truncated": truncated, "max_hosts": max_hosts, "error": ";".join(errors)}
    if errors:
        state = "timeout" if all("Timeout" in item for item in errors) else "resolver-error"
        return {"state": state, "input": value, "identity": target, "addresses": [], "truncated": False, "max_hosts": max_hosts, "error": ";".join(errors)}
    return {"state": "no-answer" if clean_negative else "resolver-error", "input": value, "identity": target, "addresses": [], "truncated": False, "max_hosts": max_hosts, "error": ""}


def grab_banner(host: str, port: int, timeout: int) -> dict[str, Any]:
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            raw = sock.recv(512)
        except socket.timeout:
            return {"state": "no-banner", "banner": "", "connected": True, "error": "recv-timeout"}
        banner = raw.decode("utf-8", errors="replace").strip()
        ssh_line = next((line.strip() for line in banner.splitlines() if line.strip().startswith("SSH-")), "")
        if ssh_line:
            return {"state": "ssh-banner", "banner": ssh_line, "connected": True, "error": ""}
        if banner:
            return {"state": "not-ssh", "banner": banner[:512], "connected": True, "error": ""}
        return {"state": "no-banner", "banner": "", "connected": True, "error": ""}
    except ConnectionRefusedError:
        return {"state": "refused", "banner": "", "connected": False, "error": "ConnectionRefusedError"}
    except (socket.timeout, TimeoutError):
        return {"state": "timeout", "banner": "", "connected": False, "error": "TimeoutError"}
    except OSError as exc:
        return {"state": "transport-error", "banner": "", "connected": False, "error": type(exc).__name__}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def paramiko_key(host: str, port: int, timeout: int) -> dict[str, Any]:
    if paramiko is None:
        return {"state": "unavailable", "source": "paramiko", "key_type": "", "key_md5": "", "key_sha256": "", "error": "dependency unavailable"}
    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        transport.auth_timeout = timeout
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        raw = key.asbytes()
        legacy, modern = _fingerprints(raw)
        return {"state": "success", "source": "paramiko", "key_type": str(key.get_name()), "key_md5": legacy, "key_sha256": modern, "error": ""}
    except (socket.timeout, TimeoutError) as exc:
        return {"state": "timeout", "source": "paramiko", "key_type": "", "key_md5": "", "key_sha256": "", "error": type(exc).__name__}
    except OSError as exc:
        return {"state": "transport-error", "source": "paramiko", "key_type": "", "key_md5": "", "key_sha256": "", "error": type(exc).__name__}
    except Exception as exc:  # Paramiko exposes multiple version-specific SSH exception classes.
        return {"state": "ssh-error", "source": "paramiko", "key_type": "", "key_md5": "", "key_sha256": "", "error": type(exc).__name__}
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def ssh_keyscan(host: str, port: int, timeout: int) -> dict[str, Any]:
    binary = shutil.which("ssh-keyscan")
    if not binary:
        return {"state": "unavailable", "source": "ssh-keyscan", "key_type": "", "key_md5": "", "key_sha256": "", "error": "executable unavailable"}
    try:
        completed = subprocess.run(
            [binary, "-T", str(max(1, timeout)), "-p", str(port), host],
            capture_output=True,
            text=True,
            timeout=max(2, timeout + 2),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"state": "timeout", "source": "ssh-keyscan", "key_type": "", "key_md5": "", "key_sha256": "", "error": "TimeoutExpired"}
    except OSError as exc:
        return {"state": "transport-error", "source": "ssh-keyscan", "key_type": "", "key_md5": "", "key_sha256": "", "error": type(exc).__name__}

    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        try:
            raw = base64.b64decode(parts[2].encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            continue
        if not raw:
            continue
        legacy, modern = _fingerprints(raw)
        return {"state": "success", "source": "ssh-keyscan", "key_type": parts[1], "key_md5": legacy, "key_sha256": modern, "error": ""}
    state = "no-key" if completed.returncode == 0 else "failed"
    return {"state": state, "source": "ssh-keyscan", "key_type": "", "key_md5": "", "key_sha256": "", "error": str(completed.returncode) if completed.returncode else ""}


def _host_key(host: str, port: int, timeout: int) -> dict[str, Any]:
    first = paramiko_key(host, port, timeout)
    if first.get("state") == "success":
        return first
    fallback = ssh_keyscan(host, port, timeout)
    if fallback.get("state") == "success":
        fallback["fallback_from"] = first.get("state", "")
        return fallback
    return {
        "state": str(fallback.get("state") or first.get("state") or "unavailable"),
        "source": str(fallback.get("source") or first.get("source") or ""),
        "key_type": "",
        "key_md5": "",
        "key_sha256": "",
        "error": str(fallback.get("error") or first.get("error") or ""),
        "primary_state": str(first.get("state", "")),
        "fallback_state": str(fallback.get("state", "")),
    }


def observe_endpoint(host: str, port: int, timeout: int) -> dict[str, Any]:
    banner = grab_banner(host, port, timeout)
    banner_state = str(banner.get("state", "transport-error"))

    if banner_state == "not-ssh":
        return {
            "host": host, "port": port, "state": "not-ssh", "ssh_verified": False,
            "banner": str(banner.get("banner", "")), **{f"key_{name}": "" for name in ("type", "md5", "sha256")},
            "key_source": "", "banner_state": banner_state, "key_state": "not-attempted", "error": "",
        }
    if not bool(banner.get("connected")):
        return {
            "host": host, "port": port, "state": banner_state, "ssh_verified": False,
            "banner": "", "key_type": "", "key_md5": "", "key_sha256": "", "key_source": "",
            "banner_state": banner_state, "key_state": "not-attempted", "error": str(banner.get("error", "")),
        }

    key = _host_key(host, port, timeout)
    key_state = str(key.get("state", ""))
    key_states = {key_state, str(key.get("primary_state", "")), str(key.get("fallback_state", ""))}
    key_ok = key_state == "success"
    banner_ok = banner_state == "ssh-banner"
    verified = bool(banner_ok or key_ok)
    if banner_ok and key_ok:
        state = "success"
    elif verified:
        state = "partial"
    elif "timeout" in key_states or str(banner.get("error", "")) == "recv-timeout":
        state = "timeout"
    elif key_states.intersection({"transport-error", "failed", "ssh-error"}):
        state = "transport-error"
    else:
        state = "no-banner"
    error = ""
    if state in {"partial", "timeout", "transport-error"}:
        error = str(key.get("error", "") or banner.get("error", ""))
    return {
        "host": host,
        "port": port,
        "state": state,
        "ssh_verified": verified,
        "banner": str(banner.get("banner", "")),
        "key_type": str(key.get("key_type", "")) if key_ok else "",
        "key_md5": str(key.get("key_md5", "")) if key_ok else "",
        "key_sha256": str(key.get("key_sha256", "")) if key_ok else "",
        "key_source": str(key.get("source", "")) if key_ok else "",
        "banner_state": banner_state,
        "key_state": key_state,
        "error": error,
    }


def _export(target: str, payload: dict[str, Any]) -> Path:
    destination = Path(RESULTS_DIR) / _safe_target_name(target)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass
    path = destination / "ssh_fingerprints.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _render(rows: list[dict[str, Any]]) -> None:
    table = Table(title="SSH Banner & Host-Key Observations", header_style="bold white")
    for column in ("Host", "Port", "State", "Banner", "Key type", "SHA256"):
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(
            str(row.get("host", "")),
            str(row.get("port", "")),
            str(row.get("state", "")),
            str(row.get("banner", ""))[:96] or "-",
            str(row.get("key_type", "")) or "-",
            str(row.get("key_sha256", "")) or "-",
        )
    console.print(table)


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
        max_hosts = max(1, min(int(opts.get("max_hosts", DEFAULT_MAX_HOSTS)), MAX_HOSTS))
        workers = max(1, min(int(threads or 1), MAX_THREADS))
        ports = parse_ports(opts.get("ports", "22"))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid SSH module options: {exc}[/red]")
        return 2

    resolution = expand_target(target, timeout, max_hosts)
    if resolution["state"] == "invalid":
        console.print(f"[red]Invalid target: {resolution.get('error', '')}[/red]")
        return 2

    tasks = [(host, port) for host in resolution.get("addresses", []) for port in ports]
    rows: list[dict[str, Any]] = []
    if tasks:
        with ThreadPoolExecutor(max_workers=min(workers, len(tasks))) as executor:
            futures = {executor.submit(observe_endpoint, host, port, timeout): (host, port) for host, port in tasks}
            for future in as_completed(futures):
                host, port = futures[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = {
                        "host": host, "port": port, "state": "internal-error", "ssh_verified": False,
                        "banner": "", "key_type": "", "key_md5": "", "key_sha256": "", "key_source": "",
                        "banner_state": "internal-error", "key_state": "not-attempted", "error": type(exc).__name__,
                    }
                rows.append(row)
    rows.sort(key=lambda row: (ipaddress.ip_address(str(row["host"])).version, int(ipaddress.ip_address(str(row["host"]))), int(row["port"])))

    verified = sum(bool(row.get("ssh_verified")) for row in rows)
    partial = sum(row.get("state") == "partial" for row in rows)
    row_errors = sum(row.get("state") in ERROR_STATES for row in rows)
    resolution_partial = resolution.get("state") == "partial"
    resolution_error = resolution.get("state") in {"timeout", "resolver-error"}
    errors = row_errors + int(resolution_partial or resolution_error)
    payload = {
        "target": target,
        "resolution": resolution,
        "ports": ports,
        "threads": workers,
        "rows": rows,
        "summary": {
            "endpoints": len(rows),
            "ssh_verified": verified,
            "partial": partial + int(resolution_partial),
            "errors": errors,
            "clean_negative": sum(row.get("state") in {"not-ssh", "no-banner", "refused"} for row in rows),
        },
    }
    path = _export(target, payload)
    _render(rows)
    console.print(f"[dim]Structured artifact: {path}[/dim]")

    if resolution_error and not rows:
        console.print("[red]SSH target resolution did not complete[/red]")
        return 1
    completed = any(row.get("state") in COMPLETED_STATES or row.get("ssh_verified") for row in rows)
    if partial or resolution_partial or (row_errors and completed):
        console.print("[yellow]SSH observation completed with partial failures[/yellow]")
        return PARTIAL_EXIT_CODE
    if row_errors and not completed:
        console.print("[red]No SSH endpoint observation completed[/red]")
        return 1
    console.print("[green]SSH observation completed[/green]")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]A target is required[/red]")
        raise SystemExit(2)
    target = sys.argv[1]
    try:
        threads = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    except ValueError:
        console.print("[red]threads must be an integer[/red]")
        raise SystemExit(2)
    try:
        parsed = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid options JSON: {exc}[/red]")
        raise SystemExit(2)
    if not isinstance(parsed, dict):
        console.print("[red]Options JSON must be an object[/red]")
        raise SystemExit(2)
    raise SystemExit(run(target, threads, parsed))
