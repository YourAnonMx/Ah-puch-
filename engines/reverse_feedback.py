#!/usr/bin/env python3
"""Bounded reverse-DNS feedback for explicitly eligible IP observations."""
from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from typing import Callable


def probe_ptr(ip: str, timeout: float = 2.0) -> dict:
    try:
        canonical = str(ipaddress.ip_address(ip))
    except ValueError:
        return {"ip": ip, "status": "invalid-input", "ptr": [], "error": "invalid IP address"}

    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(max(0.2, float(timeout)))
    try:
        host, aliases, _addresses = socket.gethostbyaddr(canonical)
    except socket.timeout as exc:
        return {"ip": canonical, "status": "timeout", "ptr": [], "error": f"{type(exc).__name__}: {exc}"}
    except socket.herror as exc:
        # h_errno 1 (HOST_NOT_FOUND) and 4 (NO_DATA) are completed clean
        # negatives. TRY_AGAIN/NO_RECOVERY are operational resolver failures.
        code = getattr(exc, "errno", None)
        if code in {1, 4}:
            return {"ip": canonical, "status": "no-ptr", "ptr": [], "error": ""}
        return {"ip": canonical, "status": "resolver-error", "ptr": [], "error": f"{type(exc).__name__}: {exc}"}
    except (socket.gaierror, OSError) as exc:
        return {"ip": canonical, "status": "resolver-error", "ptr": [], "error": f"{type(exc).__name__}: {exc}"}
    finally:
        socket.setdefaulttimeout(previous)

    values = sorted({
        value.lower().rstrip(".")
        for value in [host, *aliases]
        if value and str(value).strip()
    })
    return {"ip": canonical, "status": "success" if values else "no-ptr", "ptr": values, "error": ""}


def resolve_ptr(ip: str, timeout: float = 2.0) -> list[str]:
    """Compatibility helper returning only PTR names."""
    result = probe_ptr(ip, timeout)
    return list(result.get("ptr", []))


_DEFAULT_RESOLVE_PTR = resolve_ptr


def _build_probe_result(ip: str, timeout: float) -> dict:
    # Keep the historical resolve_ptr seam usable by deterministic tests and
    # local adapters that deliberately replace it, while production uses the
    # structured probe and therefore retains terminal error classes.
    if resolve_ptr is not _DEFAULT_RESOLVE_PTR:
        try:
            names = [str(value).lower().rstrip(".") for value in resolve_ptr(ip, timeout) if value]
        except Exception as exc:
            return {"ip": ip, "status": "resolver-error", "ptr": [], "error": f"{type(exc).__name__}: {exc}"}
        return {"ip": ip, "status": "success" if names else "no-ptr", "ptr": sorted(set(names)), "error": ""}
    return probe_ptr(ip, timeout)


def build(
    root: Path,
    ips: list[str],
    *,
    active: bool,
    allow_ip: Callable[[str], bool],
    allow_name: Callable[[str], bool],
    timeout: float = 2.0,
    limit: int = 128,
) -> list[dict]:
    destination = root / "reverse-feedback"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows: list[dict] = []
    for ip in sorted(set(ips))[: max(1, int(limit))]:
        if not allow_ip(ip):
            rows.append({"ip": ip, "status": "quarantined", "ptr": [], "promoted": [], "error": ""})
            continue
        if not active:
            rows.append({"ip": ip, "status": "not-probed", "ptr": [], "promoted": [], "error": ""})
            continue
        result = _build_probe_result(ip, timeout)
        names = [str(value) for value in result.get("ptr", []) if value]
        promoted = [name for name in names if allow_name(name)] if result.get("status") == "success" else []
        rows.append({
            "ip": str(result.get("ip", ip)),
            "status": str(result.get("status", "resolver-error")),
            "ptr": names,
            "promoted": promoted,
            "error": str(result.get("error", "")),
        })
    path = destination / "ptr.jsonl"
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return rows
