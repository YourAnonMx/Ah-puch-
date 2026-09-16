#!/usr/bin/env python3
"""Verified TLS peer-certificate inventory for target HTTPS origins."""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit


def _name_tuple(values) -> dict[str, str]:  # noqa: ANN001
    result: dict[str, str] = {}
    for rdn in values or ():
        for key, value in rdn:
            result[str(key)] = str(value)
    return result


def _probe(origin: str, timeout: int) -> dict:
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"origin": origin, "status": "not-https"}
    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=max(1, min(timeout, 15))) as raw:
            with context.wrap_socket(raw, server_hostname=host) as stream:
                cert = stream.getpeercert()
                der = stream.getpeercert(binary_form=True)
                try:
                    peer = stream.getpeername()[0]
                except (OSError, AttributeError, IndexError, TypeError):
                    peer = ""
    except Exception as exc:
        return {"origin": origin, "status": "error", "error": f"{type(exc).__name__}: {exc}"}
    sans = []
    for kind, value in cert.get("subjectAltName", ()) if isinstance(cert, dict) else ():
        if kind in {"DNS", "IP Address", "URI"} and value:
            sans.append({"type": kind, "value": str(value)})
    digest = hashlib.sha256(der).hexdigest() if der else ""
    return {
        "origin": origin,
        "status": "verified",
        "hostname": host,
        "port": port,
        "peer_address": peer,
        "certificate_sha256": digest,
        "subject": _name_tuple(cert.get("subject", ())) if isinstance(cert, dict) else {},
        "issuer": _name_tuple(cert.get("issuer", ())) if isinstance(cert, dict) else {},
        "serial_number": str(cert.get("serialNumber", "")) if isinstance(cert, dict) else "",
        "not_before": str(cert.get("notBefore", "")) if isinstance(cert, dict) else "",
        "not_after": str(cert.get("notAfter", "")) if isinstance(cert, dict) else "",
        "subject_alt_name": sans,
    }


def collect(
    root: Path,
    origins: list[str],
    *,
    active: bool,
    timeout: int,
    max_origins: int = 64,
    allow_origin: Callable[[str], bool] | None = None,
) -> list[dict]:
    destination = root / "tls-inventory"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows: list[dict] = []
    for origin in origins[: max(1, max_origins)]:
        if allow_origin and not allow_origin(origin):
            rows.append({"origin": origin, "status": "quarantined"})
            continue
        if not active:
            rows.append({"origin": origin, "status": "not-probed"})
            continue
        rows.append(_probe(origin, timeout))
    path = destination / "certificates.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    path.chmod(0o600)
    return rows
