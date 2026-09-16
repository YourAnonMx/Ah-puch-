#!/usr/bin/env python3
"""Bounded traceroute adapter for the catalog's Traceroute capability."""
from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit

from rich.console import Console
from rich.table import Table

console = Console()
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_HOPS = 30
_HOP_RE = re.compile(r"^\s*(\d+)\s+(.+?)\s*$")


def clean_target(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or ""
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        host = host.rstrip(".").lower()
        if len(host) > 253 or any(character.isspace() for character in host):
            return ""
        return host


def _parse_hops(stdout: str) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for line in str(stdout or "").splitlines():
        match = _HOP_RE.match(line)
        if not match:
            continue
        number = int(match.group(1))
        detail = match.group(2).strip()
        hops.append({"hop": number, "detail": detail})
    return hops


def trace(target: str, timeout: int = DEFAULT_TIMEOUT, max_hops: int = DEFAULT_MAX_HOPS) -> dict[str, Any]:
    host = clean_target(target)
    if not host:
        return {"state": "inapplicable", "target": str(target or ""), "hops": [], "stdout": "", "stderr": "", "error": "target-required"}
    try:
        timeout_value = max(1, int(timeout))
        hops_value = max(1, min(int(max_hops), 64))
    except (TypeError, ValueError) as exc:
        return {"state": "inapplicable", "target": host, "hops": [], "stdout": "", "stderr": "", "error": type(exc).__name__}

    binary = shutil.which("traceroute")
    if not binary:
        return {"state": "dependency-unavailable", "target": host, "hops": [], "stdout": "", "stderr": "", "error": "traceroute-not-installed"}
    command = [binary, "-n", "-m", str(hops_value), host]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_value,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "state": "timeout",
            "target": host,
            "hops": _parse_hops(exc.stdout or ""),
            "stdout": str(exc.stdout or ""),
            "stderr": str(exc.stderr or ""),
            "error": "timeout",
        }
    except OSError as exc:
        return {"state": "dependency-unavailable", "target": host, "hops": [], "stdout": "", "stderr": "", "error": type(exc).__name__}

    stdout = str(completed.stdout or "")
    stderr = str(completed.stderr or "")
    hops = _parse_hops(stdout)
    if completed.returncode == 0 and hops:
        state = "success"
    elif completed.returncode == 0:
        state = "empty"
    elif hops:
        state = "partial"
    else:
        state = "failed"
    return {"state": state, "target": host, "hops": hops, "stdout": stdout, "stderr": stderr, "error": "" if state in {"success", "empty", "partial"} else f"exit:{completed.returncode}"}


def display(result: dict[str, Any]) -> None:
    table = Table(title=f"Traceroute: {result.get('target', '')}", show_header=True)
    table.add_column("Hop")
    table.add_column("Detail")
    for row in result.get("hops", []):
        table.add_row(str(row.get("hop", "")), str(row.get("detail", "")))
    console.print(table)
    console.print(f"State: {result.get('state', 'unknown')}")


def main(target: str, timeout: int = DEFAULT_TIMEOUT, max_hops: int = DEFAULT_MAX_HOPS) -> int:
    result = trace(target, timeout, max_hops)
    if result["state"] in {"success", "empty", "partial"}:
        display(result)
        return 0 if result["state"] != "failed" else 2
    console.print(f"[yellow]Traceroute unavailable: {result['state']} ({result.get('error', '')})[/yellow]")
    return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ah-Puch bounded traceroute")
    parser.add_argument("target")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-hops", type=int, default=DEFAULT_MAX_HOPS)
    args = parser.parse_args()
    raise SystemExit(main(args.target, args.timeout, args.max_hops))
