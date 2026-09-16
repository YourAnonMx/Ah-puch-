#!/usr/bin/env python3
"""Bounded virtual-host differential probe for an explicitly active run."""
from __future__ import annotations

import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

import requests
from colorama import init
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input


init(autoreset=True)
console = Console()

WORDLIST = [
    "www", "app", "api", "admin", "portal", "login", "dev", "test", "stage", "staging",
    "prod", "production", "beta", "dashboard", "cpanel", "mail", "secure", "internal",
    "intranet", "vpn", "cdn", "assets", "static", "img", "files", "auth",
]
LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.I)


def banner() -> None:
    console.print("""
    =============================================
        Ah-Puch - Virtual Host Fuzzer
    =============================================
    """)


def _request(origin: str, host: str, timeout: int):
    """Connect to the admitted origin while varying only the HTTP Host header.

    The URL retains the target domain, so HTTPS uses its normal SNI and
    certificate validation. Redirects cannot expand scope.
    """
    if not str(origin or "").strip() or not str(host or "").strip():
        return None
    try:
        return requests.get(
            origin.rstrip("/") + "/",
            headers={"Host": host},
            timeout=timeout,
            verify=True,
            allow_redirects=False,
        )
    except (requests.RequestException, OSError, ValueError):
        return None


def base_origin(domain: str, timeout: int) -> str:
    for scheme in ("https", "http"):
        origin = f"{scheme}://{domain}"
        if _request(origin, domain, timeout) is not None:
            return origin
    return ""


def response_fingerprint(response) -> tuple[int, int, str] | None:
    if response is None:
        return None
    content = response.content or b""
    declared = response.headers.get("Content-Length", "")
    size = int(declared) if str(declared).isdigit() else len(content)
    title = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", content[:65536].decode(errors="ignore"), re.I | re.S)
    if match:
        title = " ".join(match.group(1).split())[:200]
    return int(response.status_code), size, title


def fetch_with_host(origin: str, host: str, timeout: int) -> tuple[str, int | str, int, str]:
    fingerprint = response_fingerprint(_request(origin, host, timeout))
    if fingerprint is None:
        return host, "ERR", 0, ""
    status, size, title = fingerprint
    return host, status, size, title


def _labels(path: str, limit: int) -> list[str]:
    if not path:
        return WORDLIST[:limit]
    candidate = Path(path).expanduser()
    if not candidate.is_file() or candidate.is_symlink():
        raise ValueError("wordlist must be a regular existing file")
    values = [
        value
        for raw in candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        if (value := raw.strip().casefold()) and LABEL.fullmatch(value)
    ]
    return list(dict.fromkeys(values))[:limit]


def discover_virtual_hosts(
    domain: str,
    origin: str,
    labels: list[str],
    *,
    timeout: int,
    threads: int,
) -> list[tuple[str, str, str, str]]:
    if not str(domain or "").strip() or not str(origin or "").strip():
        return []
    threads = max(1, min(int(threads), 64))
    baseline = fetch_with_host(origin, domain, timeout)
    control_host = f"ahpuch-nonexistent-control.{domain}"
    control = fetch_with_host(origin, control_host, timeout)
    if baseline[1] == "ERR":
        raise RuntimeError("baseline request failed")
    control_fingerprint = control[1:]
    candidates = list(dict.fromkeys(f"{label}.{domain}" for label in labels if LABEL.fullmatch(label)))
    results: list[tuple[str, int | str, int, str]] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(fetch_with_host, origin, host, timeout): host for host in candidates}
        for future in as_completed(futures):
            results.append(future.result())
    hits = [
        (host, str(code), str(size), title or "-")
        for host, code, size, title in results
        if code != "ERR" and (code, size, title) != control_fingerprint
    ]
    return sorted(hits)


def run(target: str, threads: int, opts: dict, wordlist_path: str = "") -> int:
    banner()
    domain = clean_domain_input(str(target or "")).split(":", 1)[0].strip().casefold().rstrip(".")
    if not domain or not all(LABEL.fullmatch(part) for part in domain.split(".")):
        console.print("[red][!] Invalid domain.[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        workers = max(1, min(int(opts.get("threads", threads)), 64))
        limit = max(1, min(int(opts.get("limit", len(WORDLIST))), 5000))
        labels = _labels(wordlist_path, limit)
    except (OSError, TypeError, ValueError) as exc:
        console.print(f"[red][!] Invalid options: {exc}[/red]")
        return 2
    if not labels:
        console.print("[yellow][!] The wordlist contains no valid DNS labels.[/yellow]")
        return 2
    origin = base_origin(domain, timeout)
    if not origin:
        console.print("[red][!] Unable to reach domain.[/red]")
        return 1

    console.print(f"[white][*] Fuzzing {len(labels)} virtual hosts through {urlsplit(origin).netloc}[/white]")
    try:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as progress:
            task = progress.add_task("Fuzzing", total=len(labels))
            hits = discover_virtual_hosts(domain, origin, labels, timeout=timeout, threads=workers)
            progress.update(task, completed=len(labels))
    except RuntimeError as exc:
        console.print(f"[red][!] {exc}[/red]")
        return 1

    table = Table(title=f"Virtual Host Findings: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Host", style="cyan", overflow="fold")
    table.add_column("Status", style="green")
    table.add_column("Size", style="yellow")
    table.add_column("Title", style="white", overflow="fold")
    for row in hits:
        table.add_row(*row)
    if hits:
        console.print(table)
    else:
        console.print("[yellow][!] No distinct virtual hosts discovered.[/yellow]")
    console.print("[white][*] Virtual host fuzzing completed.[/white]")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        console.print("[red][!] No domain provided.[/red]")
        return 2
    target = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    options: dict = {}
    wordlist = ""
    if len(sys.argv) > 2 and not sys.argv[2].isdigit() and os.path.isfile(sys.argv[2]):
        wordlist = sys.argv[2]
    if len(sys.argv) > 3:
        try:
            options = json.loads(sys.argv[3])
        except (json.JSONDecodeError, TypeError):
            console.print("[red][!] Invalid JSON options.[/red]")
            return 2
    return run(target, threads, options, wordlist)


if __name__ == "__main__":
    raise SystemExit(main())
