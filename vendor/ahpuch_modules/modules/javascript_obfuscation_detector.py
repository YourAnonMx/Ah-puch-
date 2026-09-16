#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, web_target_base, write_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"
DEFAULT_MAX = 75
PARTIAL_EXIT_CODE = 3
PAT_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.I)
PAT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
KEYWORDS = (
    "eval(", "Function(", "atob(", "unescape(", r"\\x",
    "_0x", "fromCharCode", "CryptoJS",
)


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – JavaScript Obfuscation Detector")
    console.print(f"[{TEAL}]{bar}\n")


def _host_in_scope(seed: str, candidate: str, include_subdomains: bool) -> bool:
    try:
        root = urlparse(seed)
        item = urlparse(candidate)
    except ValueError:
        return False
    root_host = (root.hostname or "").lower().rstrip(".")
    item_host = (item.hostname or "").lower().rstrip(".")
    if not root_host or not item_host or item.scheme not in {"http", "https"}:
        return False
    if item.scheme != root.scheme:
        return False
    if include_subdomains:
        return item_host == root_host or item_host.endswith("." + root_host)
    return item.netloc.lower() == root.netloc.lower()


def fetch_url(url, timeout):
    target = str(url or "").strip()
    if not target:
        return {"url": url or "", "state": "inapplicable", "text": ""}
    try:
        response = requests.get(target, timeout=timeout, verify=True, allow_redirects=False)
    except (requests.RequestException, OSError, ValueError) as exc:
        return {"url": target, "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "text": ""}
    if not response.ok:
        return {"url": target, "state": "http-negative", "status": int(response.status_code), "text": ""}
    return {"url": target, "state": "success", "status": int(response.status_code), "text": response.text or ""}


def crawl(seed, max_pages, include_subs, timeout):
    if not str(seed or "").strip() or max_pages <= 0:
        return [], []
    queue = deque([seed])
    seen = {seed}
    pages = []
    probes = []

    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total} pages"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Crawling…", total=max_pages)
        while queue and len(probes) < max_pages:
            url = queue.popleft()
            probe = fetch_url(url, timeout)
            probes.append({key: value for key, value in probe.items() if key != "text"})
            progress.advance(task)
            if probe.get("state") != "success":
                continue
            text = str(probe.get("text", ""))
            pages.append((url, text))
            for match in PAT_HREF.finditer(text):
                link = urljoin(url, match.group(1))
                if _host_in_scope(seed, link, include_subs) and link not in seen:
                    seen.add(link)
                    queue.append(link)
    return pages, probes


def extract_script_urls(pages, max_scripts, seed, include_subdomains=False):
    seen = set()
    discovered = []
    permitted = []
    for base, html in pages:
        for match in PAT_SRC.finditer(html):
            full = urljoin(base, match.group(1).strip())
            if full in seen:
                continue
            seen.add(full)
            discovered.append(full)
            if _host_in_scope(seed, full, include_subdomains):
                permitted.append(full)
                if len(permitted) >= max_scripts:
                    return discovered, permitted
    return discovered, permitted


def score_script(text):
    if not text:
        return 0, "Empty"
    length = len(text)
    lines = max(1, text.count("\n"))
    avg_len = length / lines
    nonalnum = sum(1 for char in text if not char.isalnum() and not char.isspace())
    pct_non = nonalnum / length
    has_packed = any(keyword in text for keyword in KEYWORDS)
    has_hex = bool(re.search(r"\\x[0-9A-Fa-f]{2}", text))
    has_unicode = len(re.findall(r"\\u[0-9A-Fa-f]{4}", text)) > 50
    score = 0
    score += 4 if has_packed else 0
    score += 2 if has_hex else 0
    score += 2 if has_unicode else 0
    score += 2 if pct_non > 0.4 else 0
    score += 1 if avg_len > 500 else 0
    score += 1 if length > 250_000 else 0

    if score >= 9:
        label = "Highly Obfuscated"
    elif score >= 6:
        label = "Obfuscated"
    elif score >= 3:
        label = "Minified"
    else:
        label = "Readable"
    return score, label


def run(target, threads, opts):
    banner()
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        max_pages = max(1, min(int(opts.get("max_pages", 50)), 500))
        max_scripts = max(1, min(int(opts.get("max_scripts", DEFAULT_MAX)), 500))
        workers = max(1, min(int(threads), 64))
        include_subs = bool(opts.get("include_subdomains", False))
        seed = web_target_base(target)
    except (TypeError, ValueError) as exc:
        console.print(f"[red][!] Invalid target/options: {exc}[/red]")
        return 2
    domain = urlparse(seed).hostname or clean_domain_input(target)

    pages, page_probes = crawl(seed, max_pages, include_subs, timeout)
    console.print(f"[white]* Crawled [cyan]{len(pages)}[/cyan] successful pages (include_subs={include_subs})[/white]\n")

    discovered_scripts, scripts = extract_script_urls(pages, max_scripts, seed, include_subs)
    console.print(f"[white]* Discovered [cyan]{len(discovered_scripts)}[/cyan] scripts; [cyan]{len(scripts)}[/cyan] remain in-scope[/white]\n")

    fetched = []
    script_probes = []
    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total} scripts"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Fetching scripts…", total=len(scripts))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for probe in pool.map(lambda url: fetch_url(url, timeout), scripts):
                script_probes.append({key: value for key, value in probe.items() if key != "text"})
                fetched.append(str(probe.get("text", "")) if probe.get("state") == "success" else "")
                progress.advance(task)

    rows = []
    structured_rows = []
    for url, text, probe in zip(scripts, fetched, script_probes):
        if probe.get("state") != "success":
            continue
        score, label = score_script(text)
        rows.append((url, str(len(text)), str(score), label))
        structured_rows.append({"url": url, "bytes": len(text), "score": score, "assessment": label})

    table = Table(title=f"JS Obfuscation – {domain}", header_style="bold white")
    table.add_column("Script", style="cyan", overflow="fold")
    table.add_column("Bytes", style="green", justify="right")
    table.add_column("Score", style="yellow", justify="right")
    table.add_column("Assessment", style="white")
    for row in rows:
        table.add_row(*row)
    console.print(table)

    probes = [*page_probes, *script_probes]
    completed = sum(row.get("state") in {"success", "http-negative"} for row in probes)
    errors = sum(row.get("state") == "transport-error" for row in probes)
    Path("javascript_obfuscation_detector.json").write_text(
        json.dumps(
            {
                "target": seed,
                "probes": probes,
                "discovered_scripts": discovered_scripts,
                "scripts": scripts,
                "assessments": structured_rows,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if opts.get("export_txt", False) or EXPORT_SETTINGS.get("enable_txt_export", False):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out_dir, "js_obfuscation.txt"), export_console.export_text())

    if completed == 0 and errors:
        return 2
    if completed and errors:
        return PARTIAL_EXIT_CODE
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(1)
    target = sys.argv[1]
    threads = sys.argv[2] if len(sys.argv) > 2 else "8"
    try:
        options = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        options = {}
    raise SystemExit(run(target, threads, options))
