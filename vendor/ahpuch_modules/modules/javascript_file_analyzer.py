#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
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
PARTIAL_EXIT_CODE = 3

PAT_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
PAT_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)
PAT_SECRET = re.compile(
    r"(?:AWS|AKIA|ASIA)[A-Z0-9]{16,}|"
    r"AIza[0-9A-Za-z-_]{35}|"
    r"xox[baprs]-[0-9a-zA-Z]{10,48}|"
    r"sk_live_[0-9a-zA-Z]{24,}|"
    r"(?:api[_-]?key|secret|token|bearer)[\"'=\s:]{1,10}[A-Za-z0-9_\-]{8,}",
    re.I,
)
PAT_SCRIPT_SRC = re.compile(r"<script[^>]+src=['\"]([^'\"#]+)['\"]", re.I)


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]          Ah-Puch – JavaScript Analyzer")
    console.print(f"[{TEAL}]{bar}")


def same_origin(root: str, candidate: str) -> bool:
    try:
        left = urlparse(root)
        right = urlparse(candidate)
    except ValueError:
        return False
    return (
        right.scheme in {"http", "https"}
        and left.scheme == right.scheme
        and left.netloc.lower() == right.netloc.lower()
    )


def fetch(url, timeout):
    if not str(url or "").strip():
        return {"url": url, "state": "invalid-target", "error": "empty url", "text": ""}
    try:
        response = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
    except (requests.RequestException, OSError) as exc:
        return {"url": url, "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "text": ""}
    is_js = "javascript" in response.headers.get("Content-Type", "").lower() or url.lower().endswith(".js")
    if response.status_code != 200:
        return {"url": url, "state": "http-negative", "status": int(response.status_code), "text": ""}
    if url.lower().endswith(".js") and not is_js:
        return {"url": url, "state": "http-negative", "status": int(response.status_code), "reason": "non-javascript-content-type", "text": ""}
    return {"url": url, "state": "success", "status": int(response.status_code), "text": response.text or ""}


def extract(base_html, base_url):
    return list(dict.fromkeys(urljoin(base_url, match.group(1).strip()) for match in PAT_SCRIPT_SRC.finditer(base_html)))[:150]


def analyse(text):
    return PAT_URL.findall(text), PAT_SECRET.findall(text), PAT_EMAIL.findall(text)


def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    threads = max(1, int(threads))
    if not str(target or "").strip():
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return 0
    base = web_target_base(target)
    domain = urlparse(base).hostname or clean_domain_input(target)

    base_probe = fetch(base, timeout)
    probes = [{key: value for key, value in base_probe.items() if key != "text"}]
    if base_probe.get("state") != "success":
        Path("javascript_file_analyzer.json").write_text(
            json.dumps({"target": base, "probes": probes, "findings": []}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if base_probe.get("state") == "transport-error":
            console.print("[red]✖ Unable to retrieve main page due to transport failure[/red]")
            return 2
        console.print("[yellow]Main page returned a completed non-200 observation[/yellow]")
        return 0

    html = str(base_probe.get("text", ""))
    discovered_scripts = extract(html, base)
    scripts = [url for url in discovered_scripts if same_origin(base, url)]
    console.print(f"[white]* {len(discovered_scripts)} external <script> discovered; {len(scripts)} remain in-scope[/white]")

    payloads = [(base, html)]
    if scripts:
        with Progress(SpinnerColumn(), TextColumn("Downloading…"), BarColumn(), console=console, transient=True) as progress:
            task = progress.add_task("", total=len(scripts))
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                for probe in pool.map(lambda url: fetch(url, timeout), scripts):
                    probes.append({key: value for key, value in probe.items() if key != "text"})
                    if probe.get("state") == "success":
                        payloads.append((str(probe.get("url", "")), str(probe.get("text", ""))))
                    progress.advance(task)

    findings = [analyse(text) for _source, text in payloads]
    total_urls = sum(len(row[0]) for row in findings)
    total_secrets = sum(len(row[1]) for row in findings)
    total_emails = sum(len(row[2]) for row in findings)

    table = Table(title=f"JS Analyzer – {domain}", header_style="bold white")
    table.add_column("Scripts")
    table.add_column("URLs")
    table.add_column("Secrets")
    table.add_column("Emails")
    table.add_row(str(len(scripts)), str(total_urls), str(total_secrets), str(total_emails))
    console.print(table)

    detail = Table(title="Findings detail", header_style="bold white")
    detail.add_column("Source", style="cyan", overflow="fold")
    detail.add_column("Type", style="green")
    detail.add_column("Value", style="yellow", overflow="fold")
    structured_findings = []
    for (source, _text), (urls, secrets, emails) in zip(payloads, findings):
        for value in urls:
            detail.add_row(source, "URL", value)
            structured_findings.append({"source": source, "type": "URL", "value": value})
        for value in secrets:
            detail.add_row(source, "Secret", value)
            structured_findings.append({"source": source, "type": "Secret", "value": value})
        for value in emails:
            detail.add_row(source, "Email", value)
            structured_findings.append({"source": source, "type": "Email", "value": value})
    if structured_findings:
        console.print(detail)

    errors = sum(row.get("state") == "transport-error" for row in probes)
    completed = sum(row.get("state") in {"success", "http-negative"} for row in probes)
    Path("javascript_file_analyzer.json").write_text(
        json.dumps(
            {
                "target": base,
                "probes": probes,
                "discovered_scripts": discovered_scripts,
                "scripts": scripts,
                "findings": structured_findings,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=160)
        export_console.print(detail if detail.row_count else table)
        write_to_file(os.path.join(out, "js_analysis.txt"), export_console.export_text())

    if completed == 0 and errors:
        return 2
    if completed and errors:
        return PARTIAL_EXIT_CODE
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(1)
    target = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 12
    try:
        options = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        options = {}
    raise SystemExit(run(target, threads, options))
