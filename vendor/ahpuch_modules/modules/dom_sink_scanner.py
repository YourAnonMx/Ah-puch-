#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import random
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, web_target_base, write_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()
PARTIAL_EXIT_CODE = 3

JS_EXT_RE = re.compile(r"\.js($|\?)", re.I)
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)
INLINE_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)

SINK_PATTERNS = {
    "eval": re.compile(r"\beval\s*\(", re.I),
    "innerHTML": re.compile(r"\binnerHTML\s*=", re.I),
    "outerHTML": re.compile(r"\bouterHTML\s*=", re.I),
    "document.write": re.compile(r"\bdocument\.write\s*\(", re.I),
    "setTimeout": re.compile(r"\bsetTimeout\s*\(", re.I),
    "setInterval": re.compile(r"\bsetInterval\s*\(", re.I),
    "Function": re.compile(r"\bnew\s+Function\s*\(", re.I),
    "location.assign": re.compile(r"\blocation\.assign\s*\(", re.I),
    "location.replace": re.compile(r"\blocation\.replace\s*\(", re.I),
    "insertAdjacentHTML": re.compile(r"\binsertAdjacentHTML\s*\(", re.I),
}


def banner():
    border = "=" * 44
    console.print(f"[cyan]{border}")
    console.print("[cyan]     Ah-Puch – DOM Sink Scanner")
    console.print(f"[cyan]{border}\n")


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


def fetch_page(url, timeout):
    if not str(url or "").strip():
        return {"url": url or "", "state": "inapplicable", "text": ""}
    try:
        response = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
    except (requests.RequestException, OSError, ValueError) as exc:
        return {"url": url, "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "text": ""}
    if not response.ok:
        return {"url": url, "state": "http-negative", "status": int(response.status_code), "text": ""}
    return {"url": url, "state": "success", "status": int(response.status_code), "text": response.text or ""}


def crawl(root, max_pages, timeout, workers):
    if not str(root or "").strip() or max_pages <= 0:
        return [], []
    workers = max(1, min(int(workers), 64))
    pages = []
    observations = []
    seen = {root}
    queue = [root]
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Crawling pages…", total=max_pages, url=root)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            while queue and len(observations) < max_pages:
                url = queue.pop(0)
                futures[pool.submit(fetch_page, url, timeout)] = url
                for fut in as_completed(list(futures)):
                    probe = fut.result()
                    u = str(probe.get("url", futures[fut]))
                    html = str(probe.get("text", ""))
                    observations.append({key: value for key, value in probe.items() if key != "text"})
                    prog.update(task, advance=1, url=u)
                    del futures[fut]
                    if probe.get("state") == "success":
                        pages.append((u, html))
                        for link in re.findall(r'href=["\']([^"\'#]+)', html):
                            full = urljoin(u, link)
                            if same_origin(root, full) and full not in seen:
                                seen.add(full)
                                queue.append(full)
                    if len(observations) >= max_pages:
                        break
            for fut in as_completed(futures):
                probe = fut.result()
                observations.append({key: value for key, value in probe.items() if key != "text"})
                if probe.get("state") == "success":
                    pages.append((str(probe.get("url", futures[fut])), str(probe.get("text", ""))))
    return pages[:max_pages], observations[:max_pages]


def extract_scripts(html, base_url):
    scripts = [urljoin(base_url, src) for src in SCRIPT_SRC_RE.findall(html)]
    inline = [m.group(1) for m in INLINE_SCRIPT_RE.finditer(html)]
    return scripts, inline


def fetch_script(url, timeout):
    return fetch_page(url, timeout)


def detect_sinks(code):
    hits = []
    for name, pat in SINK_PATTERNS.items():
        for i, line in enumerate(code.splitlines(), 1):
            if pat.search(line):
                hits.append((name, i, line.strip()[:120]))
    return hits


def run(target, threads, opts):
    banner()
    start = time.time()
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        pages = max(1, min(int(opts.get("max_pages", 75)), 500))
        sample_ratio = max(0.0, min(float(opts.get("sample_ratio", 0.3)), 1.0))
        workers = max(1, min(int(threads), 64))
        root = web_target_base(target)
    except (TypeError, ValueError) as exc:
        console.print(f"[red][!] Invalid target/options: {exc}[/red]")
        return 2
    domain = urlparse(root).hostname or clean_domain_input(target)

    html_pages, page_probes = crawl(root, pages, timeout, workers)
    console.print(f"[white]* Crawled [green]{len(html_pages)}[/green] successful pages\n")

    discovered_scripts = []
    scripts_to_fetch = []
    inline_codes = []
    for url, html in html_pages:
        scripts, inline = extract_scripts(html, url)
        discovered_scripts.extend(scripts)
        scripts_to_fetch.extend(script for script in scripts if same_origin(root, script))
        inline_codes.extend(inline)

    discovered_scripts = list(dict.fromkeys(discovered_scripts))
    scripts_to_fetch = list(dict.fromkeys(scripts_to_fetch))
    sample_count = min(len(scripts_to_fetch), max(1, int(len(scripts_to_fetch) * sample_ratio)))
    sampled = random.sample(scripts_to_fetch, sample_count) if sample_count else []

    console.print(f"[white]* Discovered [green]{len(discovered_scripts)}[/green] scripts; fetching [green]{len(sampled)}[/green] in-scope scripts\n")
    all_codes = inline_codes[:]
    script_probes = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Loading scripts…", total=len(sampled), url=sampled[0] if sampled else "-")
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(fetch_script, url, timeout): url for url in sampled}
            for fut in as_completed(futures):
                probe = fut.result()
                url = futures[fut]
                script_probes.append({key: value for key, value in probe.items() if key != "text"})
                prog.update(task, advance=1, url=url)
                if probe.get("state") == "success":
                    all_codes.append(str(probe.get("text", "")))

    results = []
    sink_counter = Counter()
    for code in all_codes:
        for name, line, snippet in detect_sinks(code):
            results.append((name, line, snippet))
            sink_counter[name] += 1

    table = Table(title=f"DOM Sink Findings – {domain}", header_style="bold magenta", box=box.MINIMAL)
    table.add_column("Sink", style="cyan")
    table.add_column("Line", style="green")
    table.add_column("Snippet", style="yellow", overflow="fold")
    for name, line, snippet in results:
        table.add_row(name, str(line), snippet)

    probes = [*page_probes, *script_probes]
    completed = sum(row.get("state") in {"success", "http-negative"} for row in probes)
    errors = sum(row.get("state") == "transport-error" for row in probes)
    if results:
        console.print(table)
    elif completed:
        console.print("[green]No dangerous sinks detected in completed observations[/green]")
    else:
        console.print("[red]No DOM sink observation completed[/red]")

    summary = (
        f"Pages: {len(html_pages)}  Scripts: {len(sampled)}  "
        f"Sinks: {len(results)}  Transport errors: {errors}  Top sinks: "
        + ", ".join(f"{key}:{value}" for key, value in sink_counter.most_common(3))
        + f"  Elapsed: {time.time() - start:.2f}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))

    payload = {
        "target": root,
        "probes": probes,
        "discovered_scripts": discovered_scripts,
        "sampled_scripts": sampled,
        "findings": [
            {"sink": name, "line": line, "snippet": snippet}
            for name, line, snippet in results
        ],
    }
    Path("dom_sink_scanner.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        if results:
            export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "dom_sink_scan.txt"), export_console.export_text())

    if completed == 0 and errors:
        return 2
    if completed and errors:
        return PARTIAL_EXIT_CODE
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        raise SystemExit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        opts = {}
    raise SystemExit(run(tgt, thr, opts))
