#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import urllib3
import concurrent.futures

from datetime import datetime
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

_DEFAULT_PATHS = [
    "/swagger.json","/swagger/v1/swagger.json","/swagger/v2/swagger.json",
    "/openapi.json","/openapi.yaml","/openapi.yml",
    "/api-docs","/v3/api-docs","/v2/api-docs",
    "/docs/json","/docs/swagger.json","/redoc",
    "/api/swagger.json","/api/openapi.json",
    "/.well-known/openapi.json","/.well-known/openapi.yaml"
]
_GQL_PATHS = ["/graphql","/api/graphql","/graphiql"]
_INTROSPECTION_PAYLOAD = {"query": "query { __schema { types { name } } }"}

def banner():
    border = "=" * 44
    console.print(f"[{TEAL}]{border}")
    console.print("[cyan]   Ah-Puch – API Schema Grabber")
    console.print(f"[{TEAL}]{border}")

def probe(url: str, timeout: int, json_body=None) -> tuple:
    if not str(url or "").strip():
        return url, "ERR", 0, "-", "-", 0
    start = time.time()
    try:
        if json_body:
            r = requests.post(url, json=json_body, timeout=timeout, verify=True, allow_redirects=False)
        else:
            r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        elapsed = int((time.time() - start) * 1000)
        status = r.status_code
        size = len(r.content or b"")
        ctype = r.headers.get("Content-Type", "-")
        text = r.text or ""
        kind = "-"
        if status == 200:
            if json_body and "__schema" in text:
                kind = "GraphQL"
            else:
                try:
                    j = r.json()
                    if any(k in j for k in ("swagger", "openapi")):
                        kind = "OpenAPI"
                    else:
                        kind = "JSON"
                except (TypeError, ValueError):
                    kind = "-"
        return url, status, size, ctype, kind, elapsed
    except (requests.RequestException, OSError, TypeError, ValueError):
        elapsed = int((time.time() - start) * 1000)
        return url, "ERR", 0, "-", "-", elapsed

def collect(base: str, paths: list, gql_paths: list, timeout: int, delay: float, workers: int):
    if not str(base or "").strip():
        return []
    workers = max(1, min(int(workers), 64))
    tasks = []
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        with Progress(SpinnerColumn(), TextColumn("[white]{task.fields[url]}", justify="right"), BarColumn(), console=console, transient=True) as progress:
            task = progress.add_task("Probing", total=len(paths) + len(gql_paths), url="")
            for p in paths:
                url = urljoin(base, p.lstrip("/"))
                futures = executor.submit(probe, url, timeout, None)
                tasks.append(futures)
            for p in gql_paths:
                url = urljoin(base, p.lstrip("/"))
                futures = executor.submit(probe, url, timeout, _INTROSPECTION_PAYLOAD)
                tasks.append(futures)
            for fut in concurrent.futures.as_completed(tasks):
                res = fut.result()
                results.append(res)
                progress.update(task, advance=1, url=res[0])
                if delay:
                    time.sleep(delay)
    return results

def run(target: str, threads: int, opts: dict):
    banner()
    dom = clean_domain_input(str(target or ""))
    if not dom:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        to = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        paths = list(opts.get("paths", _DEFAULT_PATHS))
        gql = list(opts.get("graphql_paths", _GQL_PATHS))
        delay = max(0.0, min(float(opts.get("delay", 0)), 10.0))
        workers = max(1, min(int(threads), 64))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid API schema options.[/red]")
        return 2

    console.print(f"[white]* Target: [bold]{dom}[/bold]  timeout: {to}s  paths:{len(paths)}  gql:{len(gql)}[/white]")

    base = None
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{dom}", timeout=to, verify=True, allow_redirects=False)
            base = r.url
            break
        except (requests.RequestException, OSError, ValueError):
            continue
    if not base:
        console.print("[red]✖ Cannot reach target[/red]")
        return 1

    rows = collect(base, paths, gql, to, delay, workers)

    table = Table(title=f"API Schema Grabber – {dom}", header_style="bold magenta", box=box.MINIMAL)
    table.add_column("URL",          style="cyan", overflow="fold")
    table.add_column("Status",       style="green")
    table.add_column("Bytes",        style="yellow", justify="right")
    table.add_column("Content-Type", style="white")
    table.add_column("Detected",     style="blue")
    table.add_column("Time(ms)",     style="magenta", justify="right")

    for url, status, size, ctype, kind, elapsed in rows:
        table.add_row(url, str(status), str(size), ctype, kind, str(elapsed))

    console.print(table)
    console.print("[green]* API Schema grab completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out_dir, "api_schema_grabber.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            opts = {}
    run(tgt, thr, opts)
