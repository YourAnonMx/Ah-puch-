#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from colorama import init
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input, web_target_base

init(autoreset=True)
console = Console()
requests.packages.urllib3.disable_warnings()

DEFAULT_MAX_PAGES = 100
DEFAULT_INCLUDE_SUBDOMAINS = False
COMMON_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/playground", "/graph", "/explorer"]
PARTIAL_EXIT_CODE = 3
ERROR_STATES = {"transport-error", "parse-error", "internal-error"}
COMPLETED_STATES = {"success", "graphql-negative", "http-negative"}


def banner():
    console.print("""
    =============================================
       Ah-Puch - GraphQL Introspection Probe
    =============================================
    """)


def parse_opts(argv):
    max_pages = DEFAULT_MAX_PAGES
    include_subs = DEFAULT_INCLUDE_SUBDOMAINS
    i = 3
    while i < len(argv):
        arg = argv[i]
        if arg == "--max-pages" and i + 1 < len(argv):
            try:
                max_pages = int(argv[i + 1])
            except (TypeError, ValueError):
                pass
            i += 2
            continue
        if arg == "--include-subdomains" and i + 1 < len(argv):
            include_subs = argv[i + 1] not in ("0", "false", "False", "no")
            i += 2
            continue
        i += 1
    return max_pages, include_subs


def normalize_base(target):
    return web_target_base(target).rstrip("/") + "/"


def same_domain(url, base_netloc, include_subs):
    netloc = urlparse(url).netloc.lower()
    if not netloc:
        return True
    if netloc == base_netloc:
        return True
    if include_subs and netloc.endswith("." + base_netloc):
        return True
    return False


def extract_links(html, base):
    return [urljoin(base, match.group(2)) for match in re.finditer(r'''(src|href)=["']([^"'#]+)''', html, re.I)]


def crawl(base_url, max_pages, include_subs):
    if not str(base_url or "").strip() or max_pages <= 0:
        return [], []
    base_netloc = urlparse(base_url).netloc.lower()
    seen = set()
    queue = [base_url]
    urls = []
    probes = []
    while queue and len(probes) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False)
        except (requests.RequestException, OSError, ValueError) as exc:
            probes.append({"url": url, "state": "transport-error", "error": f"{type(exc).__name__}: {exc}"})
            continue
        state = "success" if response.ok else "http-negative"
        probes.append({"url": url, "state": state, "status": int(response.status_code)})
        urls.append(url)
        if state != "success":
            continue
        content_type = response.headers.get("Content-Type", "")
        if "text/html" in content_type:
            for link in extract_links(response.text, url):
                if same_domain(link, base_netloc, include_subs) and link not in seen:
                    queue.append(link)
    return urls, probes


def candidate_paths(base, urls):
    candidates = set(urljoin(base, path.lstrip("/")) for path in COMMON_PATHS)
    for url in urls:
        if "graphql" in url.lower() or "graphiql" in url.lower() or "playground" in url.lower():
            candidates.add(url)
    return sorted(candidates)


def gql_post(url, query, variables=None):
    if not str(url or "").strip():
        return {"url": url, "state": "transport-error", "error": "empty URL", "response": None}
    data = {"query": query}
    if variables is not None:
        data["variables"] = variables
    try:
        response = requests.post(
            url,
            json=data,
            timeout=DEFAULT_TIMEOUT,
            verify=True,
            allow_redirects=False,
            headers={"Content-Type": "application/json"},
        )
    except (requests.RequestException, OSError, ValueError) as exc:
        return {"url": url, "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "response": None}
    if not response.ok:
        return {"url": url, "state": "http-negative", "status": int(response.status_code), "response": response}
    return {"url": url, "state": "success", "status": int(response.status_code), "response": response}


def minimal_probe(url):
    probe = gql_post(url, "query{__typename}")
    if probe["state"] != "success":
        return {key: value for key, value in probe.items() if key != "response"} | {"graphql": False, "json": None}
    response = probe["response"]
    try:
        payload = response.json()
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "url": url,
            "state": "parse-error",
            "status": probe.get("status"),
            "error": f"{type(exc).__name__}: {exc}",
            "graphql": False,
            "json": None,
        }
    graphql = bool(
        (isinstance(payload, dict) and isinstance(payload.get("data"), dict) and "__typename" in payload["data"])
        or (isinstance(payload, dict) and "errors" in payload and any("__typename" in str(error) for error in payload["errors"]))
    )
    return {
        "url": url,
        "state": "success" if graphql else "graphql-negative",
        "status": probe.get("status"),
        "graphql": graphql,
        "json": payload,
    }


def introspect(url):
    query = "query Introspect{__schema{types{name kind fields{name} interfaces{name} possibleTypes{name}} queryType{name} mutationType{name} subscriptionType{name}}}"
    probe = gql_post(url, query)
    if probe["state"] != "success":
        return {key: value for key, value in probe.items() if key != "response"} | {"json": None}
    try:
        payload = probe["response"].json()
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "url": url,
            "state": "parse-error",
            "status": probe.get("status"),
            "error": f"{type(exc).__name__}: {exc}",
            "json": None,
        }
    return {"url": url, "state": "success", "status": probe.get("status"), "json": payload}


def summarize_schema(payload):
    if not payload or "data" not in payload or "__schema" not in payload["data"]:
        return 0, 0, 0
    schema = payload["data"]["__schema"]
    types = schema.get("types") or []
    field_count = sum(len(item.get("fields") or []) for item in types)
    mutation_count = 1 if schema.get("mutationType") else 0
    return len(types), field_count, mutation_count


def terminal_code(probes):
    completed = sum(row.get("state") in COMPLETED_STATES for row in probes)
    errors = sum(row.get("state") in ERROR_STATES for row in probes)
    if completed == 0 and errors:
        return 2
    if completed and errors:
        return PARTIAL_EXIT_CODE
    return 0


def run(target, max_pages=DEFAULT_MAX_PAGES, include_subs=DEFAULT_INCLUDE_SUBDOMAINS):
    try:
        base = normalize_base(target)
        max_pages = max(1, min(int(max_pages), 500))
    except (TypeError, ValueError) as exc:
        console.print(f"[red][!] Invalid target/options: {exc}[/red]")
        return 2
    domain = urlparse(base).hostname or clean_domain_input(target)
    console.print(f"[white][*] Crawling up to {max_pages} pages (include_subdomains={include_subs}).[/white]")
    urls, crawl_probes = crawl(base, max_pages, include_subs)
    candidates = candidate_paths(base, urls)
    rows = []
    probes = list(crawl_probes)
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True)
    with progress:
        task = progress.add_task("Probing GraphQL", total=len(candidates))
        for url in candidates:
            minimal = minimal_probe(url)
            probes.append({key: value for key, value in minimal.items() if key != "json"})
            introspection = None
            type_count = field_count = mutation_count = 0
            if minimal.get("graphql"):
                introspection = introspect(url)
                probes.append({key: value for key, value in introspection.items() if key != "json"})
                if introspection.get("state") == "success":
                    type_count, field_count, mutation_count = summarize_schema(introspection.get("json"))
            rows.append((url, "Y" if minimal.get("graphql") else "N", str(type_count), str(field_count), str(mutation_count)))
            progress.advance(task)

    table = Table(title=f"GraphQL Introspection Probe: {domain}", show_header=True, header_style="bold magenta")
    table.add_column("Endpoint", style="cyan", overflow="fold")
    table.add_column("GraphQL?", style="green")
    table.add_column("Types", style="yellow")
    table.add_column("Fields", style="white")
    table.add_column("Mutation", style="blue")
    for row in rows:
        table.add_row(*row)
    console.print(table)

    Path("graphql_introspection_probe.json").write_text(
        json.dumps(
            {
                "target": base,
                "crawl_urls": urls,
                "candidates": candidates,
                "probes": probes,
                "rows": [
                    {"endpoint": row[0], "graphql": row[1] == "Y", "types": int(row[2]), "fields": int(row[3]), "mutation": int(row[4])}
                    for row in rows
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    console.print("[white][*] GraphQL introspection probing completed.[/white]")
    return terminal_code(probes)


if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        raise SystemExit(1)
    max_pages, include_subdomains = parse_opts(sys.argv)
    raise SystemExit(run(sys.argv[1], max_pages, include_subdomains))
