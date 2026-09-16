#!/usr/bin/env python3
import os, sys, json, time, itertools
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

console = Console()

DEFAULT_PATHS = [
    "/api/","/api/v1/","/api/v2/","/api/v3/","/v1/","/v2/","/v3/","/rest/","/rest/v1/",
    "/graphql","/api/graphql","/ws","/socket.io/","/json","/data","/export","/internal",
    "/admin/api/","/mobileapi/","/public/api/","/status","/health","/metrics","/openapi.json",
]
DEFAULT_METHODS = ["GET","POST","PUT","DELETE","OPTIONS","PATCH"]

UA = "Ah-Puch-API-Scanner/1.0 (+https://example.local)"

def new_session(timeout: int):
    sess = requests.Session()
    retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=False)
    adapter = HTTPAdapter(max_retries=retries, pool_connections=100, pool_maxsize=100)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update({"User-Agent": UA, "Accept": "*/*"})
    sess.verify=True
    sess.timeout = timeout
    return sess

def is_json_like(resp: requests.Response):
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "json" in ctype: return True
    txt = resp.text.strip()
    return (txt.startswith("{") and txt.endswith("}")) or (txt.startswith("[") and txt.endswith("]"))

def best_base(domain: str, timeout: int):
    if not isinstance(domain, str) or not domain.strip():
        return None
    sess = new_session(timeout)
    for scheme in ("https","http"):
        try:
            r = sess.get(f"{scheme}://{domain}", allow_redirects=False, timeout=timeout)
            if r.url: return r.url.rstrip("/")
        except (OSError, requests.RequestException, TypeError, ValueError):
            continue
    return None

def expand_candidates(base: str, paths):
    items = []
    for p in paths:
        p = ("/" + p.lstrip("/")) if p else "/"
        u = urljoin(base + "/", p.lstrip("/"))
        items.append(u)
        if not u.endswith("/"):
            items.append(u + "/")
    seen = set(); out = []
    for u in items:
        if u not in seen:
            out.append(u); seen.add(u)
    return out

def risk_from(resp: requests.Response):
    status = resp.status_code
    acao = resp.headers.get("Access-Control-Allow-Origin","") or ""
    acac = resp.headers.get("Access-Control-Allow-Credentials","") or ""
    allow = resp.headers.get("Allow","") or ""
    wwwa  = resp.headers.get("WWW-Authenticate","") or ""
    j = is_json_like(resp)
    score = 0
    if status in (200, 204): score += 1
    if j: score += 1
    if acao == "*" and acac.lower() in ("true","1"): score += 3
    elif acao == "*": score += 1
    if status in (401,): score += 0  # auth required
    if status in (403,): score += 0
    if "OPTIONS" in allow and acao: score += 1
    level = "Low"
    if score >= 4: level = "High"
    elif score >= 2: level = "Medium"
    return level

def probe(sess: requests.Session, url: str, method: str, timeout: int):
    try:
        if method == "GET":
            r = sess.get(url, allow_redirects=False, timeout=timeout)
        elif method == "POST":
            r = sess.post(url, json={}, allow_redirects=False, timeout=timeout)
        elif method == "PUT":
            r = sess.put(url, json={}, allow_redirects=False, timeout=timeout)
        elif method == "DELETE":
            r = sess.delete(url, allow_redirects=False, timeout=timeout)
        elif method == "OPTIONS":
            r = sess.options(url, allow_redirects=False, timeout=timeout)
        elif method == "PATCH":
            r = sess.patch(url, json={}, allow_redirects=False, timeout=timeout)
        else:
            r = sess.request(method, url, allow_redirects=False, timeout=timeout)
        clen = r.headers.get("Content-Length")
        size = int(clen) if clen and clen.isdigit() else len(r.content or b"")
        jsonish = "Y" if is_json_like(r) else "N"
        acao = r.headers.get("Access-Control-Allow-Origin","-")
        acac = r.headers.get("Access-Control-Allow-Credentials","-")
        risk = risk_from(r)
        return (url, method, str(r.status_code), str(size), jsonish, acao, acac, risk)
    except (AttributeError, OSError, requests.RequestException, TypeError, ValueError):
        return (url, method, "ERR", "0", "N", "-", "-", "-")

def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/] api_probe.py <domain> [threads] [opts_json]")
        sys.exit(1)

    domain = clean_domain_input(sys.argv[1])
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 50
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError):
        opts = {}

    timeout = min(max(int(opts.get("timeout", DEFAULT_TIMEOUT)), 1), 60)
    threads = min(max(threads, 1), 32)
    custom_paths = opts.get("paths") or []
    wl_file = opts.get("wordlist")
    if wl_file and os.path.isfile(wl_file):
        try:
            with open(wl_file, "r", encoding="utf-8", errors="ignore") as f:
                custom_paths.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])
        except Exception:
            pass
    paths = list(dict.fromkeys((custom_paths or []) + DEFAULT_PATHS))
    methods = list(dict.fromkeys([m.upper() for m in (opts.get("methods") or DEFAULT_METHODS)]))

    console.print(f"[white]* Target:[/] [cyan]{domain}[/cyan]")
    base = best_base(domain, timeout)
    if not base:
        console.print("[red]✖ Unable to reach domain base (http/https).[/red]")
        sys.exit(1)
    console.print(f"[white]* Base:[/] {base}")
    candidates = expand_candidates(base, paths)
    console.print(f"[white]* Probing candidates:[/] {len(candidates)}   [white]Methods:[/] {', '.join(methods)}")

    sess = new_session(timeout)
    results = []
    total = len(candidates) * len(methods)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Probing API endpoints", total=total)
        with ThreadPoolExecutor(max_workers=threads) as exe:
            futs = [exe.submit(probe, sess, u, m, timeout) for u, m in itertools.product(candidates, methods)]
            for f in as_completed(futs):
                results.append(f.result())
                prog.advance(task)

    hits = []
    for url, method, status, size, jsonish, acao, acac, risk in results:
        if status == "ERR":
            continue
        code = int(status) if status.isdigit() else 0
        if jsonish == "Y" or code in (200, 201, 202, 204, 301, 302, 307, 308, 401, 403):
            hits.append((url, method, status, size, jsonish, acao, acac, risk))

    if not hits:
        console.print("[yellow]No responsive API endpoints detected in quick probe.[/yellow]")
        console.print("[white]* Tip:[/] provide a wordlist via opts: {'wordlist': '/path/to/endpoints.txt'}")
        sys.exit(0)

    def _rank(h):
        _, _, status, _, jsonish, acao, acac, risk = h
        rscore = {"High": 2, "Medium": 1, "Low": 0}.get(risk, 0)
        js = 1 if jsonish == "Y" else 0
        cors = 1 if (acao == "*" and acac.lower() in ("true","1")) else 0
        sc = int(status) if status.isdigit() else 0
        return (-rscore, -js, -cors, -(200 <= sc < 300), sc)

    hits.sort(key=_rank)

    table = Table(title=f"API Endpoint Exposure: {domain}", header_style="bold magenta", show_lines=False)
    table.add_column("URL", style="cyan", overflow="fold")
    table.add_column("Method", style="green", width=8)
    table.add_column("Status", style="yellow", width=7)
    table.add_column("Bytes", style="white", width=8)
    table.add_column("JSON", style="blue", width=6)
    table.add_column("ACAO", style="magenta", overflow="fold")
    table.add_column("ACAC", style="magenta", width=6)
    table.add_column("Risk", style="bold")

    for row in hits:
        url, method, status, size, jsonish, acao, acac, risk = row
        risk_style = "bold red" if risk == "High" else ("yellow" if risk == "Medium" else "green")
        table.add_row(url, method, status, size, jsonish, acao, acac, f"[{risk_style}]{risk}[/]")

    console.print(table)
    console.print(f"[green]* Done.[/] {len(hits)}/{total} interesting responses\n")

if __name__ == "__main__":
    main()
