#!/usr/bin/env python3
import os
import sys
import json
import re
import time
import uuid
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from http.cookies import CookieError, SimpleCookie
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()

SET_COOKIE_SPLIT_RE = re.compile(r",(?!\s*[A-Za-z0-9_\-]+=)", re.S)

def banner():
    bar = "=" * 40
    console.print(f"[cyan]{bar}")
    console.print("[cyan]  Ah-Puch – Cookie Scope Diff Across Subdomains")
    console.print(f"[cyan]{bar}\n")

def parse_set_cookies(header_value):
    parts = SET_COOKIE_SPLIT_RE.split(header_value or "")
    out = []
    for p in parts:
        ck = SimpleCookie()
        try:
            ck.load(p.strip())
            for name in ck:
                morsel = ck[name]
                out.append((name, morsel))
        except (CookieError, TypeError, ValueError):
            continue
    return out

def attrs_from_morsel(m):
    return (
        m["domain"] or "-",
        m["path"] or "/",
        "Y" if m["secure"] else "-",
        "Y" if m["httponly"] else "-",
        m["samesite"] or "-"
    )

def risk_score(dom_attr, base_dom, secure, httponly):
    score = 0
    if dom_attr in ("-", base_dom) or dom_attr.endswith("." + base_dom):
        score += 2
    else:
        score += 1
    if secure == "-":
        score += 1
    if httponly == "-":
        score += 1
    return score

def fetch_and_parse(url, timeout, base_dom):
    if not isinstance(url, str) or not url.strip():
        return []
    try:
        r = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
        hdrs = r.raw.headers.get_all("Set-Cookie") if hasattr(r.raw.headers, "get_all") else r.headers.get("Set-Cookie", "")
        hdr_val = ",".join(hdrs) if isinstance(hdrs, list) else hdrs
        cookies = []
        for name, mors in parse_set_cookies(hdr_val):
            dom_attr, path, secure, httponly, samesite = attrs_from_morsel(mors)
            hosts = {urlparse(url).netloc.lower()}
            cookies.append((name, dom_attr, path, secure, httponly, samesite, hosts))
        return cookies
    except (AttributeError, CookieError, OSError, requests.RequestException, TypeError, ValueError):
        return []

def crawl(seed, limit, include_subdomains, timeout):
    if not isinstance(seed, str) or not seed.strip():
        return []
    try:
        limit = int(limit)
        timeout = float(timeout)
    except (TypeError, ValueError):
        return []
    if limit <= 0:
        return []
    limit = min(limit, 500)
    base_dom = urlparse(seed).netloc.lower()
    to_visit = [seed]
    seen = {seed}
    pages = []
    while to_visit and len(pages) < limit:
        url = to_visit.pop(0)
        try:
            r = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
        except (AttributeError, OSError, requests.RequestException, TypeError, ValueError):
            continue
        pages.append(url)
        if "html" in r.headers.get("Content-Type", "").lower():
            for m in re.finditer(r'(?:href|src)=["\']([^"\']+)', r.text, re.I):
                full = urljoin(url, m.group(1))
                nl = urlparse(full).netloc.lower()
                if nl and (nl == base_dom or (include_subdomains and nl.endswith("." + base_dom))) and full not in seen:
                    seen.add(full)
                    to_visit.append(full)
    return pages

def run(target, threads, opts):
    if not isinstance(target, str) or not target.strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    banner()
    start = time.time()
    domain = clean_domain_input(target)
    try:
        max_pages = int(opts.get("max_pages", 100))
    except (TypeError, ValueError):
        max_pages = 100
    max_pages = min(max(max_pages, 1), 500)
    raw_include_subs = opts.get("include_subdomains", 0)
    if isinstance(raw_include_subs, str):
        include_subs = raw_include_subs.strip().lower() in {"1", "true", "yes", "on"}
    else:
        include_subs = bool(raw_include_subs)
    try:
        threads = int(threads)
    except (TypeError, ValueError):
        threads = 1
    threads = min(max(threads, 1), 32)
    base = target if "://" in target else f"https://{domain}"
    base_dom = urlparse(base).netloc.lower()

    console.print(f"[white]* Crawling up to [cyan]{max_pages}[/cyan] pages (include_subdomains=[yellow]{include_subs}[/yellow])[/white]\n")
    pages = crawl(base, max_pages, include_subs, DEFAULT_TIMEOUT)

    console.print(f"[white]* Collected [green]{len(pages)}[/green] pages to fetch cookies[/white]\n")
    cookie_map = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Collecting cookies…", total=len(pages), url="")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch_and_parse, url, DEFAULT_TIMEOUT, base_dom): url for url in pages}
            for fut in as_completed(futures):
                url = futures[fut]
                for name, dom_attr, path, secure, httponly, samesite, hosts in fut.result():
                    key = (name, dom_attr, path)
                    rec = cookie_map.get(key, {"name":name,"domain":dom_attr,"path":path,"secure":secure,"httponly":httponly,"samesite":samesite,"hosts":set()})
                    rec["hosts"].update(hosts)
                    cookie_map[key] = rec
                prog.update(task, advance=1, url=url)

    rows = []
    risk_counts = {i:0 for i in range(1,6)}
    for rec in cookie_map.values():
        hosts = ",".join(sorted(rec["hosts"])[:5])
        score = risk_score(rec["domain"], base_dom, rec["secure"], rec["httponly"])
        risk_counts[score] += 1
        rows.append((rec["name"], rec["domain"], rec["path"], rec["secure"], rec["httponly"], rec["samesite"], hosts, score))

    console.print(f"[white]* Found [green]{len(rows)}[/green] unique cookies[/white]\n")
    table = Table(
        title=f"Cookie Scope Diff – {domain}",
        show_header=True,
        header_style="bold magenta",
        box=box.MINIMAL
    )
    for h in ["Cookie","DomainAttr","Path","Secure","HttpOnly","SameSite","Hosts","Risk"]:
        table.add_column(h, overflow="fold")
    for r in rows:
        table.add_row(*[str(x) for x in r])
    console.print(table)

    summary = "  ".join(f"Risk{score}:{count}" for score, count in sorted(risk_counts.items()) if count) + f"  Elapsed:{time.time()-start:.2f}s"
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green]* Cookie scope diff completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "cookie_scope_diff.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            opts = {}
    run(tgt, thr, opts)
