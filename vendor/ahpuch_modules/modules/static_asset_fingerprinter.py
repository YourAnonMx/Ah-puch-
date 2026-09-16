#!/usr/bin/env python3
import os
import sys
import re
import json
import hashlib
import requests
from urllib.parse import urljoin, urlparse
from collections import defaultdict, deque, Counter
from packaging import version as pkgver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
from colorama import init

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

console = Console()
DEFAULT_MAX_PAGES = 100
DEFAULT_INCLUDE_SUBDOMAINS = False
MAX_BYTES = 1024 * 1024  # 1 MB cap when streaming assets

RX_LIBS = {
    "jquery":    re.compile(r"jQuery v?([0-9][0-9A-Za-z.\-_+]*)", re.I),
    "angular":   re.compile(r"Angular(?:JS)?[^0-9]*([0-9][0-9A-Za-z.\-_+]*)", re.I),
    "react":     re.compile(r"React v?([0-9][0-9A-Za-z.\-_+]*)", re.I),
    "vue":       re.compile(r"Vue\.?js v?([0-9][0-9A-Za-z.\-_+]*)", re.I),
    "bootstrap": re.compile(r"Bootstrap v?([0-9][0-9A-Za-z.\-_+]*)", re.I),
    "lodash":    re.compile(r"lodash(?:\.js)? v?([0-9][0-9A-Za-z.\-_+]*)", re.I),
    "moment":    re.compile(r"Moment(?:\.js)? v?([0-9][0-9A-Za-z.\-_+]*)", re.I),
}

KNOWN_BAD = {
    "jquery":    "3.5.0",
    "bootstrap": "4.1.2",
    "lodash":    "4.17.20",
    "moment":    "2.29.0",
}

ASSET_RE = re.compile(
    r"<(?:script|link)[^>]+(?:src|href)=['\"]([^'\"]+\.(?:js|css))['\"]",
    re.I
)

def banner():
    console.print("""
    =============================================
       Ah-Puch - Static Asset Fingerprinter
    =============================================
    """)

def parse_opts(argv):
    max_pages = DEFAULT_MAX_PAGES
    include_subs = DEFAULT_INCLUDE_SUBDOMAINS
    sig_path = None
    i = 3
    while i < len(argv):
        a = argv[i]
        if a == "--max-pages" and i+1 < len(argv):
            try:
                max_pages = int(argv[i+1])
            except (TypeError, ValueError):
                pass
            i += 2
            continue
        if a == "--include-subdomains":
            include_subs = True
            i += 1
            continue
        if a == "--sig-file" and i+1 < len(argv):
            sig_path = argv[i+1]
            i += 2
            continue
        i += 1
    return max_pages, include_subs, sig_path

def norm_base(target):
    if not isinstance(target, str) or not target.strip():
        return ""
    if "://" not in target:
        target = "https://" + target
    return target.rstrip("/") + "/"

def same_domain(url, base_netloc, include_subs):
    host = urlparse(url).netloc.lower()
    if host == base_netloc:
        return True
    if include_subs and host.endswith("." + base_netloc):
        return True
    return False

def extract_links(html, base):
    out = []
    for m in re.finditer(r"(?:href|src)=['\"]([^'\"#]+)['\"]", html, re.I):
        out.append(urljoin(base, m.group(1)))
    return out

def crawl(start, max_pages, include_subs, timeout):
    if not isinstance(start, str) or not start.strip():
        return []
    try:
        max_pages = int(max_pages)
        timeout = float(timeout)
    except (TypeError, ValueError):
        return []
    if max_pages <= 0:
        return []
    max_pages = min(max_pages, 500)
    base_netloc = urlparse(start).netloc.lower()
    seen = {start}
    q = deque([start])
    pages = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.completed}/{task.total} Pages"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Crawling…", total=max_pages)
        while q and len(pages) < max_pages:
            url = q.popleft()
            try:
                r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
            except (OSError, requests.RequestException, TypeError, ValueError):
                prog.advance(task)
                continue
            pages.append((url, r))
            prog.advance(task)
            ct = r.headers.get("Content-Type","")
            if "text/html" in ct:
                for link in extract_links(r.text, url):
                    if same_domain(link, base_netloc, include_subs) and link not in seen:
                        seen.add(link)
                        q.append(link)
    return pages

def load_custom_sigs(path):
    if not path or not os.path.isfile(path):
        return {}
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
        out = {}
        for lib, info in data.items():
            rx = info.get("regex")
            if rx:
                out[lib.lower()] = re.compile(rx, re.I)
            bad = info.get("bad_before")
            if bad:
                KNOWN_BAD[lib.lower()] = bad
        return out
    except (OSError, TypeError, ValueError, json.JSONDecodeError, re.error):
        return {}

def fetch_asset(url):
    if not isinstance(url, str) or not url.strip():
        return b""
    try:
        r = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=True, allow_redirects=False, stream=True)
        buf = b""
        for chunk in r.iter_content(8192):
            buf += chunk
            if len(buf) >= MAX_BYTES:
                break
        return buf
    except (OSError, requests.RequestException, TypeError, ValueError):
        return b""

def detect_library(name, data, rx):
    txt = data.decode(errors="ignore")
    m = rx.search(txt)
    return m.group(1) if m else None

def risk_flag(lib, ver):
    ref = KNOWN_BAD.get(lib)
    if not ref or not ver:
        return "-"
    try:
        if pkgver.parse(ver) < pkgver.parse(ref):
            return "OLD"
    except (TypeError, ValueError):
        pass
    return "-"

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Usage: <domain> [threads] [--max-pages N] [--include-subdomains] [--sig-file path]")
        sys.exit(1)

    raw = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 10
    max_pages, include_subs, sig_path = parse_opts(sys.argv)
    domain = clean_domain_input(raw)
    base = norm_base(domain)
    if not base:
        console.print("[red][!] Invalid target.[/red]")
        sys.exit(2)
    threads = min(max(threads, 1), 32)
    console.print(f"[white]* Crawling up to {max_pages} pages (include_subdomains={include_subs})[/white]")

    custom = load_custom_sigs(sig_path)
    signatures = dict(RX_LIBS, **custom)

    pages = crawl(base, max_pages, include_subs, DEFAULT_TIMEOUT)

    assets = defaultdict(lambda: {"pages": set(), "sha1":"-", "lib":"-", "ver":"-", "risk":"-"})
    for url, resp in pages:
        if "text/html" not in resp.headers.get("Content-Type",""):
            continue
        for m in ASSET_RE.finditer(resp.text):
            asset = urljoin(url, m.group(1))
            assets[asset]["pages"].add(url)

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.completed}/{task.total} Assets"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Fingerprinting…", total=len(assets))
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = { pool.submit(fetch_asset, url): url for url in assets }
            for fut in futures:
                data = fut.result()
                url = futures[fut]
                sha = "-"
                lib = ver = risk = "-"
                if data:
                    sha = hashlib.sha1(data).hexdigest()[:12]
                    for name, rx in signatures.items():
                        found = detect_library(name, data, rx)
                        if found:
                            lib = name
                            ver = found
                            risk = risk_flag(name, ver)
                            break
                assets[url].update({"sha1": sha, "lib": lib, "ver": ver, "risk": risk})
                results.append((
                    url,
                    lib or "-",
                    ver or "-",
                    risk or "-",
                    sha,
                    ",".join(list(assets[url]["pages"])[:2])
                ))
                prog.advance(task)

    table = Table(title=f"Static Asset Fingerprinter: {domain}", box=box.MINIMAL)
    table.add_column("Asset URL", style="cyan", overflow="fold")
    table.add_column("Library", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Risk", style="red")
    table.add_column("SHA1 (short)", style="white")
    table.add_column("Seen On (sample)", style="magenta", overflow="fold")

    for row in results:
        table.add_row(*row)
    console.print(table if results else "[yellow]No JS/CSS assets found.[/yellow]")

    console.print(Panel(f"Assets fingerprinted: {len(results)}", title="Summary", style="bold white"))
    console.print("[green]* Static asset fingerprinting completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        write_to_file(
            os.path.join(out, "assets_report.json"),
            json.dumps({k: dict(v, pages=list(v["pages"])) for k,v in assets.items()}, indent=2)
        )
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out, "assets_report.txt"), export_console.export_text())
