#!/usr/bin/env python3
import os, sys, json, re, requests, concurrent.futures, urllib3
from urllib.parse import urljoin, urlparse
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

PAT_STATIC = re.compile(r'<(?:script|img|link)[^>]+(?:src|href)=["\']([^"\']+)["\']', re.I)
PAT_LAZY = re.compile(r'data-(?:src|href|lazy-src)=["\']([^"\']+)["\']', re.I)
PAT_FETCH = [
    re.compile(r'fetch\(["\']([^"\']+)["\']', re.I),
    re.compile(r'\$\.(?:get|post|ajax|load)\(["\']([^"\']+)["\']', re.I),
    re.compile(r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']', re.I),
    re.compile(r'import\(["\']([^"\']+)["\']', re.I),
]

MAX_STATIC = 100
MAX_DYNAMIC = 200
MAX_WORKERS = 24

session = requests.Session()

def banner():
    console.print(f"[{TEAL}]{'='*44}")
    console.print("[cyan]     Ah-Puch – Lazy-Load Resource Finder")
    console.print(f"[{TEAL}]{'='*44}")


def fetch(url, timeout):
    if not str(url or "").strip():
        return ""
    try:
        r = session.get(url, timeout=timeout, verify=True, allow_redirects=False)
        return r.text if r.ok else ""
    except (requests.RequestException, OSError, ValueError):
        return ""


def extract(patterns, text, base, net):
    urls = []
    if not text:
        return urls
    for pat in (patterns if isinstance(patterns, list) else [patterns]):
        for match in pat.finditer(text):
            link = urljoin(base, match.group(1).strip())
            p = urlparse(link)
            if p.scheme in ("http", "https") and p.netloc == net:
                urls.append(link)
    return list(dict.fromkeys(urls))


def run(target, threads, opts):
    banner()
    dom = clean_domain_input(str(target or ""))
    if not dom:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        workers = max(1, min(int(threads), MAX_WORKERS))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid lazy-load options.[/red]")
        return 2
    session.headers.update({"User-Agent": "Ah-Puch-Lazy/1.0"})
    base = f"https://{dom}"
    html = fetch(base, timeout) or fetch(f"http://{dom}", timeout)
    if not html:
        console.print("[red]✖ Unable to reach domain[/red]")
        return

    net = urlparse(base).netloc
    static = extract(PAT_STATIC, html, base, net)[:MAX_STATIC]
    dynamic = extract(PAT_LAZY, html, base, net)

    if static:
        with Progress(SpinnerColumn(), TextColumn("Scanning"), BarColumn(), console=console, transient=True) as pg:
            task = pg.add_task("", total=len(static))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                for content in pool.map(lambda u: fetch(u, timeout), static):
                    dynamic += extract(PAT_LAZY, content, base, net)
                    for pat in PAT_FETCH:
                        dynamic += extract(pat, content, base, net)
                    pg.advance(task)

    static = list(dict.fromkeys(static))
    dynamic = list(dict.fromkeys(dynamic))[:MAX_DYNAMIC]

    table = Table(title=f"Lazy Resources – {dom}", header_style="bold white", box=box.MINIMAL)
    table.add_column("Type", style="magenta")
    table.add_column("URL", style="cyan", overflow="fold")

    for url in static:
        table.add_row("static", url)
    for url in dynamic:
        table.add_row("dynamic", url)

    console.print(table if static or dynamic else "[yellow]No lazy/dynamic resources detected[/yellow]")
    console.print("[green]* Lazy-load scan completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        if static or dynamic:
            export_console.print(table)
        else:
            export_console.print("[yellow]No lazy/dynamic resources detected[/yellow]")
        write_to_file(os.path.join(out, "lazy_resources.txt"), export_console.export_text())
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: lazy_load_finder.py <domain> [threads] [options_json][/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else MAX_WORKERS
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            pass
    run(tgt, thr, opts)
