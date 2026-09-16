#!/usr/bin/env python3
import os, sys, json, re, concurrent.futures, requests, urllib3
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

FORM_RE  = re.compile(r"<form[^>]*>", re.I)
FILE_RE  = re.compile(r'type=["\']?file["\']?', re.I)
JS_HINT  = re.compile(r'(upload|multipart/form-data|xhr\.send)', re.I)
LINK_RE  = re.compile(r'(?:href|src)=["\']([^"\']+)["\']', re.I)

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]       Ah-Puch – File Upload Surface Finder")
    console.print(f"[{TEAL}]{bar}")

def fetch(url, timeout):
    if not str(url or "").strip():
        return None
    try:
        return requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
    except (requests.RequestException, OSError, ValueError):
        return None

def extract_links(html, base):
    return {
        urljoin(base, m.group(1))
        for m in LINK_RE.finditer(html)
    }

def crawl(start, max_pages, include_subs, timeout):
    if not str(start or "").strip() or max_pages <= 0:
        return []
    netloc = urlparse(start).netloc.lower()
    seen, queue, pages = {start}, [start], []
    while queue and len(pages) < max_pages:
        u = queue.pop(0)
        resp = fetch(u, timeout)
        pages.append((u, resp))
        if not resp:
            continue
        ct = resp.headers.get("Content-Type", "")
        if "text/html" not in ct:
            continue
        for link in extract_links(resp.text, u):
            parsed = urlparse(link)
            host = parsed.netloc.lower()
            if host == "" or host == netloc or (include_subs and host.endswith("." + netloc)):
                if link not in seen:
                    seen.add(link)
                    queue.append(link)
    return pages

def analyse(html):
    out = []
    if FILE_RE.search(html) or JS_HINT.search(html):
        for fm in FORM_RE.finditer(html):
            seg = html[fm.start(): fm.end() + 600]
            act = re.search(r'action=["\']?([^"\'> ]+)', seg, re.I)
            enc = re.search(r'enctype=["\']?([^"\'> ]+)', seg, re.I)
            maxs = re.search(r'max(?:length|size)=["\']?(\d+)', seg, re.I)
            csrf = "Y" if re.search(r'csrf|xsrf|token', seg, re.I) else "-"
            ftype = "Y" if FILE_RE.search(seg) else "JS"
            out.append((
                act.group(1) if act else "-",
                enc.group(1) if enc else "-",
                maxs.group(1) if maxs else "-",
                csrf,
                ftype
            ))
    return out

def run(target, threads, opts):
    banner()
    dom = clean_domain_input(str(target or ""))
    if not dom:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        maxp = max(1, min(int(opts.get("max_pages", 150)), 500))
        include_subs = bool(opts.get("include_subs", False))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid upload-surface options.[/red]")
        return 2
    start    = f"https://{dom}"
    console.print(f"[white]* Crawling up to {maxp} pages (include_subs={include_subs}) on [cyan]{dom}[/cyan][/white]")

    pages = crawl(start, maxp, include_subs, timeout)
    if not pages:
        console.print("[red]✖ Could not reach domain[/red]")
        return 1
    rows   = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as pg:
        task = pg.add_task("Scanning…", total=len(pages))
        for url, resp in pages:
            if resp and "text/html" in resp.headers.get("Content-Type", ""):
                for act, enc, maxs, csrf, ftype in analyse(resp.text):
                    rows.append((url, urljoin(url, act) if act not in ("-", "#") else url, enc, maxs, csrf, ftype))
            pg.advance(task)

    table = Table(title=f"Upload Surfaces – {dom}", show_header=True, header_style="bold white")
    for col in ("Page", "Action URL", "Enctype", "Max", "CSRF", "Type"):
        table.add_column(col, overflow="fold")

    if rows:
        for r in rows:
            table.add_row(*r)
        console.print(table)
    else:
        console.print("[yellow]No upload surfaces found[/yellow]")

    console.print("[green]* Upload surface scan completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=160)
        if rows:
            export_console.print(table)
        else:
            export_console.print("No upload surfaces found")
        export_console.print("* Upload surface scan completed")
        write_to_file(os.path.join(out, "upload_surfaces.txt"), export_console.export_text())
    return 0

if __name__ == "__main__":
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            pass
    run(tgt, thr, opts)
