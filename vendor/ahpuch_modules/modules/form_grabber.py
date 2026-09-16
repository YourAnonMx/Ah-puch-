#!/usr/bin/env python3
import os, sys, json, re, requests, urllib3
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
session = requests.Session()

FORM_FIELD_TYPES = (
    "button","checkbox","color","date","datetime-local","email","file","hidden","image","month",
    "number","password","radio","range","reset","search","tel","text","time","url","week",
    "datetime","fileupload","select","textarea"
)
SENSITIVE_RX = re.compile(r"(passw|csrf|token|auth|sess|secret|key|user|login)", re.I)

def banner():
    bar = "="*44
    console.print(f"[#2EC4B6]{bar}")
    console.print("[cyan]              Ah-Puch – Form Grabber")
    console.print(f"[#2EC4B6]{bar}\n")

def fetch(url, timeout):
    if not str(url or "").strip():
        return None
    try:
        return session.get(url, timeout=timeout, verify=True, allow_redirects=False)
    except:
        return None

def crawl(seed, max_pages, include_subs, timeout):
    netloc = urlparse(seed).netloc.lower()
    queue, seen, pages = [seed], {seed}, []
    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        resp = fetch(url, timeout)
        if not resp or "text/html" not in resp.headers.get("Content-Type",""):
            continue
        html = resp.text
        pages.append((url, html))
        for m in re.finditer(r'href=["\']([^"\'#]+)', html, re.I):
            link = urljoin(url, m.group(1))
            h = urlparse(link).netloc.lower()
            if (h == netloc or (include_subs and h.endswith("."+netloc))) and link not in seen:
                seen.add(link); queue.append(link)
    return pages

def analyse(page):
    url, html = page
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for form in soup.find_all("form"):
        action = form.get("action","-") or "-"
        method = form.get("method","GET").upper()
        enc    = form.get("enctype","-")
        counts = {t:0 for t in FORM_FIELD_TYPES}
        sensitive = []
        for fld in form.find_all(["input","textarea","select","button"]):
            ftype = fld.get("type","text").lower()
            if ftype in counts: counts[ftype] += 1
            name = fld.get("name","")
            if SENSITIVE_RX.search(name):
                sensitive.append(name[:40])
        fields = ",".join(f"{k}:{v}" for k,v in counts.items() if v) or "-"
        sens   = ",".join(sensitive) if sensitive else "-"
        out.append({
            "page": url,
            "action": action,
            "method": method,
            "enctype": enc,
            "fields": fields,
            "sensitive": sens
        })
    return out

def run(target, threads, opts):
    banner()
    timeout      = int(opts.get("timeout", DEFAULT_TIMEOUT))
    threads      = max(1, int(threads))
    max_pages    = max(1, int(opts.get("max_pages", 250)))
    include_subs = bool(opts.get("include_subs", False))
    dom          = clean_domain_input(target)
    if not dom:
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return
    seed         = f"https://{dom}"
    console.print(f"[*] Crawling up to {max_pages} pages (include_subs={include_subs}) on [cyan]{dom}[/cyan]\n")

    pages = crawl(seed, max_pages, include_subs, timeout)
    total_pages = len(pages)
    results     = []

    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total} Parsing forms"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("", total=total_pages)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for fut in as_completed([pool.submit(analyse, p) for p in pages]):
                results.extend(fut.result())
                prog.advance(task)

    table = Table(title=f"Forms – {dom}", header_style="bold white", box=None)
    for col in ("Page","Action","Method","Enc.","Fields","Sensitive"):
        table.add_column(col, overflow="fold")
    for f in results:
        table.add_row(f["page"], f["action"], f["method"], f["enctype"], f["fields"], f["sensitive"])

    if results:
        console.print(table)
    else:
        console.print("[yellow]No forms detected.[/yellow]")

    total_forms     = len(results)
    total_sensitive = sum(1 for f in results if f["sensitive"]!="-")
    summary = (f"Pages crawled: {total_pages}  Forms: {total_forms}  "
               f"Sensitivities: {total_sensitive}")
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] Form grabbing completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out_dir)
        write_to_file(os.path.join(out_dir, "forms.json"), json.dumps(results, indent=2))
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out_dir, "forms.txt"), export_console.export_text())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No domain provided.[/red]")
        sys.exit(1)
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 12
    opts = json.loads(sys.argv[3]) if len(sys.argv)>3 else {}
    run(tgt, thr, opts)
