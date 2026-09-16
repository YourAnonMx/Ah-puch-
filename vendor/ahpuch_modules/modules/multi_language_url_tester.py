#!/usr/bin/env python3
import os
import sys
import json
import time
import requests
import urllib3
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"

LANG_PATHS = ["en","fr","es","de","it","pt","ru","ja","zh","ar","tr","ko"]
LANG_HDRS  = [
    "en-US,en;q=0.9","fr-FR,fr;q=0.9","es-ES,es;q=0.9","de-DE,de;q=0.9",
    "it-IT,it;q=0.9","pt-PT,pt;q=0.9","ru-RU,ru;q=0.9","ja-JP,ja;q=0.9",
    "zh-CN,zh;q=0.9","ar-AR,ar;q=0.9","tr-TR,tr;q=0.9","ko-KR,ko;q=0.9"
]

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]     Ah-Puch – Multi-Language URL Tester")
    console.print(f"[{TEAL}]{bar}\n")

def fetch(url, timeout, headers=None):
    start = time.time()
    target = str(url or "").strip()
    if not target:
        return "ERR", 0, url, -1
    try:
        r = requests.get(target, headers=headers or {}, timeout=timeout,
                         verify=True, allow_redirects=False)
        latency = int((time.time() - start)*1000)
        size    = int(r.headers.get("Content-Length", len(r.content)))
        return r.status_code, size, r.url, latency
    except (requests.RequestException, OSError, ValueError):
        return "ERR", 0, url, -1

def run(target, threads, opts):
    banner()
    domain = clean_domain_input(str(target or ""))
    if not domain:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid multi-language options.[/red]")
        return 2

    code,size,final,_ = fetch(f"https://{domain}/", timeout)
    base = f"https://{domain}/"
    if code == "ERR":
        code,size,final,_ = fetch(f"http://{domain}/", timeout)
        base = f"http://{domain}/"
    if code == "ERR":
        console.print("[red]✖ Unable to reach domain[/red]")
        return

    tests = []
    for lp in LANG_PATHS:
        url = urljoin(base, f"{lp}/")
        tests.append(("PATH:"+lp, url, None))

    for hdr in LANG_HDRS:
        tests.append(("HDR:"+hdr.split(",",1)[0], base, {"Accept-Language": hdr}))

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.completed}/{task.total} tests"),
        BarColumn(),
        console=console,
        transient=True
    ) as pg:
        task = pg.add_task("Testing…", total=len(tests))
        for label, url, hdr in tests:
            status, length, final_url, ms = fetch(url, timeout, hdr)
            results.append((label, url, str(status), str(length), str(ms), final_url))
            pg.advance(task)

    table = Table(title=f"Multi-Language Handling – {domain}", header_style="bold white")
    for col, style in [
        ("Test","cyan"), ("URL","white"), ("Status","green"),
        ("Bytes","yellow"), ("Latency(ms)","magenta"), ("Final URL","white")
    ]:
        table.add_column(col, style=style, overflow="fold")

    for row in results:
        table.add_row(*row)

    console.print(table)
    console.print("[green]* Multi-language test completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        exp = Console(record=True, width=console.width)
        exp.print(table)
        write_to_file(
            os.path.join(out, "multi_language.txt"),
            exp.export_text()
        )
    return 0

if __name__=="__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv)>3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            pass
    run(tgt, thr, opts)
