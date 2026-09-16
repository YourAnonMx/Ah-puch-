#!/usr/bin/env python3
import os
import sys
import json
import random
import string
import requests
import urllib3
import warnings
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", "Unverified HTTPS request")

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

console = Console()

def banner():
    console.print("[cyan]" + "="*40)
    console.print("[cyan]   Ah-Puch – CORS Misconfiguration Scanner")
    console.print("[cyan]" + "="*40)

def rand_origin(domain):
    tok = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"https://{tok}.{domain}"

def test_origin(url, origin, timeout):
    if not str(url or "").strip() or not str(origin or "").strip():
        return origin, "ERR", None, None, None
    try:
        r = requests.get(
            url,
            headers={"Origin": origin},
            timeout=timeout,
            verify=True,
            allow_redirects=False
        )
        return origin, r.status_code, r.headers.get("Access-Control-Allow-Origin"), r.headers.get("Access-Control-Allow-Credentials"), r.headers.get("Vary")
    except (requests.RequestException, OSError):
        return origin, "ERR", None, None, None

def classify(origin, acao, acac, vary, target_origin):
    if not acao:
        return "None"
    acac_flag = (acac or "").lower() == "true"
    if acao == "*":
        return "Wildcard+Creds" if acac_flag else "Wildcard"
    if acao.lower() == origin.lower():
        if origin == target_origin:
            return "Reflect-Target+Creds" if acac_flag else "Reflect-Target"
        else:
            return "Reflect-Other+Creds" if acac_flag else "Reflect-Other"
    if acao.endswith(target_origin):
        return "Subdomain-Pattern+Creds" if acac_flag else "Subdomain-Pattern"
    return "Other"

def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    threads = max(1, int(threads))
    domain = clean_domain_input(target)
    if not domain:
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return
    base = target if target.startswith(("http://","https://")) else f"https://{domain}"
    parsed = urlparse(base)
    target_origin = f"{parsed.scheme}://{parsed.netloc}"
    tests = [
        target_origin,
        rand_origin(domain),
        "null",
        "http://evil.example",
        f"http://{domain}",
        f"https://{domain}"
    ]

    console.print(f"[white]* Testing [cyan]{len(tests)}[/cyan] origins with [yellow]{threads}[/yellow] threads[/white]")
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Testing CORS…", total=len(tests))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(test_origin, base, o, timeout): o for o in tests}
            for fut in as_completed(futures):
                o, status, acao, acac, vary = fut.result()
                cls = classify(o, acao or "", acac or "", vary or "", target_origin)
                results.append((o, acao or "-", "Y" if acac == "true" else "N", vary or "-", cls, str(status)))
                prog.advance(task)

    console.print(f"[white]* Completed [green]{len(results)}[/green] origin tests[/white]")
    table_str = tabulate(
        results,
        headers=["Origin","ACAO","ACAC","Vary","Class","Status"],
        tablefmt="grid"
    )
    console.print(table_str)
    console.print("[green]* CORS misconfiguration scan completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "cors_scan.txt"), table_str)

if __name__=="__main__":
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 4
    opts = {}
    if len(sys.argv)>3:
        try: opts = json.loads(sys.argv[3])
        except: pass
    run(tgt, thr, opts)
