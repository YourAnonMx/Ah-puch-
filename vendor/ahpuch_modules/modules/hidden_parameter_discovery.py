#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import random
import string
import warnings
import requests
from urllib.parse import urljoin, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

console = Console()
TEAL = "#2EC4B6"

DEFAULT_PARAMS = [
    "debug","test","stage","beta","preview","admin","auth","key","token",
    "id","ref","redirect","next","lang","locale","format","json","xml",
    "callback","output","export","download","limit","offset"
]

def banner():
    console.print(f"[{TEAL}]" + "="*44)
    console.print(f"[cyan]     Ah-Puch – Hidden Parameter Discovery")
    console.print(f"[{TEAL}]" + "="*44 + "\n")

def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def get_baseline(url: str, timeout: int):
    if not str(url or "").strip():
        return 0, sha256(b""), 0
    r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
    length = len(r.content)
    hsh = sha256(r.content)
    return length, hsh, r.status_code

def random_token(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def probe(param: str, value: str, url: str, baseline_len: int, baseline_hash: str, timeout: int, threshold: int):
    try:
        full_url = f"{url}?{urlencode({param: value})}"
        r = requests.get(url, params={param: value}, timeout=timeout, verify=True, allow_redirects=False)
        length = len(r.content)
        hsh = sha256(r.content)
        diff = abs(length - baseline_len)
        changed = diff > threshold or (hsh != baseline_hash)
        is_redirect = r.is_redirect or r.status_code in (301,302,303,307,308)
        return {
            "param": param,
            "value": value,
            "status": r.status_code,
            "length": length,
            "delta": diff,
            "changed": changed,
            "redirect": is_redirect
        }
    except Exception:
        return {
            "param": param,
            "value": value,
            "status": "ERR",
            "length": 0,
            "delta": 0,
            "changed": False,
            "redirect": False
        }

def run(target, threads, opts):
    banner()
    timeout    = int(opts.get("timeout", DEFAULT_TIMEOUT))
    threshold  = int(opts.get("threshold", 50))
    max_params = int(opts.get("max_params", len(DEFAULT_PARAMS)))
    test_values= opts.get("test_values", ["1", random_token(), "<script>alert(1)</script>"])
    params_file= opts.get("params_file")

    threads = max(1, int(threads))
    domain = clean_domain_input(target)
    if not domain:
        console.print("[yellow][!] Empty target is not applicable.[/yellow]")
        return
    base   = target if target.startswith(("http://","https://")) else f"https://{domain}"

    params = list(DEFAULT_PARAMS)
    if params_file and os.path.isfile(params_file):
        try:
            with open(params_file,"r",encoding="utf8",errors="ignore") as f:
                extra = [l.strip() for l in f if l.strip()]
                params.extend(extra)
        except:
            pass
    params = list(dict.fromkeys(params))[:max_params]

    console.print(f"[white]* Baseline request to [cyan]{base}[/cyan]…[/white]")
    baseline_len, baseline_hash, baseline_status = get_baseline(base, timeout)
    console.print(f"[white]* Baseline len={baseline_len} status={baseline_status} hash={baseline_hash[:8]}…[/white]\n")

    tasks = []
    for p in params:
        for v in test_values:
            tasks.append((p,v, base, baseline_len, baseline_hash, timeout, threshold))

    console.print(f"[white]* Probing [cyan]{len(params)}[/cyan] params × [cyan]{len(test_values)}[/cyan] values = [cyan]{len(tasks)}[/cyan] checks with [yellow]{threads}[/yellow] threads[/white]")

    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Probing…", total=len(tasks))
        with ThreadPoolExecutor(max_workers=threads) as exe:
            futures = {exe.submit(probe, *t): t[0] for t in tasks}
            for fut in as_completed(futures):
                res = fut.result()
                results.append(res)
                prog.advance(task)

    summary = {}
    for r in results:
        p = r["param"]
        rec = summary.setdefault(p, {
            "status": set(), "max_delta": 0, "values": [], "redirects": 0
        })
        rec["status"].add(r["status"])
        if r["changed"]:
            rec["values"].append((r["value"], r["delta"]))
            rec["max_delta"] = max(rec["max_delta"], r["delta"])
        if r["redirect"]:
            rec["redirects"] += 1

    hits = []
    for p,info in summary.items():
        if info["values"] or info["redirects"]>0:
            vals = ",".join(f"{v} (Δ{d})" for v,d in info["values"])
            hits.append((p,
                         "/".join(str(s) for s in info["status"]),
                         info["max_delta"],
                         info["redirects"],
                         vals or "-"))

    table = Table(title=f"Hidden Params – {domain}", header_style="bold magenta")
    table.add_column("Param", style="cyan")
    table.add_column("Status Codes", style="green")
    table.add_column("Max Δlen", style="yellow", justify="right")
    table.add_column("Redirects", style="white", justify="right")
    table.add_column("Values Triggered", style="blue", overflow="fold")

    if hits:
        for row in sorted(hits, key=lambda x: -x[2]):
            table.add_row(*map(str, row))
        console.print(table)
    else:
        console.print("[yellow][!] No hidden‑parameter anomalies detected.[/yellow]")

    total_hits = len(hits)
    panel = Panel(f"Params tested: {len(params)}  Hits: {total_hits}  Elapsed: N/A",
                  title="Summary", style="bold white")
    console.print(panel, "\n[green]* Hidden parameter discovery completed[/green]")

if __name__=="__main__":
    tgt  = sys.argv[1] if len(sys.argv)>1 else ""
    thr  = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 20
    opts = {}
    if len(sys.argv)>3:
        try: opts = json.loads(sys.argv[3])
        except: pass
    run(tgt, thr, opts)
