#!/usr/bin/env python3
import os
import sys
import json
import requests
import urllib.parse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

from ahpuch_modules.utils.util import clean_url, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR, API_KEYS

init(autoreset=True)
console = Console()
TEAL = "#2EC4B6"

def banner():
    border = "=" * 44
    console.print(f"[{TEAL}]{border}")
    console.print(f"[{TEAL}]   Ah-Puch - Performance Monitoring")
    console.print(f"[{TEAL}]{border}\n")

def fetch_metrics(encoded_url, strategy, key, timeout, verify_ssl):
    params = {"url": encoded_url, "strategy": strategy, "key": key}
    return requests.get(
        "https://www.googleapis.com/pagespeedonline/v5/runPagespeed",
        params=params, timeout=timeout, verify=verify_ssl
    )

def parse_lighthouse(data):
    lr = data.get("lighthouseResult", {})
    cat = lr.get("categories", {}).get("performance", {})
    audits = lr.get("audits", {})
    def get_val(name):
        v = audits.get(name, {}).get("numericValue")
        return round(v,2) if isinstance(v,(int,float)) else "-"
    return {
        "Score": round(cat.get("score",0)*100,1),
        "FCP(ms)": get_val("first-contentful-paint"),
        "LCP(ms)": get_val("largest-contentful-paint"),
        "TTI(ms)": get_val("interactive"),
        "TBT(ms)": get_val("total-blocking-time"),
        "CLS":     get_val("cumulative-layout-shift"),
        "SI(ms)": get_val("speed-index"),
    }

def run(target, threads, opts):
    banner()
    api_key = opts.get("key") or API_KEYS.get("GOOGLE_API_KEY","")
    if not api_key:
        console.print("[red][!] Google API key not configured.[/red]")
        return

    raw = clean_url(target)
    url = raw if raw.startswith(("http://","https://")) else f"https://{raw}"
    encoded = urllib.parse.quote_plus(url)
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    verify_ssl = bool(opts.get("verify_ssl", True))
    strategies = opts.get("strategies", ["mobile","desktop"])
    if isinstance(strategies, str):
        strategies = [s.strip() for s in strategies.split(",") if s.strip()]

    console.print(f"[white][*] Fetching PageSpeed metrics for [cyan]{url}[/cyan][/white]\n")
    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[strat]}", justify="right"),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Querying", total=len(strategies), strat="")
        for strat in strategies:
            prog.update(task, strat=strat.capitalize())
            resp = fetch_metrics(encoded, strat, api_key, timeout, verify_ssl)
            if resp.status_code == 200:
                results[strat] = parse_lighthouse(resp.json())
            else:
                msg = "-"
                try:
                    err = resp.json().get("error", {})
                    msg = err.get("message", resp.text)
                except:
                    msg = resp.text
                console.print(f"[red][!] {strat.capitalize()} error {resp.status_code}: {msg}[/red]")
            prog.advance(task)

    if not results:
        console.print("[yellow]No metrics retrieved[/yellow]")
        return

    tbl = Table(title=f"Performance Scores – {raw}", header_style="bold magenta")
    tbl.add_column("Strategy", style="cyan")
    for metric in ("Score","FCP(ms)","LCP(ms)","TTI(ms)","TBT(ms)","CLS","SI(ms)"):
        tbl.add_column(metric, justify="right")
    for strat, mets in results.items():
        tbl.add_row(strat.capitalize(), *(str(mets[m]) for m in tbl.columns[1:]))

    console.print(tbl)
    avg_score = sum(m["Score"] for m in results.values()) / len(results)
    summary = f"Avg Score: {avg_score:.1f}%   Strategies: {', '.join(strategies)}"
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] Performance monitoring completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, raw)
        ensure_directory_exists(out)
        recorder = Console(record=True, width=console.width)
        recorder.print(tbl)
        recorder.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "performance_monitoring.txt"), recorder.export_text())

if __name__=="__main__":
    tgt = sys.argv[1] if len(sys.argv)>1 else ""
    thr = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv)>3:
        try: opts = json.loads(sys.argv[3])
        except: pass
    run(tgt, thr, opts)
