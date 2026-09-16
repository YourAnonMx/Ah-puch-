#!/usr/bin/env python3
import os, sys, json, re, requests
from tabulate import tabulate
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

console = Console()
ROBOT_PATH = "/robots.txt"

def banner():
    console.print("[cyan]" + "="*40)
    console.print("[cyan]         Ah-Puch – Crawl Rules Check")
    console.print("[cyan]" + "="*40)

def fetch_robots(url, timeout):
    try:
        r = requests.get(f"{url.rstrip('/')}{ROBOT_PATH}", timeout=timeout, verify=True)
        return r.status_code, r.text.splitlines() if r.status_code == 200 else []
    except:
        return "ERR", []

def parse_rules(lines):
    rules = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#") or ":" not in ln:
            continue
        d, p = map(str.strip, ln.split(":", 1))
        rules.append([d, p])
    return rules

def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom = clean_domain_input(target)
    base = f"https://{dom}"
    console.print(f"[white]* Fetching [cyan]{base}{ROBOT_PATH}[/cyan][/white]")

    status, lines = fetch_robots(base, timeout)
    if status != 200 or not lines:
        console.print("[yellow]No robots.txt accessible[/yellow]"); return

    rules = parse_rules(lines)
    allow = sum(1 for r in rules if r[0].lower() == "allow")
    dis  = sum(1 for r in rules if r[0].lower() == "disallow")
    console.print(f"[white]* Parsed [green]{len(rules)}[/green] rules ([green]{allow} Allow[/green] / [red]{dis} Disallow[/red])[/white]")

    table = tabulate(rules, headers=["Directive","Path"], tablefmt="grid")
    console.print(table)
    console.print("[green]* Crawl rules analysis completed[/green]")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out, "crawl_rules.txt"), table)

if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv)>1 else ""
    thr = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv)>3:
        try: opts = json.loads(sys.argv[3])
        except: pass
    run(tgt, thr, opts)
