#!/usr/bin/env python3
import os
import re
import sys
import json
import csv
import io
import zipfile
import requests
import urllib3
import itertools

from rich.console import Console
from rich.table import Table

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
TEAL = "#2EC4B6"
TRANCODAY = "https://tranco-list.eu/top-1m.csv.zip"
CISCO_ZIP = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]          Ah-Puch – Global Ranking")
    console.print(f"[{TEAL}]{bar}\n")

def fetch_tranco_rank(domain: str, timeout: int):
    if not isinstance(domain, str) or not domain.strip():
        return "-"
    try:
        r = requests.get(TRANCODAY, timeout=timeout, verify=True, allow_redirects=False)
        if not r.ok:
            return "-"
        z = io.BytesIO(r.content)
        with zipfile.ZipFile(z) as zf:
            with zf.open(zf.namelist()[0]) as f:
                reader = csv.reader(io.TextIOWrapper(f, newline=""))
                for rank, dom in itertools.islice(reader, 0, 1_000_000):
                    if dom.lower() == domain.lower():
                        return int(rank)
    except (AttributeError, csv.Error, IndexError, OSError, requests.RequestException,
            TypeError, ValueError, UnicodeError, zipfile.BadZipFile):
        pass
    return "-"

def fetch_cisco_rank(domain: str, timeout: int):
    if not isinstance(domain, str) or not domain.strip():
        return "-"
    try:
        r = requests.get(CISCO_ZIP, timeout=timeout, verify=True, allow_redirects=False)
        if not r.ok:
            return "-"
        z = io.BytesIO(r.content)
        with zipfile.ZipFile(z) as zf:
            with zf.open(zf.namelist()[0]) as f:
                for line in f:
                    row = line.decode().strip().split(",")
                    if len(row) == 2 and row[1].lower() == domain.lower():
                        return int(row[0])
    except (AttributeError, IndexError, OSError, requests.RequestException,
            TypeError, ValueError, UnicodeError, zipfile.BadZipFile):
        pass
    return "-"

def fetch_quantcast(domain: str, timeout: int):
    if not isinstance(domain, str) or not domain.strip():
        return "-"
    try:
        r = requests.get(f"https://www.quantcast.com/{domain}", timeout=timeout, verify=True, allow_redirects=False)
        if not r.ok:
            return "-"
        m = re.search(r'globalRank.*?value":"(\d+)"', r.text)
        if m:
            return int(m.group(1))
    except (AttributeError, OSError, requests.RequestException, TypeError, ValueError):
        pass
    return "-"

def run(target: str, threads: int, opts: dict):
    if not isinstance(target, str) or not target.strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    banner()
    try:
        timeout = min(max(int(opts.get("timeout", DEFAULT_TIMEOUT)), 1), 60)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    dom = clean_domain_input(target)
    console.print(f"[white]* Gathering public popularity ranks for [cyan]{dom}[/cyan][/white]\n")

    tranco = fetch_tranco_rank(dom, timeout)
    cisco  = fetch_cisco_rank(dom, timeout)
    quant  = fetch_quantcast(dom, timeout)

    table = Table(title=f"Global Ranking – {dom}", header_style="bold white")
    table.add_column("Source", style="cyan")
    table.add_column("Rank", style="green")
    table.add_row("Tranco 1M", str(tranco))
    table.add_row("Cisco Umbrella 1M", str(cisco))
    table.add_row("Quantcast", str(quant))

    console.print(table)
    console.print("[green]* Global ranking lookup completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        recorder = Console(record=True, width=console.width)
        recorder.print(table)
        txt = recorder.export_text()
        write_to_file(os.path.join(out, "global_ranking.txt"), txt)
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided. Please pass a domain.[/red]")
        sys.exit(1)

    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1

    opts = {}
    if len(sys.argv) > 3:
        try:
            loaded = json.loads(sys.argv[3])
            if isinstance(loaded, dict):
                opts = loaded
            else:
                console.print("[yellow]⚠️  Ignoring options: must be a JSON object[/yellow]")
        except (TypeError, ValueError):
            console.print("[yellow]⚠️  Could not parse JSON options; ignoring[/yellow]")

    raise SystemExit(run(tgt, thr, opts))
