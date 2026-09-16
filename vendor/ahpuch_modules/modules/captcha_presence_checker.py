#!/usr/bin/env python3
import os
import sys
import json
import time
import re
import random
import concurrent.futures
import requests
import urllib3

from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box
from colorama import init

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()
TEAL = "#2EC4B6"

SIGS = {
    "reCAPTCHA":        r"www\.google\.com/recaptcha|data-sitekey|g-recaptcha",
    "hCaptcha":         r"hcaptcha\.com/1/site\.js",
    "FriendlyCaptcha":  r"friendlycaptcha\.com",
    "CloudflareTurnstile": r"challenges\.cloudflare\.com/turnstile"
}

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – CAPTCHA Presence Checker")
    console.print(f"[{TEAL}]{bar}\n")

def crawl(seed: str, limit: int, timeout: int) -> list[str]:
    if not str(seed or "").strip() or limit <= 0:
        return []
    seen = {seed}
    queue = [seed]
    idx = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[url]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Crawling pages…", total=limit, url="")
        while idx < len(queue) and len(seen) < limit:
            url = queue[idx]
            prog.update(task, advance=1, url=url)
            try:
                r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
                html = r.text
                for link in re.findall(r'href=["\']([^"\'#]+)', html):
                    full = urljoin(url, link)
                    if full.startswith(("http://", "https://")) and urlparse(full).netloc == urlparse(seed).netloc and full not in seen:
                        seen.add(full)
                        queue.append(full)
            except (requests.RequestException, OSError, ValueError):
                pass
            idx += 1
    return list(seen)

def detect(url: str, timeout: int) -> tuple[str, list[str]] | None:
    if not str(url or "").strip():
        return None
    try:
        r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        h = r.text.lower()
    except (requests.RequestException, OSError, ValueError):
        return None
    found = []
    for name, pattern in SIGS.items():
        if re.search(pattern, h):
            found.append(name)
    if found:
        return url, sorted(set(found))
    return None

def run(target: str, threads: int, opts: dict):
    banner()
    start = time.time()
    domain = clean_domain_input(target)
    if not domain:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        max_pages = max(1, min(int(opts.get("max_pages", 80)), 500))
        ratio = max(0.0, min(float(opts.get("sample_ratio", 0.3)), 1.0))
        workers = max(1, min(int(threads), 64))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid CAPTCHA options.[/red]")
        return 2

    seed = f"https://{domain}"
    console.print(f"[white][*] Crawling up to [yellow]{max_pages}[/yellow] pages on [cyan]{domain}[/cyan][/white]")
    urls = crawl(seed, max_pages, timeout)
    sample_count = min(len(urls), max(1, int(len(urls) * ratio))) if urls else 0
    sample = random.sample(urls, sample_count) if sample_count else []
    console.print(f"[white][*] Scanning [green]{len(sample)}[/green] pages for CAPTCHA[/white]\n")

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]Scanning…[/white]"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Detecting CAPTCHA", total=len(sample))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for res in pool.map(lambda u: detect(u, timeout), sample):
                if res:
                    results.append(res)
                prog.advance(task)

    if results:
        table = Table(
            title=f"CAPTCHA Presence – {domain}",
            header_style="bold magenta",
            box=box.MINIMAL
        )
        table.add_column("URL", style="cyan", overflow="fold")
        table.add_column("CAPTCHA Type(s)", style="green", overflow="fold")

        type_counts = {}
        for url, types in results:
            table.add_row(url, ", ".join(types))
            for t in types:
                type_counts[t] = type_counts.get(t, 0) + 1

        console.print(table)
        summary = (
            f"Pages scanned: {len(sample)}  "
            f"Detection hits: {len(results)}  "
            + "  ".join(f"{t}:{c}" for t, c in type_counts.items())
            + f"  Elapsed: {time.time() - start:.2f}s"
        )
        console.print(Panel(summary, title="Summary", style="bold white"))
    else:
        console.print("[yellow]No CAPTCHA detected[/yellow]")

    console.print(f"[green]* CAPTCHA presence check completed in {time.time() - start:.2f}s[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        if results:
            export_console.print(table)
            export_console.print(Panel(summary, title="Summary", style="bold white"))
        else:
            export_console.print("[yellow]No CAPTCHA detected[/yellow]")
        write_to_file(
            os.path.join(out_dir, "captcha_presence.txt"),
            export_console.export_text()
        )
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 6
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except:
            opts = {}
    run(tgt, thr, opts)
