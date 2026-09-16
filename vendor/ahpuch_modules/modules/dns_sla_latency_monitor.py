#!/usr/bin/env python3
import os
import sys
import json
import time
import dns.resolver
import urllib3

from statistics import mean, median, pstdev
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

DEFAULT_RESOLVERS = {
    "Cloudflare": "1.1.1.1",
    "Google":     "8.8.8.8",
    "Quad9":      "9.9.9.9",
    "OpenDNS":    "208.67.222.222"
}

def banner():
    bar = "=" * 44
    console.print(f"[green]{bar}")
    console.print("[green]       Ah-Puch - DNS SLA Latency Monitor")
    console.print(f"[green]{bar}\n")

def measure(name, server, domain, samples, timeout):
    if not str(domain or "").strip():
        return name, server, 0, timeout * 1000, timeout * 1000, timeout * 1000, timeout * 1000, 0.0
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.lifetime = timeout
    times = []
    samples = max(1, int(samples))
    for _ in range(samples):
        start = time.time()
        try:
            resolver.resolve(domain, "A")
            times.append((time.time() - start) * 1000)
        except:
            times.append(timeout * 1000)
    return name, server, samples, round(min(times),2), round(median(times),2), round(mean(times),2), round(max(times),2), round(pstdev(times),2)

def run(target, threads, opts):
    banner()
    start = time.time()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    samples = int(opts.get("samples", 5))
    domain = clean_domain_input(target)
    if not domain:
        console.print("[yellow]No target[/yellow]")
        return
    resolvers = opts.get("resolvers", DEFAULT_RESOLVERS)
    if not isinstance(resolvers, dict):
        resolvers = DEFAULT_RESOLVERS
    if not resolvers:
        console.print("[yellow]No resolvers configured[/yellow]")
        return

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[white]{task.fields[name]}", justify="right"),
        BarColumn(),
        console=console,
        transient=True
    ) as prog:
        task = prog.add_task("Measuring SLAs…", total=len(resolvers), name="")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(measure, name, ip, domain, samples, timeout): name
                for name, ip in resolvers.items()
            }
            for fut in as_completed(futures):
                name = futures[fut]
                results.append(fut.result())
                prog.update(task, advance=1, name=name)

    table = Table(title=f"DNS SLA Latency – {domain}", header_style="bold magenta", box=box.MINIMAL)
    for col in ("Resolver","IP","Samples","Min(ms)","Med(ms)","Avg(ms)","Max(ms)","StdDev(ms)"):
        table.add_column(col, justify="center")
    avg_list = []
    for r in results:
        table.add_row(*[str(x) for x in r])
        avg_list.append(r[5])
    console.print(table)

    fastest = min(results, key=lambda x: x[5])
    slowest = max(results, key=lambda x: x[5])
    overall_avg = round(mean(avg_list),2) if avg_list else "-"
    summary = (
        f"Samples: {samples}  "
        f"Fastest: {fastest[0]}({fastest[5]}ms)  "
        f"Slowest: {slowest[0]}({slowest[5]}ms)  "
        f"Overall Avg: {overall_avg}ms  "
        f"Elapsed: {round(time.time()-start,2)}s"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] DNS SLA monitoring completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(Panel(summary, title="Summary", style="bold white"))
        write_to_file(os.path.join(out, "dns_sla.txt"), export_console.export_text())

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    run(tgt, thr, opts)
