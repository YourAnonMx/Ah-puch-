#!/usr/bin/env python3
import os
import sys
import json
import time
import ipaddress
import subprocess
import re
import signal
import urllib3

from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel

from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.utils.util import resolve_to_ip, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
MAX_TIMEOUT = 300
MAX_WORKERS = 32
NBNS_REGEX = re.compile(r"\s*([^\s<]+)<([0-9A-Fa-f]{2})>\s+<(\w+)>\s+<ACTIVE>")

def banner():
    bar = "=" * 44
    console.print(f"[#2EC4B6]{bar}")
    console.print("[cyan]       Ah-Puch - NetBIOS Name Query")
    console.print(f"[#2EC4B6]{bar}\n")

def query_nbns(ip, timeout=DEFAULT_TIMEOUT):
    """Return names, elapsed milliseconds, and an explicit transport/tool error."""
    start = time.time()
    try:
        proc = subprocess.Popen(
            ["nmblookup", "-A", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        return [], None, f"{type(exc).__name__}: {exc}"
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
        try:
            proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            # Do not let inherited pipes from a misbehaving helper hold the
            # module past the unified runner deadline.
            for stream in (proc.stdout, proc.stderr):
                if stream:
                    stream.close()
        return [], None, "nmblookup timeout"
    except OSError as exc:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
        try:
            proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        return [], None, f"{type(exc).__name__}: {exc}"
    elapsed = int((time.time() - start) * 1000)
    if proc.returncode not in (0, None):
        detail = (err or "").strip()
        return [], elapsed, f"nmblookup exit {proc.returncode}" + (f": {detail}" if detail else "")
    names = []
    for line in out.splitlines():
        m = NBNS_REGEX.match(line)
        if m:
            names.append({
                "name": m.group(1),
                "code": m.group(2),
                "type": m.group(3),
                "time_ms": elapsed
            })
    return names, elapsed, ""

def gather_hosts(target):
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            return []
    ip = resolve_to_ip(target)
    return [ip] if ip else []

def run(target, threads, opts):
    banner()
    target = str(target or "").strip()
    if not target:
        console.print("[red]✖ No valid hosts to query[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (AttributeError, TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    try:
        threads = max(1, min(int(opts.get("threads", threads)), MAX_WORKERS))
    except (AttributeError, TypeError, ValueError):
        threads = max(1, min(int(threads or 1), MAX_WORKERS))
    hosts = gather_hosts(clean_domain_input(target)) if "/" in target else gather_hosts(target)
    if not hosts:
        console.print("[red]✖ No valid hosts to query[/red]")
        return 1
    total = len(hosts)
    console.print(f"[*] Scanning {total} host(s)\n")

    results = {}
    failures = {}
    # Leave a small cleanup margin for the production runner's outer timeout;
    # an inner probe expiring at the exact same second otherwise gets killed by
    # the parent and is misclassified as a runner timeout instead of degraded.
    # Keep the complete bounded pool inside the unified runner deadline;
    # nmblookup can retain a child process after its communicate timeout.
    waves = (total + max(1, threads) - 1) // max(1, threads)
    probe_timeout = max(1, min(
        timeout - 1,
        max(1, DEFAULT_TIMEOUT // 2),
        max(1, (timeout - 1) // max(1, waves)),
    ))
    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total}"), BarColumn(), console=console, transient=True) as prog:
        task = prog.add_task("Querying NetBIOS…", total=total)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(query_nbns, ip, probe_timeout): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    names, tms, error = fut.result()
                except Exception as exc:
                    names, tms, error = [], None, f"{type(exc).__name__}: {exc}"
                results[ip] = names
                if error:
                    failures[ip] = error
                prog.advance(task)

    table = Table(title="NetBIOS Name Query Results", header_style="bold white", box=None)
    for col in ("IP","Name","Code","Type","Time(ms)"):
        table.add_column(col, overflow="fold")

    hosts_with = 0
    for ip, entries in results.items():
        if entries:
            hosts_with += 1
            for e in entries:
                table.add_row(ip, e["name"], e["code"], e["type"], str(e["time_ms"]))
        elif ip in failures:
            table.add_row(ip, "ERR", "-", "-", "-")
        else:
            table.add_row(ip, "-", "-", "-", "-")

    console.print(table)
    summary = f"Hosts scanned: {total}  Hosts with names: {hosts_with}  Probe failures: {len(failures)}"
    console.print(Panel(summary, style="bold white"))
    if failures:
        for ip, error in sorted(failures.items()):
            console.print(f"[yellow]⚠ {ip}: {error}[/yellow]")
        console.print("[yellow][*] NetBIOS query completed with degraded coverage[/yellow]\n")
    else:
        console.print("[green][*] NetBIOS name query completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, target.replace("/", "_"))
        ensure_directory_exists(out)
        export_console = Console(record=True, width=160)
        export_console.print(table)
        write_to_file(os.path.join(out, "nbns_results.txt"), export_console.export_text() + f"\n{summary}")
        write_to_file(
            os.path.join(out, "nbns_results.json"),
            json.dumps({"results": results, "failures": failures}, indent=2),
        )
    return 1 if failures else 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ Usage: netbios_name_query.py <host|CIDR> [threads][/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            opts = {}
    sys.exit(run(tgt, thr, opts))
