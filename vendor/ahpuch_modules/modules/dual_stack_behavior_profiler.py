#!/usr/bin/env python3
import os
import sys
import json
import time
import socket
import ssl
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init, Fore, Style

init(autoreset=True)
console = Console()

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

DEFAULT_PATHS = ["/", "/login", "/api/", "/status", "/health"]

def banner():
    console.print(f"{Fore.CYAN}{'='*44}")
    console.print(f"{Fore.CYAN}     Ah-Puch – Dual-Stack Behavior Profiler")
    console.print(f"{Fore.CYAN}{'='*44}{Style.RESET_ALL}")

def get_ips(domain, timeout):
    if not str(domain or "").strip():
        return [], []
    v4 = []
    v6 = []
    try:
        for r in dns.resolver.resolve(domain, "A", lifetime=timeout):
            v4.append(r.address)
    except:
        pass
    try:
        for r in dns.resolver.resolve(domain, "AAAA", lifetime=timeout):
            v6.append(r.address)
    except:
        pass
    return v4, v6

def tcp_connect(ip, fam, timeout):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.time()
    try:
        s.connect((ip, 443))
        return round((time.time() - start)*1000, 1), s
    except:
        s.close()
        return None, None

def tls_handshake(sock, domain, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1", "h2"])
    sock.settimeout(timeout)
    try:
        tls = ctx.wrap_socket(sock, server_hostname=domain)
        proto = tls.version() or "-"
        cipher = tls.cipher()[0] if tls.cipher() else "-"
        return True, proto, cipher, tls
    except:
        sock.close()
        return False, "-", "-", None

def http_request(tls_sock, domain, path, timeout):
    req = f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
    tls_sock.settimeout(timeout)
    try:
        tls_sock.sendall(req)
        resp = b""
        while True:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        lines = resp.split(b"\r\n", 1)
        status = lines[0].split(b" ")[1].decode() if len(lines) > 0 and b" " in lines[0] else "-"
        size = len(resp)
        return status, size
    except:
        return "-", 0

def profile_task(domain, path, ip, fam, timeout):
    rtt, sock = tcp_connect(ip, fam, timeout)
    if not sock:
        return (path, "IPv4" if fam==socket.AF_INET else "IPv6", ip, "-", "-", "-", "-", "-", 0)
    ok, proto, cipher, tls_sock = tls_handshake(sock, domain, timeout)
    if not ok or tls_sock is None:
        return (path, "IPv4" if fam==socket.AF_INET else "IPv6", ip, f"{rtt} ms", "N", "-", "-", "-", 0)
    status, size = http_request(tls_sock, domain, path, timeout)
    tls_sock.close()
    return (path, "IPv4" if fam==socket.AF_INET else "IPv6", ip, f"{rtt} ms", "Y", proto, cipher, status, size)

def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    threads = max(1, int(threads))
    paths = opts.get("paths", DEFAULT_PATHS) or DEFAULT_PATHS
    limit = max(0, int(opts.get("limit", len(paths))))
    domain = clean_domain_input(target)
    if not domain:
        console.print("[yellow][!] Empty target is not applicable[/yellow]")
        return
    v4, v6 = get_ips(domain, timeout)
    tests = []
    for p in paths[:limit]:
        for ip, fam in [(ip, socket.AF_INET) for ip in v4] + [(ip, socket.AF_INET6) for ip in v6]:
            tests.append((p, ip, fam))
    console.print(f"[white][*] Testing {len(tests)} endpoints on {domain}[/white]")
    results = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Profiling", total=len(tests))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(profile_task, domain, p, ip, fam, timeout): (p, ip) for p, ip, fam in tests}
            for fut in as_completed(futures):
                results.append(fut.result())
                progress.advance(task)
    table = Table(title=f"Dual-Stack Profile – {domain}", header_style="bold magenta")
    cols = ["Path","Fam","IP","TCP-RTT","TLS?","TLS-Ver","Cipher","HTTP","Bytes"]
    for c in cols:
        table.add_column(c, overflow="fold", justify="center" if c in ("Fam","TLS?","HTTP") else "left")
    diffs = 0
    grouped = {}
    for row in results:
        key = (row[0], row[1])  # path + family
        grouped.setdefault((row[0], row[1]), []).append(row)
    for path in paths[:limit]:
        rows4 = grouped.get((path, "IPv4")) or []
        rows6 = grouped.get((path, "IPv6")) or []
        for r in rows4+rows6:
            table.add_row(*[str(x) for x in r])
        if rows4 and rows6:
            b4 = sum(r[-1] for r in rows4)
            b6 = sum(r[-1] for r in rows6)
            if b4 != b6:
                diffs += 1
    console.print(table)
    console.print(f"[yellow][*] Paths with byte-diff between v4/v6: {diffs}[/yellow]")
    console.print("[green][*] Dual-stack behavior profiling completed[/green]")
    if EXPORT_SETTINGS.get("enable_txt_export"):
        out_dir = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out_dir)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        export_console.print(f"Byte-Diffs: {diffs}")
        write_to_file(os.path.join(out_dir, "dual_stack_behavior.txt"), export_console.export_text())

if __name__=="__main__":
    tgt = sys.argv[1] if len(sys.argv)>1 else ""
    thr = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 8
    opts = {}
    if len(sys.argv)>3:
        try: opts = json.loads(sys.argv[3])
        except: opts = {}
    run(tgt, thr, opts)
