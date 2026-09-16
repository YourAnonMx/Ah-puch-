#!/usr/bin/env python3
import os, sys, json, re, base64, hashlib, requests, urllib3, warnings
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table

try:
    import mmh3
except ImportError:
    mmh3 = None

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

console = Console()
TEAL = "#2EC4B6"

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]              Ah-Puch – Favicon Hashing")
    console.print(f"[{TEAL}]{bar}")

def fetch_page(dom, t):
    if not str(dom or "").strip():
        return None, ""
    for sch in ("https","http"):
        try:
            r = requests.get(f"{sch}://{dom}", timeout=t, verify=True, allow_redirects=False)
            if r.status_code < 400:
                return r.url, r.text
        except:
            pass
    return None, ""

def discover_favicon(html, base_url):
    m = re.search(
        r'<link[^>]+rel=["\'](?:shortcut icon|icon)["\'][^>]*href=["\']([^"\']+)',
        html, re.I
    )
    href = m.group(1) if m else "/favicon.ico"
    return urljoin(base_url, href)

def fetch_bytes(u, t):
    if not str(u or "").strip():
        return b""
    try:
        r = requests.get(u, timeout=t, verify=True)
        return r.content if r.ok else b""
    except:
        return b""

def mmh3_hash(content):
    if not content:
        return "-"
    b = base64.b64encode(content)
    if mmh3:
        return str(mmh3.hash(b))
    return str(int(hashlib.md5(b).hexdigest(), 16) % (1 << 31))

def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    dom     = clean_domain_input(target)
    if not dom:
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return
    base, html = fetch_page(dom, timeout)
    if not base:
        console.print("[red]✖ Could not reach target[/red]")
        return

    favurl = discover_favicon(html, base)
    console.print(f"[white][*] Fetching favicon [cyan]{favurl}[/cyan][/white]")
    data = fetch_bytes(favurl, timeout)

    table = Table(title=f"Favicon Hashes – {dom}", show_header=True, header_style="bold white")
    table.add_column("Algorithm")
    table.add_column("Value", overflow="fold")
    table.add_row("Shodan mmh3", mmh3_hash(data))
    table.add_row("MD5",         hashlib.md5(data).hexdigest()     if data else "-")
    table.add_row("SHA1",        hashlib.sha1(data).hexdigest()    if data else "-")
    table.add_row("SHA256",      hashlib.sha256(data).hexdigest()  if data else "-")
    console.print(table)
    console.print("[green][*] Favicon hashing completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        from rich.console import Console as _Console
        export_console = _Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(
            os.path.join(out, "favicon_hashes.txt"),
            export_console.export_text()
        )

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided. Usage: run <domain> [threads] [json‑opts][/red]")
        sys.exit(1)

    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except json.JSONDecodeError:
            pass

    run(tgt, thr, opts)
