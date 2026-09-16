#!/usr/bin/env python3
import os
import sys
import re
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

from ahpuch_modules.utils.util import clean_domain_input, clean_url, ensure_directory_exists, write_to_file, log_message
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

FIELDS = {
    "Contact":             (True,  re.compile(r'^(mailto:|https?://)')),
    "Encryption":          (False, re.compile(r'^https?://')),
    "Acknowledgements":    (False, re.compile(r'^https?://')),
    "Preferred-Languages": (False, re.compile(r'^[a-zA-Z-]+(,[a-zA-Z-]+)*$')),
    "Expires":             (False, re.compile(r'^\d{4}-\d{2}-\d{2}$')),
    "Policy":              (False, re.compile(r'^https?://')),
    "Hiring":              (False, re.compile(r'^https?://')),
}

def run(target, threads, opts):
    if not isinstance(target, str) or not target.strip():
        return {"status": "inapplicable", "error": "empty target", "analysis": {}}
    opts = opts if isinstance(opts, dict) else {}
    try:
        timeout = min(max(int(opts.get("timeout", DEFAULT_TIMEOUT)), 1), 60)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    do_log = bool(opts.get("log", False))
    domain     = clean_domain_input(target)
    base       = clean_url(target)
    if not urlparse(base).scheme:
        base = "https://" + base
    url        = urljoin(base.rstrip("/") + "/", ".well-known/security.txt")

    console.print(Fore.GREEN + "=============================================")
    console.print(Fore.GREEN + "      Ah-Puch - Security.txt Detection")
    console.print(Fore.GREEN + "=============================================\n")
    console.print(f"[*] Fetching {url}\n")

    fetch_error = ""
    try:
        r = requests.get(url, timeout=timeout, verify=True, headers={"User-Agent": "Ah-Puch/1.0"})
        content = r.text if r.status_code == 200 else ""
    except (OSError, requests.RequestException, TypeError, ValueError) as e:
        console.print(Fore.RED + f"[!] Error: {e}")
        content = ""
        fetch_error = f"{type(e).__name__}: {e}"

    entries = {}
    for line in content.splitlines():
        if not line.strip() or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k in FIELDS:
            entries[k] = v

    analysis = {}
    for field, (required, pattern) in FIELDS.items():
        val = entries.get(field)
        if val:
            ok = bool(pattern.search(val))
            status = "Valid" if ok else "Invalid"
        else:
            status = "Unverified" if fetch_error else ("Missing" if required else "Not Provided")
        analysis[field] = (status, val or "-",)

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", overflow="fold")
    table.add_column("Status", style="green")
    table.add_column("Value", style="yellow", overflow="fold")
    for field, (status, val) in analysis.items():
        clr = "green" if status == "Valid" else ("red" if status in ("Invalid", "Missing") else "yellow")
        table.add_row(field, f"[{clr}]{status}[/{clr}]", val)
    console.print(table)
    if fetch_error:
        console.print(Fore.RED + "\n[!] Fetch failed; policy fields were not classified\n")
    else:
        console.print(Fore.GREEN + "\n[*] Completed\n")

    if do_log:
        log = f"URL: {url}\n"
        for f, (st, v) in analysis.items():
            log += f"{f}: {st} | {v}\n"
        log_message("security_txt_detection.log", log)

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        txt = export_console.export_text()
        write_to_file(os.path.join(out, "security_txt.txt"), txt)
    return {"status": "error" if fetch_error else "success", "error": fetch_error, "analysis": analysis}

if __name__ == "__main__":
    tgt  = sys.argv[1] if len(sys.argv) > 1 else ""
    thr  = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    try:
        opts = __import__("json").loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError):
        opts = {}
    run(tgt, thr, opts)
