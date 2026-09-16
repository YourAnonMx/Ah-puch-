#!/usr/bin/env python3
import os
import sys
import json
import re
import requests
import urllib3
from http.cookies import SimpleCookie
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from colorama import init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

console = Console()

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 8
DEFAULT_PATHS = ["/", "/login", "/signin", "/account", "/user", "/admin", "/api/", "/api/v1/"]
DEFAULT_HINTS = [
    "session","sess","sid","phpsessid","jsessionid","aspsessionid",
    "token","auth","jwt","bearer","sessionid"
]

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import EXPORT_SETTINGS, RESULTS_DIR


def reach(domain, timeout):
    if not domain or not str(domain).strip():
        return None
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
            return r.url
        except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
            continue
    return None


def fetch(url, timeout):
    if not url or not str(url).strip():
        return None, {"_fetch_error": "empty URL"}
    try:
        r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        return r.status_code, r.headers
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError) as exc:
        return None, {"_fetch_error": f"{type(exc).__name__}: {exc}"}


def parse_cookies(set_cookie_header):
    cookies = []
    if not set_cookie_header or not isinstance(set_cookie_header, str):
        return cookies
    parts = set_cookie_header.split(",")
    buf = ""
    tmp = []
    for p in parts:
        if "=" in p.split(";", 1)[0] and buf:
            tmp.append(buf)
            buf = p
        else:
            buf = f"{buf},{p}" if buf else p
    if buf:
        tmp.append(buf)
    for raw in tmp:
        sc = SimpleCookie()
        sc.load(raw)
        for name, morsel in sc.items():
            attrs = {k.lower(): v for k, v in morsel.items()}
            cookies.append((name, morsel.value, attrs))
    return cookies


def assess_cookie(name, attrs, hints):
    lname = name.lower()
    sensitive = any(h in lname for h in hints)
    secure = bool(attrs.get("secure"))
    http_only = bool(attrs.get("httponly"))
    same_site = attrs.get("samesite", "-").lower()
    dom = attrs.get("domain", "-")
    path = attrs.get("path", "-")
    if sensitive and not (secure and http_only):
        risk = "High"
    elif sensitive and same_site not in ("strict", "lax"):
        risk = "Medium"
    else:
        risk = "Low"
    return sensitive, secure, http_only, same_site, dom, path, risk


def option_list(value, default):
    if value is None or value == "":
        return list(default)
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(part).strip() for part in value if str(part).strip()]
    return list(default)


def run(target, threads, opts):
    if not target or not str(target).strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 60))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    try:
        threads = max(1, min(int(threads), 32))
    except (TypeError, ValueError):
        threads = 1
    paths = option_list(opts.get("paths"), DEFAULT_PATHS)
    hints = option_list(opts.get("session_hints"), DEFAULT_HINTS)

    domain = clean_domain_input(target)
    if not domain:
        return 2
    base = reach(domain, timeout)
    if not base:
        console.print(f"[red]✖ Unable to reach {domain}[/red]")
        return

    urls = [urljoin(base, p.lstrip("/")) for p in paths]
    console.print(f"[white]* Sampling {len(urls)} path(s) with {threads} thread(s), timeout={timeout}s[/white]")

    rows = []
    failures = []
    with Progress(SpinnerColumn(), TextColumn("{task.completed}/{task.total}"), BarColumn(), console=console) as prog:
        task = prog.add_task("Fetching…", total=len(urls))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(fetch, url, timeout): url for url in urls}
            for fut in as_completed(futures):
                url = futures[fut]
                code, hdrs = fut.result()
                if code is None:
                    failures.append((url, hdrs.get("_fetch_error", "request failed")))
                    prog.advance(task)
                    continue
                sc = hdrs.get("Set-Cookie", "")
                for name, val, attrs in parse_cookies(sc):
                    sens, sec, httponly, ss, dom, path, risk = assess_cookie(name, attrs, hints)
                    rows.append((
                        url,
                        name,
                        "Y" if sens else "N",
                        "Y" if sec else "N",
                        "Y" if httponly else "N",
                        ss or "-",
                        dom or "-",
                        path or "-",
                        risk
                    ))
                prog.advance(task)

    table = Table(title=f"Session Cookie Security – {domain}", header_style="bold magenta")
    for col, style in [
        ("URL","cyan"),("Cookie","green"),("Sensitive","yellow"),
        ("Secure","white"),("HttpOnly","white"),("SameSite","blue"),
        ("Domain","magenta"),("Path","magenta"),("Risk","red")
    ]:
        table.add_column(col, style=style, overflow="fold")

    if rows:
        for r in rows:
            table.add_row(*map(str, r))
        console.print(table)
    elif failures and len(failures) == len(urls):
        console.print("[red](!) Every cookie probe failed; no absence claim was made.[/red]")
    else:
        console.print("[yellow](!) No Set-Cookie headers observed.[/yellow]")

    if failures and len(failures) == len(urls):
        console.print("[red][!] Session cookie analysis failed[/red]")
    else:
        console.print("[green][*] Session hijacking passive analysis completed[/green]")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        if rows:
            export_console.print(table)
        else:
            export_console.print("(!) No Set-Cookie headers observed.")
        export_console.print("[*] Session hijacking passive analysis completed")
        write_to_file(os.path.join(out, "session_hijack_passive.txt"), export_console.export_text())
    return {"status": "error" if failures and len(failures) == len(urls) else "success", "failures": failures, "rows": rows}


if __name__ == "__main__":
    tgt = sys.argv[1] if len(sys.argv) > 1 else ""
    thr = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_THREADS
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            pass
    run(tgt, thr, opts)
