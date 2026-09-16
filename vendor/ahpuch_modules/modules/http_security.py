#!/usr/bin/env python3
import sys
import os
import re
import json
import requests
import urllib3
from urllib.parse import urlparse
from http.cookies import CookieError, SimpleCookie
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
console = Console()

DEFAULT_TIMEOUT = 10

def banner():
    console.print(Fore.GREEN + r"""
    =============================================
           Ah-Puch - Advanced HTTP Security Headers Check
    =============================================
    """)

def ensure_url_format(u: str) -> str:
    if not isinstance(u, str) or not u.strip():
        return ""
    u = u.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    return u

def get_headers(url: str, timeout: int):
    if not isinstance(url, str) or not url.strip():
        return None, "invalid target"
    try:
        resp = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        resp.raise_for_status()
        return dict(resp.headers), resp.text
    except (OSError, requests.RequestException, TypeError, ValueError) as e:
        return None, str(e)

def display_headers(headers: dict):
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Header", style="cyan", justify="left")
    tbl.add_column("Value", style="green", overflow="fold")
    for k, v in headers.items():
        tbl.add_row(k, v)
    console.print(tbl)

def analyze_security_headers(headers: dict):
    critical = {
        "Content-Security-Policy": None,
        "Strict-Transport-Security": None,
        "X-Content-Type-Options": None,
        "X-Frame-Options": None,
        "X-XSS-Protection": None,
        "Referrer-Policy": None,
        "Permissions-Policy": None,
    }
    out = {}
    for hdr in critical:
        val = headers.get(hdr)
        if val:
            out[hdr] = {"status": "Configured", "value": val}
        else:
            out[hdr] = {"status": "Missing", "value": None}
    return out

def format_security_table(checks: dict):
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Header", style="cyan")
    tbl.add_column("Status")
    tbl.add_column("Value", overflow="fold")
    for hdr, info in checks.items():
        status = info["status"]
        val = info["value"] or "-"
        color = "green" if status == "Configured" else "red"
        tbl.add_row(hdr, f"[{color}]{status}[/{color}]", val)
    console.print(tbl)

def scan_vulnerabilities(headers: dict):
    issues = []
    ctp = headers.get("X-Content-Type-Options", "").lower()
    if ctp != "nosniff":
        issues.append("X-Content-Type-Options not 'nosniff'")
    sts = headers.get("Strict-Transport-Security", "")
    if not sts:
        issues.append("Strict-Transport-Security header missing")
    else:
        if not re.search(r"max-age=\d+", sts):
            issues.append("Strict-Transport-Security missing 'max-age'")
        elif "max-age=0" in sts:
            issues.append("Strict-Transport-Security max-age=0")
    csp = headers.get("Content-Security-Policy", "")
    if csp and "default-src 'self'" not in csp:
        issues.append("Content‐Security‐Policy not restrictive (no default-src 'self')")
    xfo = headers.get("X-Frame-Options", "").upper()
    if xfo not in ("DENY", "SAMEORIGIN"):
        issues.append("X-Frame-Options not 'DENY' or 'SAMEORIGIN'")
    return issues

def format_vuln_table(issues: list[str]):
    if not issues:
        console.print(Fore.GREEN + "[+] No header‐based vulnerabilities detected.")
        return
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Issue", style="red")
    for issue in issues:
        tbl.add_row(issue)
    console.print(tbl)

def analyze_cookies(headers: dict):
    raw = headers.get("Set-Cookie", "")
    if not raw:
        return []
    cookie = SimpleCookie()
    try:
        cookie.load(raw)
    except (CookieError, TypeError, ValueError):
        return []
    out = []
    for name, morsel in cookie.items():
        flags = []
        if morsel.get("secure"):
            flags.append("Secure")
        if morsel.get("httponly"):
            flags.append("HttpOnly")
        ss = morsel.get("samesite")
        if ss:
            flags.append(f"SameSite={ss}")
        out.append({"cookie": f"{name}={morsel.value}", "flags": flags or ["None"]})
    return out

def format_cookie_table(cookies: list[dict]):
    if not cookies:
        console.print(Fore.YELLOW + "[!] No cookies to analyze.")
        return
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Cookie", style="cyan")
    tbl.add_column("Flags", style="green")
    for entry in cookies:
        tbl.add_row(entry["cookie"], ", ".join(entry["flags"]))
    console.print(tbl)

def detect_frameworks(body: str):
    patterns = {
        "WordPress": "wp-content",
        "Joomla": "Joomla!",
        "Drupal": "Drupal.settings",
        "Django": "csrftoken",
        "Ruby on Rails": "Rails",
        "Laravel": "laravel_session",
    }
    return [name for name, sig in patterns.items() if sig in body]

def format_frameworks(frameworks: list[str]):
    if frameworks:
        console.print(Fore.GREEN + f"[+] Detected Frameworks: {', '.join(frameworks)}")
    else:
        console.print(Fore.YELLOW + "[!] No common frameworks detected.")

def detect_server(headers: dict):
    srv = headers.get("Server", "Unknown")
    tech = "Unknown"
    low = srv.lower()
    if "nginx" in low:
        tech = "Nginx"
    elif "apache" in low:
        tech = "Apache"
    elif "iis" in low:
        tech = "Microsoft IIS"
    elif "cloudflare" in low:
        tech = "Cloudflare CDN"
    return srv, tech

def format_server(srv: str, tech: str):
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("Server Header", style="cyan")
    tbl.add_column("Technology", style="green")
    tbl.add_row(srv, tech)
    console.print(tbl)

def run(target: str, threads: int, opts: dict):
    if not isinstance(target, str) or not target.strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    banner()
    try:
        timeout = min(max(int(opts.get("timeout", DEFAULT_TIMEOUT)), 1), 60)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    json_out = bool(opts.get("json", False))
    url = ensure_url_format(target)
    console.print(Fore.WHITE + f"[*] Scanning {url}\n")
    headers, body = get_headers(url, timeout)
    if headers is None:
        console.print(Fore.RED + f"[!] Failed to fetch headers: {body}")
        return 1
    sec = analyze_security_headers(headers)
    vulns = scan_vulnerabilities(headers)
    cookies = analyze_cookies(headers)
    frameworks = detect_frameworks(body)
    srv_hdr, srv_tech = detect_server(headers)
    if json_out:
        result = {
            "target": url,
            "security_headers": sec,
            "vulnerabilities": vulns,
            "cookies": cookies,
            "frameworks": frameworks,
            "server": {"header": srv_hdr, "technology": srv_tech}
        }
        print(json.dumps(result, indent=2))
    else:
        display_headers(headers)
        format_security_table(sec)
        format_vuln_table(vulns)
        format_cookie_table(cookies)
        format_frameworks(frameworks)
        format_server(srv_hdr, srv_tech)
        console.print(Fore.WHITE + "[*] Analysis complete.")
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 1
    opts = {}
    if len(sys.argv) > 3:
        try:
            opts = json.loads(sys.argv[3])
        except (TypeError, ValueError):
            pass
    raise SystemExit(run(tgt, thr, opts))
