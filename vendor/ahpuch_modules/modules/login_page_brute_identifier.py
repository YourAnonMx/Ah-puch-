#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, web_target_base, write_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

console = Console()
PARTIAL_EXIT_CODE = 3
MAX_REDIRECTS = 5
BASE_CANDIDATES = [
    "/login", "/signin", "/sign-in", "/user/login", "/account/login", "/auth/login", "/session/login",
    "/member/login", "/dashboard/login", "/admin/login", "/cpanel", "/wp-login.php", "/login.html",
    "/login.php", "/administrator", "/auth", "/account", "/user", "/portal", "/signin.php", "/sign-in.php",
]


def build_paths(opts):
    paths = list(BASE_CANDIDATES)
    for extra in opts.get("paths", []):
        if str(extra).startswith("/"):
            paths.append(str(extra))
    paths_file = opts.get("paths_file")
    if paths_file and os.path.isfile(paths_file):
        with open(paths_file, encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                path = line.strip()
                if path.startswith("/"):
                    paths.append(path)
    return sorted(set(paths))


def _same_origin(root: str, candidate: str) -> bool:
    try:
        left = urlparse(root)
        right = urlparse(candidate)
    except ValueError:
        return False
    return (
        right.scheme in {"http", "https"}
        and left.scheme == right.scheme
        and left.netloc.lower() == right.netloc.lower()
    )


def fetch_page(args):
    url, timeout, follow = args
    if not str(url or "").strip():
        return {"url": url, "state": "invalid-target", "status": None, "html": "", "error": "empty url"}
    current = url
    for hop in range(MAX_REDIRECTS + 1):
        try:
            response = requests.get(current, timeout=timeout, verify=True, allow_redirects=False)
        except (requests.RequestException, OSError) as exc:
            return {
                "url": current,
                "state": "transport-error",
                "status": None,
                "html": "",
                "error": f"{type(exc).__name__}: {exc}",
            }
        status = int(response.status_code)
        if follow and status in {301, 302, 303, 307, 308}:
            location = response.headers.get("Location", "")
            candidate = urljoin(current, location) if location else ""
            if not candidate or not _same_origin(url, candidate):
                return {
                    "url": current,
                    "state": "http-negative",
                    "status": status,
                    "html": "",
                    "redirect_to": candidate or location,
                    "reason": "redirect-outside-origin" if candidate else "redirect-without-location",
                }
            if hop >= MAX_REDIRECTS:
                return {
                    "url": current,
                    "state": "http-negative",
                    "status": status,
                    "html": "",
                    "redirect_to": candidate,
                    "reason": "redirect-limit",
                }
            current = candidate
            continue
        content_type = response.headers.get("Content-Type", "").lower()
        html = response.text if "html" in content_type else ""
        if not response.ok:
            return {"url": current, "state": "http-negative", "status": status, "html": html}
        return {"url": current, "state": "success", "status": status, "html": html}
    return {"url": current, "state": "http-negative", "status": None, "html": "", "reason": "redirect-limit"}


def derive_base(target, timeout):
    probes = []
    explicit = "://" in str(target)
    candidates = [web_target_base(target)] if explicit else [web_target_base(target, scheme) for scheme in ("https", "http")]
    for candidate in candidates:
        probe = fetch_page((candidate, timeout, True))
        probes.append({key: value for key, value in probe.items() if key != "html"})
        if probe.get("state") in {"success", "http-negative"}:
            return str(probe.get("url", candidate)).rstrip("/"), probes
    return None, probes


def parse_forms(html, base_url):
    out = []
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        method = form.get("method", "GET").upper()
        action = urljoin(base_url, form.get("action") or base_url)
        inputs = form.find_all("input")
        buttons = form.find_all("button")
        user = passw = None
        tokens = []
        for inp in inputs:
            name = inp.get("name", "")
            input_type = inp.get("type", "").lower()
            if input_type == "password" or "pwd" in name.lower() or "pass" in name.lower():
                passw = name or passw
            if input_type in ("text", "email") or any(key in name.lower() for key in ("user", "email", "login")):
                user = name or user
            if input_type == "hidden" and any(key in name.lower() for key in ("csrf", "token", "auth")):
                tokens.append(name)
        if not passw:
            for button in buttons:
                text = button.get_text(strip=True).lower()
                if "login" in text or "sign in" in text:
                    passw = "-"
                    user = user or "-"
        if passw:
            out.append((method, action, user or "-", passw or "-", ",".join(tokens) or "-"))
    return out


def analyse(target, threads, opts):
    domain = clean_domain_input(target)
    threads = max(1, int(threads))
    if not domain:
        console.print("[yellow]✖ Empty target is not applicable[/yellow]")
        return 0
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    follow = bool(int(opts.get("follow_redirects", 1)))
    base, base_probes = derive_base(target, timeout)
    if not base:
        Path("login_page_identifier.json").write_text(
            json.dumps({"target": domain, "probes": base_probes, "findings": []}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        console.print("[red]✖ Unable to reach target due to transport failure[/red]")
        return 2

    paths = build_paths(opts)
    urls = [base] + [base + path for path in paths]
    console.print(f"[*] Scanning {len(urls)} pages for login forms with {threads} threads\n")
    args = [(url, timeout, follow) for url in urls]
    probes = list(base_probes)
    pages = []
    with Progress(SpinnerColumn(), TextColumn("{task.fields[url]}", justify="right"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Fetching…", total=len(urls), url="")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            for probe in pool.map(fetch_page, args):
                probes.append({key: value for key, value in probe.items() if key != "html"})
                pages.append(probe)
                progress.update(task, advance=1, url=urlparse(str(probe.get("url", ""))).path or "/")

    findings = []
    for probe in pages:
        if probe.get("state") == "success" and probe.get("html"):
            for form in parse_forms(str(probe["html"]), str(probe["url"])):
                findings.append((str(probe["url"]), *form))

    if findings:
        table = Table(title=f"Login Forms – {domain}", header_style="bold magenta")
        for column, style in (("Page", "cyan"), ("Method", "green"), ("Action", "yellow"), ("User", "white"), ("Pass", "white"), ("Tokens", "blue")):
            table.add_column(column, style=style, overflow="fold")
        for row in findings:
            table.add_row(*row)
        console.print(table)
    else:
        console.print("[yellow]No login forms detected in completed observations[/yellow]")

    completed = sum(row.get("state") in {"success", "http-negative"} for row in probes)
    errors = sum(row.get("state") == "transport-error" for row in probes)
    structured = [
        {"page": row[0], "method": row[1], "action": row[2], "user": row[3], "password": row[4], "tokens": row[5]}
        for row in findings
    ]
    Path("login_page_identifier.json").write_text(
        json.dumps({"target": base, "probes": probes, "findings": structured}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    summary = {"pages_scanned": len(urls), "forms_found": len(findings), "unique_actions": len({row[2] for row in findings}), "transport_errors": errors}
    console.print(Panel(
        f"Pages: {summary['pages_scanned']}  Forms: {summary['forms_found']}  Actions: {summary['unique_actions']}  Transport errors: {errors}",
        title="Summary",
        style="bold white",
    ))
    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, domain)
        ensure_directory_exists(out)
        write_to_file(os.path.join(out, "login_forms.json"), json.dumps(structured, indent=2, ensure_ascii=False))

    if completed == 0 and errors:
        return 2
    if completed and errors:
        return PARTIAL_EXIT_CODE
    return 0


def main():
    if len(sys.argv) < 3:
        console.print("Error")
        return 1
    target = sys.argv[1]
    threads = int(sys.argv[2])
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        opts = {}
    opts.setdefault("timeout", DEFAULT_TIMEOUT)
    opts.setdefault("follow_redirects", 1)
    return analyse(target, threads, opts)


if __name__ == "__main__":
    raise SystemExit(main())
