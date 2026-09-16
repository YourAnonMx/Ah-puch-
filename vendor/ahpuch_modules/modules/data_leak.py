#!/usr/bin/env python3
"""Bounded public data-leak lookup module retained from the legacy catalog."""

from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()
DEFAULT_EMAIL_PREFIXES = ("admin", "contact", "info", "support", "sales", "webmaster", "postmaster")
MAX_EMAILS = 64
MAX_WORKERS = 16
MAX_TIMEOUT = 60


def clean_domain_input(value: str) -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    return parsed.netloc or parsed.path.split("/", 1)[0]


def generate_emails(domain: str, requested: list[str] | None = None) -> list[str]:
    values = requested or [f"{prefix}@{domain}" for prefix in DEFAULT_EMAIL_PREFIXES]
    return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))[:MAX_EMAILS]


def parse_breaches(html: str) -> list[dict[str, object]]:
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    if table is None:
        return []
    rows: list[dict[str, object]] = []
    for row in table.find_all("tr")[1:]:
        columns = [cell.get_text(" ", strip=True) for cell in row.find_all("td")]
        if len(columns) >= 3:
            rows.append({"name": columns[0], "date": columns[1], "data_classes": [item.strip() for item in columns[2].split(",") if item.strip()]})
    return rows


def check_email(email: str, timeout: int) -> dict[str, object]:
    url = f"https://leak-lookup.com/search?query={quote(email)}"
    try:
        response = requests.get(url, headers={"User-Agent": "AhPuchDataLeakChecker/2"}, timeout=timeout, verify=True, allow_redirects=False)
    except (requests.RequestException, OSError) as exc:
        return {"email": email, "status": "transport-error", "error": f"{type(exc).__name__}: {exc}", "breaches": []}
    if response.status_code != 200:
        return {"email": email, "status": "http-error", "http_status": response.status_code, "breaches": []}
    if "no leaks found" in response.text.casefold():
        return {"email": email, "status": "no-results", "breaches": []}
    return {"email": email, "status": "results", "breaches": parse_breaches(response.text)}


def run(target: str, threads: int = 4, opts: dict | None = None) -> int:
    options = opts if isinstance(opts, dict) else {}
    domain = clean_domain_input(target)
    if not domain:
        return 2
    try:
        timeout = max(1, min(int(options.get("timeout", 15)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = 15
    raw_emails = options.get("emails") or options.get("email")
    requested = raw_emails if isinstance(raw_emails, list) else ([raw_emails] if raw_emails else None)
    emails = generate_emails(domain, requested)
    try:
        workers = max(1, min(int(threads or 1), MAX_WORKERS))
    except (TypeError, ValueError):
        workers = 1
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(emails) or 1)) as pool:
        futures = [pool.submit(check_email, email, timeout) for email in emails]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda row: str(row.get("email", "")))
    payload = {"target": target, "domain": domain, "status": "success", "emails": results, "timeout": timeout, "workers": workers}
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    try:
        options = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except json.JSONDecodeError:
        options = {}
    raise SystemExit(run(target, threads, options))
