#!/usr/bin/env python3
"""Public leak-index monitoring with bounded, non-authenticated requests."""

from __future__ import annotations

import concurrent.futures
import json
import sys
from urllib.parse import quote

import requests

MAX_WORKERS = 8
MAX_TIMEOUT = 60


def _query_scylla(domain: str, timeout: int) -> dict[str, object]:
    try:
        response = requests.get(
            f"https://scylla.sh/search?q=email:*@{quote(domain)}&size=100",
            timeout=timeout,
            headers={"User-Agent": "Ah-Puch/10"},
            verify=True,
            allow_redirects=False,
        )
        if not response.ok:
            return {"source": "scylla", "status": "http-error", "http_status": response.status_code, "rows": []}
        return {"source": "scylla", "status": "success", "rows": response.json()}
    except (requests.RequestException, OSError, TypeError, ValueError) as exc:
        return {"source": "scylla", "status": "error", "error": f"{type(exc).__name__}: {exc}", "rows": []}


def _query_paste_index(domain: str, timeout: int) -> dict[str, object]:
    try:
        response = requests.get(
            f"https://psbdmp.ws/api/v3/search/{quote(domain)}",
            timeout=timeout,
            headers={"User-Agent": "Ah-Puch/10"},
            verify=True,
            allow_redirects=False,
        )
        if not response.ok:
            return {"source": "psbdmp", "status": "http-error", "http_status": response.status_code, "rows": []}
        payload = response.json()
        return {"source": "psbdmp", "status": "success", "rows": payload.get("data", []) if isinstance(payload, dict) else []}
    except (requests.RequestException, OSError, TypeError, ValueError) as exc:
        return {"source": "psbdmp", "status": "error", "error": f"{type(exc).__name__}: {exc}", "rows": []}


def run(target: str, threads: int = 4, opts: dict | None = None) -> int:
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", 30)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = 30
    try:
        workers = max(1, min(int(options.get("workers", threads or 1)), MAX_WORKERS))
    except (TypeError, ValueError):
        workers = min(max(1, int(threads or 1)), MAX_WORKERS)
    domain = str(target).strip()
    if not domain:
        print(json.dumps({"target": domain, "status": "inapplicable", "error": "target is required", "sources": []}, ensure_ascii=False, sort_keys=True))
        return 2
    functions = (_query_scylla, _query_paste_index)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(functions))) as pool:
        futures = [pool.submit(function, domain, timeout) for function in functions]
        sources = [future.result() for future in futures]
    print(json.dumps({"target": domain, "status": "success", "timeout": timeout, "workers": workers, "sources": sources}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        options = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except json.JSONDecodeError:
        options = {}
    raise SystemExit(run(target, int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4, options))
