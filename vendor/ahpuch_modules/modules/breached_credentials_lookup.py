#!/usr/bin/env python3
"""HIBP/Pwned Passwords lookup retained as a bounded legacy module."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from urllib.parse import quote

import requests

from ahpuch_modules.config.settings import API_KEYS, DEFAULT_TIMEOUT

MAX_TIMEOUT = 60


def _timeout(options: dict) -> int:
    try:
        return max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT


def pwned_password(password: str, timeout: int) -> dict[str, object]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=timeout, verify=True, allow_redirects=False)
    except (requests.RequestException, OSError) as exc:
        return {"status": "transport-error", "error": f"{type(exc).__name__}: {exc}"}
    if response.status_code != 200:
        return {"status": "http-error", "http_status": response.status_code}
    for line in response.text.splitlines():
        if ":" not in line:
            continue
        raw_suffix, raw_count = line.split(":", 1)
        if raw_suffix.casefold() == suffix.casefold():
            try:
                return {"status": "found", "times_seen": int(raw_count)}
            except ValueError:
                return {"status": "parse-error", "error": "invalid pwned-passwords count"}
    return {"status": "not-found", "times_seen": 0}


def hibp_account(email: str, timeout: int) -> dict[str, object]:
    headers = {"User-Agent": "Ah-Puch/10"}
    api_key = API_KEYS.get("HIBP_API_KEY", "")
    if api_key:
        headers["hibp-api-key"] = api_key
    try:
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false",
            headers=headers,
            timeout=timeout,
            verify=True,
            allow_redirects=False,
        )
    except (requests.RequestException, OSError) as exc:
        return {"status": "transport-error", "error": f"{type(exc).__name__}: {exc}"}
    if response.status_code == 404:
        return {"status": "not-found", "breaches": []}
    if response.status_code in {401, 403}:
        return {"status": "api-key-required", "http_status": response.status_code, "breaches": []}
    if response.status_code != 200:
        return {"status": "http-error", "http_status": response.status_code, "breaches": []}
    try:
        return {"status": "found", "breaches": response.json()}
    except (TypeError, ValueError) as exc:
        return {"status": "parse-error", "error": f"{type(exc).__name__}: {exc}", "breaches": []}


def run(target: str, threads: int = 4, opts: dict | None = None) -> int:
    options = opts if isinstance(opts, dict) else {}
    timeout = _timeout(options)
    value = str(target or "").strip()
    if not value:
        print(json.dumps({"status": "inapplicable", "error": "email or password=VALUE is required"}, ensure_ascii=False, sort_keys=True))
        return 2
    if value.startswith("password="):
        password = value.split("=", 1)[1]
        if not password:
            print(json.dumps({"status": "inapplicable", "error": "password value is required"}, ensure_ascii=False, sort_keys=True))
            return 2
        # Never echo or persist the cleartext password.
        result = {"target_kind": "password", "sha1": hashlib.sha1(password.encode()).hexdigest().upper(), "result": pwned_password(password, timeout)}
    else:
        email = value
        result = {"target_kind": "email", "email": email, "result": hibp_account(email, timeout)}
    print(json.dumps({"status": "success", "timeout": timeout, "result": result}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        options = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except json.JSONDecodeError:
        options = {}
    raise SystemExit(run(target, int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4, options))
