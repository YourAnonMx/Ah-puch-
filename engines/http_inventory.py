#!/usr/bin/env python3
"""Canonical HTTP inventory and final-200 routing for Ah-Puch."""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit

try:
    from .asset_graph import canonical_origin, url_within_target
    from .runner_registry import admitted_path, run_bounded
    from .runtime_hardening import current_budget
except ImportError:
    from asset_graph import canonical_origin, url_within_target
    from runner_registry import admitted_path, run_bounded
    from runtime_hardening import current_budget

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


class _BudgetExceeded(RuntimeError):
    """Internal transport stop that is reported as a bounded observation."""


def _open(opener: urllib.request.OpenerDirector, request: urllib.request.Request, timeout: int):
    budget = current_budget()
    if budget is not None and not budget.reserve_request("http-request"):
        raise _BudgetExceeded("max_requests")
    return opener.open(request, timeout=timeout)


def _read_body(response: Any, maximum: int) -> tuple[bytes, bool]:
    budget = current_budget()
    limit = max(1, int(maximum))
    if budget is not None:
        remaining = budget.remaining("max_response_bytes")
        if remaining <= 0:
            raise _BudgetExceeded("max_response_bytes")
        limit = min(limit, remaining)
    body = response.read(limit)
    truncated = len(body) >= limit
    if budget is not None:
        budget.record_response(len(body), "response-bytes")
    return body, truncated


def _host(value: str) -> str:
    if value.startswith(("http://", "https://")):
        try:
            return (urlsplit(value).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    raw = value.strip()
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")].lower().rstrip(".")
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        raw = raw.rsplit(":", 1)[0]
    return raw.strip("[]").lower().rstrip(".")


def _candidate_filter(target: str, boundary_mode: str, hosts: list[str], urls: list[str]) -> Callable[[str], bool]:
    """Allow only caller-promoted hosts plus the original target host.

    The runner filters ``hosts`` and ``urls`` through the current target
    boundary before calling this module. This local allow-set ensures redirects
    cannot turn a merely related but unpromoted hostname into a live target.
    """
    promoted_hosts = {_host(value) for value in hosts if _host(value)}
    promoted_hosts.update(_host(value) for value in urls if _host(value))
    original = _host(target)
    if original:
        promoted_hosts.add(original)

    def allowed(value: str) -> bool:
        host = _host(value)
        return bool(host and host in promoted_hosts)

    return allowed


class _TargetRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, target: str, boundary_mode: str, chain: list[dict], allow_url: Callable[[str], bool] | None = None):
        super().__init__()
        self.target = target
        self.boundary_mode = boundary_mode
        self.chain = chain
        self.allow_url = allow_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        absolute = urljoin(req.full_url, newurl)
        allowed = self.allow_url(absolute) if self.allow_url else url_within_target(absolute, self.target, self.boundary_mode)
        self.chain.append({"status": int(code), "from": req.full_url, "to": absolute, "allowed": allowed})
        if not allowed:
            raise urllib.error.HTTPError(req.full_url, code, "redirect leaves target boundary", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, absolute)


def candidate_origins(
    target: str,
    hosts: list[str],
    urls: list[str],
    boundary_mode: str = "domain",
    allow_target: Callable[[str], bool] | None = None,
) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    allowed = allow_target or _candidate_filter(target, boundary_mode, hosts, urls)
    for url in urls:
        origin = canonical_origin(url)
        if origin and allowed(origin) and origin not in seen:
            seen.add(origin)
            values.append(origin)
    for host in hosts:
        if not allowed(host):
            continue
        display = f"[{host}]" if ":" in host and not host.startswith("[") else host
        for scheme in ("https", "http"):
            origin = f"{scheme}://{display}/"
            if allowed(origin) and origin not in seen:
                seen.add(origin)
                values.append(origin)
    if target.startswith(("http://", "https://")):
        origin = canonical_origin(target)
        if origin and allowed(origin) and origin not in seen:
            values.insert(0, origin)
    return values


def _metadata(opener: urllib.request.OpenerDirector, final_url: str, timeout: int) -> dict:
    request = urllib.request.Request(final_url, method="GET", headers={"User-Agent": "ah-puch/2", "Range": "bytes=0-65535"})
    try:
        response = _open(opener, request, max(1, min(timeout, 15)))
        body, truncated = _read_body(response, 65536)
        headers = dict(response.headers.items())
        status = int(getattr(response, "status", response.getcode()))
        url = response.geturl()
        response.close()
    except urllib.error.HTTPError as exc:
        try:
            body, truncated = _read_body(exc, 65536)
        except (Exception, _BudgetExceeded):
            body = b""
            truncated = False
        headers = dict(exc.headers.items()) if exc.headers else {}
        status = int(exc.code)
        url = exc.geturl() or final_url
    except Exception as exc:
        return {"metadata_error": f"{type(exc).__name__}: {exc}"}
    text = body.decode("utf-8", errors="replace")
    title_match = TITLE_RE.search(text)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    security_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() in {
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "permissions-policy",
            "referrer-policy",
        }
    }
    return {
        "metadata_status": status,
        "metadata_url": url,
        "server": headers.get("Server", ""),
        "content_type": headers.get("Content-Type", ""),
        "title": title[:1000],
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "bytes_sampled": len(body),
        "response_truncated": truncated,
        "security_headers": security_headers,
    }


def _probe(origin: str, target: str, boundary_mode: str, timeout: int, allow_url: Callable[[str], bool] | None = None) -> dict:
    chain: list[dict] = []
    handler = _TargetRedirect(target, boundary_mode, chain, allow_url)
    opener = urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(origin, method="HEAD", headers={"User-Agent": "ah-puch/2"})
    try:
        response = _open(opener, request, max(1, min(timeout, 15)))
        status = int(getattr(response, "status", response.getcode()))
        final_url = response.geturl()
        headers = dict(response.headers.items())
        response.close()
        row = {"origin": origin, "status": status, "final_url": final_url, "redirects": chain, "headers": headers, "error": ""}
        if status == 200:
            row.update(_metadata(opener, final_url, timeout))
        return row
    except urllib.error.HTTPError as exc:
        if exc.code in {405, 501}:
            try:
                request = urllib.request.Request(origin, method="GET", headers={"User-Agent": "ah-puch/2", "Range": "bytes=0-0"})
                response = _open(opener, request, max(1, min(timeout, 15)))
                status = int(getattr(response, "status", response.getcode()))
                final_url = response.geturl()
                headers = dict(response.headers.items())
                _read_body(response, 1)
                response.close()
                row = {"origin": origin, "status": status, "final_url": final_url, "redirects": chain, "headers": headers, "error": ""}
                if status == 200:
                    row.update(_metadata(opener, final_url, timeout))
                return row
            except Exception as inner:
                return {
                    "origin": origin,
                    "status": getattr(inner, "code", 0) or 0,
                    "final_url": origin,
                    "redirects": chain,
                    "headers": {},
                    "error": f"{type(inner).__name__}: {inner}",
                }
        return {
            "origin": origin,
            "status": int(exc.code),
            "final_url": exc.geturl() or origin,
            "redirects": chain,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "error": str(exc.reason),
        }
    except Exception as exc:
        return {
            "origin": origin,
            "status": 0,
            "final_url": origin,
            "redirects": chain,
            "headers": {},
            "error": f"{type(exc).__name__}: {exc}",
        }


def _timed_probe(
    origin: str,
    target: str,
    boundary_mode: str,
    timeout: int,
    allow_url: Callable[[str], bool] | None = None,
) -> dict:
    """Run the canonical probe and attach monotonic elapsed time."""
    started = time.perf_counter()
    row = _probe(origin, target, boundary_mode, timeout, allow_url)
    row["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
    return row


def _httpx_enrichment(
    destination: Path, origins: list[str], timeout: int, options: dict[str, Any] | None = None,
) -> dict[str, dict]:
    """Collect no-follow batch metadata without allowing redirects to widen the target."""
    binary = admitted_path("http_probe")
    if not binary or not origins:
        return {}
    inputs = destination / "httpx-inputs.txt"
    output = destination / "httpx-metadata.jsonl"
    inputs.write_text("\n".join(origins) + "\n", encoding="utf-8")
    inputs.chmod(0o600)
    options = options or {}
    command = [
        binary,
        "-l",
        str(inputs),
        "-silent",
        "-json",
        "-location",
        "-threads",
        str(max(1, int(options.get("threads", 50)))),
        "-timeout",
        str(max(1, min(int(options.get("timeout", timeout)), 120))),
        "-o",
        str(output),
    ]
    for option, flag in (("status_code", "-sc"), ("title", "-title"), ("server", "-server"), ("ip", "-ip"), ("cname", "-cname"), ("tech_detect", "-td")):
        if int(options.get(option, 1)):
            command.append(flag)
    if int(options.get("rate_limit", 0)) > 0:
        command.extend(["-rate-limit", str(int(options["rate_limit"]))])
    if int(options.get("deep", 0)):
        command.append("-favicon")
    run_bounded(
        command,
        destination,
        destination / "httpx.console.txt",
        destination / "httpx.stderr.txt",
        min(max(timeout, 30), 300),
    )
    rows: dict[str, dict] = {}
    if not output.is_file():
        return rows
    for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = str(item.get("url", ""))
        origin = canonical_origin(url)
        if not origin:
            continue
        rows[origin] = {
            "httpx_status": item.get("status_code"),
            "httpx_title": item.get("title", ""),
            "httpx_server": item.get("webserver", item.get("server", "")),
            "host_ip": item.get("host_ip", item.get("ip", "")),
            "cname": item.get("cname", []),
            "technologies": item.get("tech", item.get("technologies", [])),
            "cdn_name": item.get("cdn_name", item.get("cdn", "")),
            "location": item.get("location", ""),
            "scheme": item.get("scheme", ""),
            "method": item.get("method", ""),
        }
    return rows


def build_inventory(
    root: Path,
    target: str,
    hosts: list[str],
    urls: list[str],
    *,
    active: bool,
    timeout: int,
    boundary_mode: str = "domain",
    max_origins: int = 128,
    allow_target: Callable[[str], bool] | None = None,
    tool_options: dict[str, dict[str, Any]] | None = None,
) -> dict:
    destination = root / "http-inventory"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    allowed = allow_target or _candidate_filter(target, boundary_mode, hosts, urls)
    httpx_options = (tool_options or {}).get("httpx", {})
    live_limit = int(httpx_options.get("max_live_urls", max_origins))
    origins = candidate_origins(target, hosts, urls, boundary_mode, allow_target=allowed)[: max(1, min(max_origins, live_limit))]
    budget = current_budget()
    if active and budget is not None:
        origins = origins[: max(0, min(len(origins), budget.remaining("max_requests")))]
    rows: list[dict] = []
    enrichment: dict[str, dict] = {}
    if active:
        # Metadata collector does not follow redirects; target-bound Python probes own
        # redirect semantics and final-200 classification.
        enrichment = _httpx_enrichment(destination, origins, timeout, httpx_options)
        with ThreadPoolExecutor(max_workers=max(1, min(16, len(origins) or 1))) as executor:
            future_map = {
                executor.submit(_timed_probe, origin, target, boundary_mode, timeout, allowed): origin
                for origin in origins
            }
            indexed: dict[str, dict] = {}
            for future in as_completed(future_map):
                origin = future_map[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = {
                        "origin": origin,
                        "status": 0,
                        "final_url": origin,
                        "redirects": [],
                        "headers": {},
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                row.update(enrichment.get(origin, {}))
                indexed[origin] = row
            rows = [indexed[origin] for origin in origins if origin in indexed]
    else:
        rows = [
            {
                "origin": origin,
                "status": None,
                "final_url": origin,
                "redirects": [],
                "headers": {},
                "error": "not probed in passive mode",
            }
            for origin in origins
        ]

    if budget is not None:
        allowed_results = budget.remaining("max_results")
        if len(rows) > allowed_results:
            rows = rows[:allowed_results]
        budget.record_result(len(rows), "http-observations")

    ledger = destination / "observed.jsonl"
    ledger.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    ledger.chmod(0o600)
    final_200 = sorted(
        {
            str(row["final_url"])
            for row in rows
            if row.get("status") == 200 and allowed(str(row.get("final_url", "")))
        }
    )
    final_path = destination / "final-200.txt"
    final_path.write_text("\n".join(final_200) + ("\n" if final_200 else ""), encoding="utf-8")
    final_path.chmod(0o600)
    non200 = destination / "non-200.jsonl"
    non200.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
            if row.get("status") not in {200, None}
        ),
        encoding="utf-8",
    )
    non200.chmod(0o600)
    return {"origins": origins, "rows": rows, "final_200": final_200, "httpx_enriched": len(enrichment)}
