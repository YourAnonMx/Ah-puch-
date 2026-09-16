#!/usr/bin/env python3
"""Native composites for the retired personal reconnaissance utilities.

The old utilities are represented here as named capability contracts.  Their
useful behavior is executed through the existing Ah-Puch target boundary, artifact and
timeout boundaries; the old interactive shells are not invoked.  This module
is intentionally deterministic when no active composite is selected, which
keeps the normal profile behavior unchanged.
"""
from __future__ import annotations

import hashlib
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

try:
    from .capability_plans import execution_plan, selected_capabilities
    from .industrial_routing import industrial_keywords, nmap_command, routes_from_record
    from .legacy_capability_registry import dispatch_plan as legacy_dispatch_plan, matrix_summary as legacy_matrix_summary
    from .runner_registry import inspect_runner, run_bounded
    from .service_routing import origins_from_record, parse_service
except ImportError:
    from capability_plans import execution_plan, selected_capabilities
    from industrial_routing import industrial_keywords, nmap_command, routes_from_record
    from legacy_capability_registry import dispatch_plan as legacy_dispatch_plan, matrix_summary as legacy_matrix_summary
    from runner_registry import inspect_runner, run_bounded
    from service_routing import origins_from_record, parse_service


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ADVISORY_SOURCE = ROOT / "data" / "advisories" / "reference-corpus"
DEFAULT_KNOWLEDGE_SOURCE = ROOT / "data" / "knowledge" / "reference-corpus"
REFERENCE_CORPUS_MANIFEST = ROOT / "data" / "REFERENCE_CORPUS_MANIFEST.tsv"
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
SOCIAL_RE = re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com|facebook\.com|instagram\.com|youtube\.com|t\.me)/[^\s\"'<>]+", re.I)
FILE_EXTENSIONS = {"js", "txt", "pdf", "xlsx", "doc", "docx", "csv", "zip", "jpg", "png", "rar", "apk"}
REFERENCE_TEXT_SUFFIXES = {
    ".c", ".cfg", ".csv", ".html", ".ini", ".json", ".js", ".md", ".rst", ".sh",
    ".sql", ".svg", ".tex", ".toml", ".tsv", ".txt", ".xml", ".yaml", ".yml",
}
REFERENCE_EXECUTABLE_SUFFIXES = {".c", ".js", ".py", ".sh"}
EXTERNAL_DOMAIN_FILTER = {
    "wikipedia", "waze", "goo.gl", "wa.me", "tiktok", "unpkg", "vimeo", "godaddy",
    "akamaiedge.net", "pinterest", "wechat", "vk.com", "studiopress", "whatsapp",
    "akamai", "icao.int", "bit.ly", "aparat.com", "jquery", "android", "euronews",
    "forbes", "foreignaffairs", "france24", "huffingtonpost", "economist", "theguardian",
    "dailytimes", "washingtonpost", "theglobeandmail", "creativecommons", "foreignpolicy",
    "reuters", "maxcdn", "thefrontierpost", "theintercept", "weibo", "wordpress",
    "aljazeera", "amnesty", "bloomberg", "bbc", "cnn", "dailymail", "businessinsider",
    "facebook", "meta", "messenger", "fbcdn", "googletagmanager", "oculus", "twitter",
    "youtube", "instagram", "google", "apple", "microsoft", "twimg", "telegram",
    "t.me", "cloudflare", "jsdelivr", "youtu", "linkedin",
}
ICS_KEYWORDS = industrial_keywords()


CAPABILITY_CONTRACTS: dict[str, dict[str, Any]] = {
    "complete-assessment": {
        "label": "Complete assessment orchestration",
        "components": ("dns", "http", "crawl", "content", "tls", "network", "assessment", "report"),
        "canonical": "profile-deep + pipeline all + active consumers",
        "gate": "active and optional intrusive validation flags",
    },
    "complete-web-evidence": {
        "label": "Complete web evidence extraction",
        "components": ("crawl", "files", "domains", "dns", "certificates", "emails", "social", "banners", "parameters"),
        "canonical": "web-fanout + canonical evidence projection",
        "gate": "active for live crawl; projection remains local",
    },
    "subdomain-infrastructure": {
        "label": "Subdomain and infrastructure workflow",
        "components": ("subdomains", "ip-attribution", "nmap-vuln"),
        "canonical": "discovery + DNS attribution + Nmap vulnerability scripts",
        "gate": "active for Nmap validation",
    },
    "range-http-verification": {
        "label": "Range HTTP path verification",
        "components": ("masscan-http", "range-paths", "verified-200-only"),
        "canonical": "range discovery + bounded path verifier",
        "gate": "active; only target endpoints are queried",
    },
    "industrial-protocol-followup": {
        "label": "Industrial protocol keyword follow-up",
        "components": ("keyword-body-search", "protocol-nmap", "bounded-timeout"),
        "canonical": "industrial evidence + exact keyword follow-up",
        "gate": "active for URL retrieval and Nmap follow-up",
    },
    "device-inventory": {
        "label": "Device and service inventory",
        "components": ("subnet", "tcp-udp-ports", "resume", "http-cookies", "whatweb", "fingerprints", "inventory"),
        "canonical": "device surface + network profile + imported fingerprint rules",
        "gate": "active for network and HTTP probes",
    },
    "ssh-credential-audit": {
        "label": "SSH credential audit",
        "components": ("host-list", "ssh-endpoints", "credential-combinations", "ssh-command-test"),
        "canonical": "SSH endpoint queue + explicit credential-audit runner",
        "gate": "credential-audit must be explicitly enabled",
    },
    "dictionary-corpus": {
        "label": "Directory dictionary corpus builder",
        "components": ("micro", "short", "long", "cleaning", "deduplication", "typed-dictionary"),
        "canonical": "typed dictionary broker + local corpus builder",
        "gate": "local-only",
    },
    "advisory-correlation": {
        "label": "Advisory corpus and reference mapper",
        "components": ("markdown-advisory", "references", "priority-items", "denylist", "offline-index", "product-correlation"),
        "canonical": "offline advisory store + Markdown corpus importer",
        "gate": "local-only; executable references are cataloged, never executed",
    },
    "knowledge-index": {
        "label": "Knowledge and reference index",
        "components": ("markdown-notebook", "topic-index", "references", "provenance"),
        "canonical": "local metadata-only knowledge index",
        "gate": "local-only; source must be explicitly supplied",
    },
    "intelligence-catalog": {
        "label": "Information-gathering catalog",
        "components": ("passive-modules", "active-modules", "optional-api-modules", "module-options", "reports"),
        "canonical": "current public catalog + integrated capability composites",
        "gate": "per-module target-boundary and activity gates",
    },
}
CAPABILITY_CONTRACTS["complete-recon"] = {
    "label": "Complete integrated assessment cycle",
    "components": tuple(sorted({component for row in CAPABILITY_CONTRACTS.values() for component in row.get("components", ())})),
    "canonical": "all named integrated composites",
    "gate": "each component keeps its own gate",
}

def _write(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    if isinstance(value, bytes):
        temporary.write_bytes(value)
    else:
        temporary.write_text(value, encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def _json(path: Path, value: Any) -> None:
    _write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _read_texts(root: Path, per_file_limit: int = 8_000_000) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.stat().st_size > per_file_limit:
            continue
        if path.suffix.casefold() not in {".txt", ".log", ".json", ".jsonl", ".csv", ".html", ".xml", ".tsv"}:
            continue
        try:
            rows.append((str(path.relative_to(root)), path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return rows


def _urls(root: Path, run: Any) -> list[str]:
    values: set[str] = set()
    for value in getattr(run, "http_final_200", []) or []:
        values.add(str(value).rstrip(".,;:)]}"))
    for _source, text in _read_texts(root):
        values.update(match.rstrip(".,;:)]}") for match in URL_RE.findall(text))
    allowed = getattr(run, "_allowed", lambda _value: True)
    return sorted(value for value in values if value.startswith(("http://", "https://")) and allowed(value))


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _service_records(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    # The artifact bus and the normalized inventory are both valid producers.
    # Reading both prevents a capability from falling back to the raw target
    # when a prior stage already found a concrete service endpoint.
    for path in (root / "artifacts" / "queues" / "services.jsonl", root / "inventory" / "services.jsonl"):
        if not path.is_file() or path.is_symlink():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _service_origins(root: Path) -> list[str]:
    values: set[str] = set()
    for row in _service_records(root):
        values.update(origins_from_record(row))
    return sorted(values)


def _existing_verified_200(root: Path, run: Any) -> list[str]:
    allowed = getattr(run, "_allowed", lambda _value: True)
    candidates: list[str] = []
    direct = root / "http-reverification" / "verified_200_urls.txt"
    phase_files = sorted((root / "http-reverification").glob("*.verified_200_urls.txt"))
    for path in [direct, *phase_files]:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            candidates.extend(line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
    for value in getattr(run, "http_final_200", []) or []:
        candidates.append(str(value).strip())
    return sorted({
        value
        for value in candidates
        if value.startswith(("http://", "https://")) and allowed(value)
    })


def _web_evidence(root: Path, run: Any) -> dict[str, Any]:
    destination = root / "integrated-capabilities" / "web-evidence"
    urls = _urls(root, run)
    files = [value for value in urls if (urlsplit(value).path.rsplit("/", 1)[-1].split(".")[-1].casefold() in FILE_EXTENSIONS)]
    domains = sorted({urlsplit(value).hostname.lower().rstrip(".") for value in urls if urlsplit(value).hostname})
    filtered = [value for value in domains if not any(token in value.casefold() for token in EXTERNAL_DOMAIN_FILTER)]
    emails = sorted({match for _source, text in _read_texts(root) for match in EMAIL_RE.findall(text)})
    socials = sorted({match.rstrip(".,;:)]}") for _source, text in _read_texts(root) for match in SOCIAL_RE.findall(text)})
    injections = sorted({value for value in urls if "?" in value})
    banners = sorted({line.strip() for _source, text in _read_texts(root) for line in text.splitlines() if re.search(r"(?:^|\b)(?:server:|x-powered-by:|ssh-\d|http/\d)", line, re.I)})
    records = {
        "unique_urls": urls,
        "files": files,
        "domains": domains,
        "filtered_domains": filtered,
        "emails": emails,
        "social_links": socials,
        "injection_points": injections,
        "server_banners": banners,
    }
    for name, values in records.items():
        _write(destination / f"{name}.txt", "".join(f"{value}\n" for value in values))
    report = ["WEB EVIDENCE CAPABILITY REPORT", "", "This is a canonical projection of Ah-Puch evidence.", ""]
    for name, values in records.items():
        report.extend([f"[{name}]", *values, ""])
    _write(destination / "report.txt", "\n".join(report))
    _json(destination / "summary.json", {"status": "success", "counts": {key: len(value) for key, value in records.items()}, "artifacts": sorted(str(path.relative_to(root)) for path in destination.iterdir())})
    return {"status": "success", "urls": len(urls), "files": len(files), "domains": len(filtered), "injection_points": len(injections)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _http_get(url: str, timeout: float) -> tuple[int, str, dict[str, str]]:
    opener = urllib.request.build_opener(_NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "Ah-Puch/integrated-capability"})
    try:
        with opener.open(request, timeout=max(0.2, timeout)) as response:
            body = response.read(200_000).decode("utf-8", errors="replace")
            return int(getattr(response, "status", response.getcode())), body, dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(200_000).decode("utf-8", errors="replace"), dict(exc.headers.items()) if exc.headers else {}
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return 0, f"{type(exc).__name__}: {exc}", {}


def _bounded_workers(run: Any, attribute: str, fallback: int, count: int, ceiling: int) -> int:
    """Resolve one bounded pool size without allowing nested fan-out to explode."""
    try:
        requested = int(getattr(run.args, attribute, fallback) or fallback)
    except (TypeError, ValueError):
        requested = fallback
    if count <= 0:
        return 1
    return max(1, min(ceiling, requested, count))


def _range_http_verification(root: Path, run: Any) -> dict[str, Any]:
    destination = root / "integrated-capabilities" / "range-http-verification"
    path_file = Path(str(getattr(run.args, "range_paths", "") or ROOT / "data" / "wordlists" / "range.paths.txt")).expanduser()
    paths = [line.strip().lstrip("/") for line in path_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip() and not line.startswith("#")] if path_file.is_file() else []
    url_origins = {_origin(value) for value in _urls(root, run) if _origin(value)}
    service_origins = set(_service_origins(root))
    origins = sorted(url_origins | service_origins)
    verified_existing = _existing_verified_200(root, run)
    if verified_existing and not getattr(run.args, "dry_run", False):
        _write(destination / "verified-200.txt", "".join(f"{url}\n" for url in verified_existing))
        _write(
            destination / "requests.jsonl",
            "".join(
                json.dumps(
                    {"url": url, "status": 200, "source": "http-reverification", "reused": True},
                    ensure_ascii=False,
                    sort_keys=True,
                ) + "\n"
                for url in verified_existing
            ),
        )
        _json(
            destination / "summary.json",
            {
                "status": "success",
                "source": "http-reverification",
                "reused_pipeline_evidence": True,
                "paths": len(paths),
                "origins": len(origins),
                "service_origins": len(service_origins),
                "planned_requests": 0,
                "verified_200": len(verified_existing),
                "path_source": str(path_file),
            },
        )
        return {
            "status": "success",
            "source": "http-reverification",
            "reused_pipeline_evidence": True,
            "paths": len(paths),
            "origins": len(origins),
            "service_origins": len(service_origins),
            "planned_requests": 0,
            "verified_200": len(verified_existing),
        }
    max_requests = max(1, int(getattr(run.args, "range_max_requests", 4096)))
    planned = [{"origin": origin, "path": path, "url": origin.rstrip("/") + "/" + path} for origin in origins for path in paths][:max_requests]
    results: list[dict[str, Any]] = []
    active = bool(getattr(run.args, "active", False) and not getattr(run.args, "passive", False))
    if not active or getattr(run.args, "dry_run", False):
        status = "planned" if getattr(run.args, "dry_run", False) else "skipped"
        _json(destination / "summary.json", {"status": status, "reason": "active mode is required", "paths": len(paths), "origins": len(origins), "service_origins": len(service_origins), "planned_requests": len(planned)})
        _write(destination / "verified-200.txt", "")
        return {"status": status, "paths": len(paths), "origins": len(origins), "service_origins": len(service_origins), "planned_requests": len(planned), "verified_200": 0}
    timeout = min(max(1, int(getattr(run.args, "module_timeout", 60))), 15)
    allowed = getattr(run, "_allowed", lambda _value: True)

    def verify(item: dict[str, Any]) -> dict[str, Any]:
        url = str(item["url"])
        if not allowed(url):
            return {**item, "status": "outside-target"}
        code, body, headers = _http_get(url, timeout)
        result = {**item, "status": code, "response_bytes": len(body.encode("utf-8")), "server": headers.get("Server", "")}
        if code == 200:
            result["body_sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        return result

    workers = _bounded_workers(run, "integrated_http_workers", getattr(run.args, "threads", 4), len(planned), 32)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(verify, planned))
    verified = sorted(item["url"] for item in results if item.get("status") == 200)
    _write(destination / "requests.jsonl", "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in results))
    _write(destination / "verified-200.txt", "".join(f"{url}\n" for url in verified))
    _json(destination / "summary.json", {"status": "success", "paths": len(paths), "origins": len(origins), "service_origins": len(service_origins), "planned_requests": len(planned), "verified_200": len(verified), "path_source": str(path_file)})
    return {"status": "success", "paths": len(paths), "origins": len(origins), "service_origins": len(service_origins), "planned_requests": len(planned), "verified_200": len(verified)}


def _industrial_protocol_followup(root: Path, run: Any) -> dict[str, Any]:
    destination = root / "integrated-capabilities" / "industrial-protocol-followup"
    urls = _urls(root, run)
    texts = _read_texts(root)
    context_rows: list[dict[str, Any]] = []
    for source, text in texts:
        lowered = text.casefold()
        for keyword in ICS_KEYWORDS:
            if keyword in lowered:
                context_rows.append({"source": source, "keyword": keyword, "evidence": "local-artifact"})
    url_limit = max(1, int(getattr(run.args, "ics_max_urls", 64)))
    active = bool(getattr(run.args, "active", False) and not getattr(run.args, "passive", False) and not getattr(run.args, "dry_run", False))
    if active:
        timeout = min(max(1, int(getattr(run.args, "module_timeout", 60))), 15)
        candidate_urls = urls[:url_limit]

        def inspect_url(url: str) -> list[dict[str, Any]]:
            code, body, headers = _http_get(url, timeout)
            lowered = body.casefold()
            return [
                {"source": url, "keyword": keyword, "url": url, "status": code, "evidence": "http-body", "response_bytes": len(body.encode("utf-8")), "server": headers.get("Server", "")}
                for keyword in ICS_KEYWORDS
                if keyword in lowered
            ]

        workers = _bounded_workers(run, "integrated_http_workers", getattr(run.args, "threads", 4), len(candidate_urls), 16)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for rows in pool.map(inspect_url, candidate_urls):
                context_rows.extend(rows)
    unique_context = {(row["source"], row["keyword"]): row for row in context_rows}
    context = list(unique_context.values())
    route_map = {
        (route.endpoint.uri, route.protocol): route
        for row in _service_records(root)
        for route in routes_from_record(row)
    }
    routes = [route_map[key] for key in sorted(route_map)]
    nmap_runs: list[dict[str, Any]] = []
    runner = inspect_runner("network_service")
    if active and runner.get("available") and runner.get("contract_ok"):
        nmap_dir = destination / "nmap"
        nmap_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        candidate_routes = [
            route for route in routes[: max(1, int(getattr(run.args, "ics_max_followups", 32)))]
            if getattr(run, "_network_allowed", getattr(run, "_allowed", lambda _value: True))(route.endpoint.host)
        ]

        def run_followup(item: tuple[int, Any]) -> dict[str, Any]:
            index, route = item
            host = route.endpoint.host
            safe_protocol = re.sub(r"[^a-z0-9-]+", "-", route.protocol)
            stdout = nmap_dir / f"{index:03d}-{safe_protocol}-{route.endpoint.port}.stdout.txt"
            stderr = nmap_dir / f"{index:03d}-{safe_protocol}-{route.endpoint.port}.stderr.txt"
            command = nmap_command(str(runner["path"]), route)
            receipt = run_bounded(command, nmap_dir, stdout, stderr, min(10, max(1, int(getattr(run.args, "ics_timeout", 10)))))
            return {**route.as_dict(), **receipt}

        workers = _bounded_workers(run, "integrated_probe_workers", getattr(run.args, "threads", 4), len(candidate_routes), 8)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            nmap_runs = list(pool.map(run_followup, enumerate(candidate_routes, 1)))
    if getattr(run.args, "dry_run", False):
        status = "planned"
    elif not active:
        status = "skipped"
    elif routes and not (runner.get("available") and runner.get("contract_ok")):
        status = "partial"
    elif any(int(row.get("exit_code", 1)) != 0 for row in nmap_runs):
        status = "partial"
    else:
        status = "success"
    _write(destination / "context-indicators.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in sorted(context, key=lambda value: (str(value.get("keyword")), str(value.get("source"))))))
    _write(destination / "protocol-endpoints.jsonl", "".join(json.dumps(route.as_dict(), ensure_ascii=False, sort_keys=True) + "\n" for route in routes))
    _json(destination / "summary.json", {"status": status, "keywords": list(ICS_KEYWORDS), "context_indicators": len(context), "protocol_endpoints": len(routes), "nmap_runs": nmap_runs})
    return {"status": status, "context_indicators": len(context), "protocol_endpoints": len(routes), "nmap_runs": len(nmap_runs)}


def _service_targets(root: Path, run: Any) -> list[tuple[str, int]]:
    """Extract only SSH endpoints already present in scoped service evidence."""
    values: set[tuple[str, int]] = set()
    for row in _service_records(root):
        attributes = row.get("attributes") if isinstance(row.get("attributes"), dict) else row
        endpoint = parse_service(row.get("value", ""), attributes)
        if endpoint and endpoint.port == 22 and endpoint.protocol == "tcp":
            values.add((endpoint.host, endpoint.port))
        text = json.dumps(row, ensure_ascii=False)
        for host, raw_port in re.findall(r"\b([A-Za-z0-9_.:-]+):(\d{1,5})/(?:tcp|ssh)\b", text, re.I):
            try:
                port = int(raw_port)
            except ValueError:
                continue
            if port == 22:
                values.add((host.strip("[]"), port))
        host = str(row.get("host", "") or row.get("address", "")).strip("[]")
        raw_port = row.get("port")
        protocol = str(row.get("protocol", row.get("transport", "tcp"))).casefold()
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            port = 0
        if host and port == 22 and protocol in {"tcp", "ssh", ""}:
            values.add((host, port))
    # No raw-target fallback: SSH candidate auditing is evidence-driven.  A
    # hostname alone is not proof that port 22 is an SSH service.
    allowed = getattr(run, "_network_allowed", getattr(run, "_allowed", lambda _value: True))
    return sorted((host, port) for host, port in values if allowed(host))


def _nonempty_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and path.stat().st_size > 0


def _nonempty_any(root: Path, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        for path in root.glob(pattern):
            if _nonempty_file(path):
                return True
    return False


def _target_evidence(target: str) -> dict[str, int]:
    """Return conservative evidence flags derived from the operator target."""
    value = str(target or "").strip()
    parsed = urlsplit(value if "://" in value else f"//{value}")
    host = str(parsed.hostname or "").strip("[]").rstrip(".").casefold()
    is_url = parsed.scheme.casefold() in {"http", "https"} and bool(host)
    is_range = False
    try:
        is_range = "/" in value and ipaddress.ip_network(value, strict=False).prefixlen >= 0
    except ValueError:
        is_range = False
    is_ip = False
    if host:
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
    has_host = bool(host) and not is_range
    is_domain = has_host and not is_ip and "." in host
    return {
        "target": int(bool(value)),
        "target-bound-input": int(bool(value)),
        "target-url": int(is_url),
        "target-domain": int(is_domain),
        "host-input": int(has_host),
        "host-or-domain": int(has_host),
        "domain": int(is_domain),
        "domain-or-ip": int(is_domain or (has_host and is_ip)),
    }


def _ssh_credential_audit(root: Path, run: Any) -> dict[str, Any]:
    """Run bounded SSH candidates only after an explicit credential-audit opt-in."""
    destination = root / "integrated-capabilities" / "ssh-credential-audit"
    targets = _service_targets(root, run)
    user_value = str(getattr(run.args, "ssh_audit_users", "") or os.environ.get("AH_PUCH_SSH_AUDIT_USERS", "")).strip()
    password_value = str(getattr(run.args, "ssh_audit_passwords", "") or os.environ.get("AH_PUCH_SSH_AUDIT_PASSWORDS", "")).strip()
    user_path = Path(user_value).expanduser() if user_value else ROOT / "data" / "credentials" / "ssh-audit-users.txt"
    password_path = Path(password_value).expanduser() if password_value else ROOT / "data" / "credentials" / "ssh-audit-passwords.txt"
    users = [line.strip() for line in user_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip() and not line.lstrip().startswith("#")] if user_path.is_file() else []
    passwords = [line.rstrip("\n") for line in password_path.read_text(encoding="utf-8", errors="replace").splitlines() if line and not line.lstrip().startswith("#")] if password_path.is_file() else []
    attempts = [(host, port, user, password) for host, port in targets for user in users for password in passwords]
    max_attempts = max(1, min(int(getattr(run.args, "ssh_audit_max_attempts", 5000)), 5000))
    attempts = attempts[:max_attempts]
    enabled = bool(getattr(run.args, "credential_audit", False) and getattr(run.args, "active", False) and not getattr(run.args, "passive", False) and not getattr(run.args, "dry_run", False))
    if not enabled:
        status = "planned" if getattr(run.args, "dry_run", False) else "skipped"
        _json(destination / "summary.json", {"status": status, "reason": "--credential-audit and active mode are required", "targets": len(targets), "candidate_attempts": len(attempts)})
        _write(destination / "results.jsonl", "")
        return {"status": status, "targets": len(targets), "candidate_attempts": len(attempts), "successes": 0}
    try:
        import paramiko
    except ImportError:
        _json(destination / "summary.json", {"status": "unavailable", "reason": "paramiko is not installed", "targets": len(targets), "candidate_attempts": len(attempts)})
        return {"status": "unavailable", "targets": len(targets), "candidate_attempts": len(attempts), "successes": 0}

    timeout = min(max(1, int(getattr(run.args, "module_timeout", 60))), 15)
    workers = max(1, min(40, int(getattr(run.args, "ssh_audit_workers", 16))))

    def attempt(item: tuple[str, int, str, str]) -> dict[str, Any]:
        host, port, username, password = item
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(host, port=port, username=username, password=password, timeout=timeout, auth_timeout=timeout, banner_timeout=timeout, allow_agent=False, look_for_keys=False)
            _stdin, stdout, _stderr = client.exec_command('echo "Connection Test"', timeout=timeout)
            verified = b"Connection Test" in stdout.read(4096)
            return {"host": host, "port": port, "username": username, "status": "authenticated" if verified else "connected-not-verified", "password_sha256": hashlib.sha256(password.encode()).hexdigest()}
        except paramiko.AuthenticationException:
            return {"host": host, "port": port, "username": username, "status": "authentication-failed"}
        except (paramiko.SSHException, socket.error, OSError) as exc:
            return {"host": host, "port": port, "username": username, "status": "connection-error", "error": f"{type(exc).__name__}: {exc}"}
        finally:
            client.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, attempts))
    _write(destination / "results.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in results))
    successes = [row for row in results if row.get("status") == "authenticated"]
    _json(destination / "summary.json", {"status": "success", "targets": len(targets), "candidate_attempts": len(attempts), "successes": len(successes), "secrets": "passwords are never persisted; SHA-256 evidence only"})
    return {"status": "success", "targets": len(targets), "candidate_attempts": len(attempts), "successes": len(successes)}


_DIRECTORY_FILTERS = (
    re.compile(r"[\!(,%]"), re.compile(r".{100,}"), re.compile(r"[0-9]{4,}"),
    re.compile(r"[0-9]{3,}$"), re.compile(r"[a-z0-9]{32}"),
    re.compile(r"[0-9]+[A-Z0-9]{5,}"), re.compile(r"\/.*\/.*\/.*\/.*\/.*\/.*\/"),
    re.compile(r"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"),
    re.compile(r"[0-9]+[a-zA-Z]+[0-9]+[a-zA-Z]+[0-9]+"),
    re.compile(r"\.(png|jpg|jpeg|gif|svg|bmp|ttf|avif|wav|mp4|aac|ajax|css|all|)$"),
    re.compile(r"^http"),
)


def build_dictionary(source: Path, output: Path, tier: str) -> dict[str, Any]:
    """Build a compatible directory corpus without ``eval`` or unbounded memory."""
    source = source.expanduser().resolve()
    output = output.expanduser().resolve()
    if tier not in {"micro", "short", "long", "all"}:
        raise ValueError("dictionary tier must be micro, short, long or all")
    direct_pattern = {"micro": "*micro*.txt", "short": "*short*.txt", "all": "*all*.txt"}.get(tier)
    candidates = sorted(source.glob(direct_pattern)) if direct_pattern else []
    if not candidates:
        dictionary = source / "dict" if (source / "dict").is_dir() else source
        suffix = "_short.txt" if tier == "short" else "_long.txt" if tier in {"long", "all"} else "_short.txt"
        candidates = sorted(dictionary.glob(f"*{suffix}"))
        if tier == "all" and not candidates:
            candidates = sorted(dictionary.glob("*.txt"))
    candidates = [path for path in candidates if path.is_file() and not path.is_symlink()]
    if not candidates:
        raise FileNotFoundError(f"no directory corpus or category files for tier {tier} under {source}")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False, prefix=f".{output.name}.") as handle:
        temporary = Path(handle.name)
        for path in candidates:
            with path.open("r", encoding="utf-8", errors="replace") as source_handle:
                for raw in source_handle:
                    value = raw.strip()
                    if not value or any(pattern.search(value) for pattern in _DIRECTORY_FILTERS):
                        continue
                    handle.write(value + "\n")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False, prefix=f".{output.name}.sorted.") as sorted_handle:
        sorted_temporary = Path(sorted_handle.name)
    try:
        result = subprocess.run(
            ["sort", "-u", str(temporary), "-o", str(sorted_temporary)],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "sort failed while building directory corpus")
        sorted_temporary.replace(output)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("sort timed out while building directory corpus") from exc
    finally:
        temporary.unlink(missing_ok=True)
        sorted_temporary.unlink(missing_ok=True)
    output.chmod(0o600)
    count = sum(1 for _ in output.open("r", encoding="utf-8", errors="replace"))
    return {"status": "success", "tier": tier, "source_files": len(candidates), "lines": count, "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "output": str(output)}


def _bundled_advisory_cache() -> tuple[Path, str] | None:
    """Return a user-cache location keyed by the bundled corpus manifest."""
    manifest = REFERENCE_CORPUS_MANIFEST
    if not manifest.is_file():
        return None
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    cache_home = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))).expanduser()
    return cache_home / "ah-puch" / "reference-corpus" / "advisory", digest


def _copy_private(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copyfile(source, destination)
    try:
        destination.chmod(0o600)
    except OSError:
        pass


def _reuse_bundled_advisory_cache(destination: Path) -> dict[str, Any] | None:
    cached = _bundled_advisory_cache()
    if cached is None:
        return None
    cache_root, manifest_sha256 = cached
    metadata_path = cache_root / "cache-meta.json"
    summary_path = cache_root / "summary.json"
    index_path = cache_root / "index.jsonl"
    ids_path = cache_root / "cve-ids.txt"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if metadata.get("manifest_sha256") != manifest_sha256 or not all(path.is_file() for path in (index_path, ids_path)):
        return None
    _copy_private(index_path, destination / "index.jsonl")
    _copy_private(ids_path, destination / "cve-ids.txt")
    _copy_private(summary_path, destination / "summary.json")
    return {
        **summary,
        "source": str(DEFAULT_ADVISORY_SOURCE),
        "source_mode": "bundled",
        "cache": "reused",
    }


def index_advisory_corpus(source: Path, destination: Path) -> dict[str, Any]:
    """Index every local advisory file without importing or executing code.

    Markdown is parsed for CVE identifiers and references.  Other source
    files, including historical PoC material, still receive a path/size/hash
    record so the corpus is complete, but their contents are never imported,
    compiled, or executed.
    """
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if not source.is_dir():
        raise FileNotFoundError(source)
    if source == DEFAULT_ADVISORY_SOURCE.resolve():
        cached = _reuse_bundled_advisory_cache(destination)
        if cached is not None:
            return cached
    rows: list[dict[str, Any]] = []
    all_cves: set[str] = set()
    total_references = 0
    executable_files = 0
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            raw = path.read_bytes()
            size = len(raw)
        except OSError:
            continue
        suffix = path.suffix.casefold()
        identifiers: list[str] = []
        references: list[str] = []
        if suffix in REFERENCE_TEXT_SUFFIXES and size <= 4_000_000:
            text = raw.decode("utf-8", errors="replace")
            identifiers = sorted({value.upper() for value in CVE_RE.findall(text)})
            references = sorted(set(URL_RE.findall(text)))
        if not identifiers:
            match = re.search(r"CVE-\d{4}-\d{4,7}", path.name, re.I)
            if match:
                identifiers = [match.group(0).upper()]
        all_cves.update(identifiers)
        total_references += len(references)
        executable_material = suffix in REFERENCE_EXECUTABLE_SUFFIXES
        executable_files += int(executable_material)
        rows.append({
            "file": str(path.relative_to(source)),
            "kind": "executable-material-data" if executable_material else ("text" if suffix in REFERENCE_TEXT_SUFFIXES else "binary-or-opaque-data"),
            "bytes": size,
            "cves": identifiers,
            "references": references,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "metadata_only": True,
            "executable_material": executable_material,
        })
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write(destination / "index.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))
    _write(destination / "cve-ids.txt", "".join(f"{identifier}\n" for identifier in sorted(all_cves)))
    summary = {
        "status": "success",
        "source": str(source),
        "files": len(rows),
        "cves": len(all_cves),
        "references": total_references,
        "executable_material_files": executable_files,
        "metadata_only": True,
        "poc_execution": False,
    }
    _json(destination / "summary.json", summary)
    if source == DEFAULT_ADVISORY_SOURCE.resolve():
        cached = _bundled_advisory_cache()
        if cached is not None:
            cache_root, manifest_sha256 = cached
            _copy_private(destination / "index.jsonl", cache_root / "index.jsonl")
            _copy_private(destination / "cve-ids.txt", cache_root / "cve-ids.txt")
            _copy_private(destination / "summary.json", cache_root / "summary.json")
            _json(cache_root / "cache-meta.json", {
                "schema_version": 1,
                "manifest_sha256": manifest_sha256,
                "source": str(source),
            })
    return summary


def _advisory_correlation(root: Path, run: Any) -> dict[str, Any]:
    """Summarize local advisory indexing and product/version correlation."""
    source_value = str(getattr(run.args, "advisory_source", "") or "").strip()
    source = Path(source_value).expanduser() if source_value else DEFAULT_ADVISORY_SOURCE
    store_value = str(getattr(run.args, "advisory_store", "") or "").strip()
    parts: dict[str, Any] = {}
    if source.is_dir():
        try:
            parts["markdown_index"] = index_advisory_corpus(
                source,
                root / "integrated-capabilities" / "advisory-correlation",
            )
            parts["markdown_index"]["source_mode"] = "operator" if source_value else "bundled"
        except (OSError, ValueError) as exc:
            parts["markdown_index"] = {"status": "unavailable", "error": f"{type(exc).__name__}: {exc}"}
    else:
        parts["markdown_index"] = {
            "status": "skipped",
            "reason": "bundled advisory reference corpus is unavailable; provide --advisory-source for an operator corpus",
        }
    if store_value:
        product = _orchestration_evidence(
            root,
            "advisory-correlation",
            bool(getattr(run.args, "dry_run", False)),
        )
        product["advisory_store_configured"] = True
        parts["product_correlation"] = product
    else:
        parts["product_correlation"] = {
            "status": "skipped",
            "reason": "provide --advisory-store for offline product/version advisory correlation",
        }
    statuses = {str(value.get("status", "success")) for value in parts.values()}
    if statuses & {"unavailable", "failed", "partial"}:
        status = "partial"
    elif statuses <= {"skipped"}:
        status = "skipped"
    elif "planned" in statuses:
        status = "planned"
    else:
        status = "success"
    return {"status": status, **parts}


def _knowledge_index(root: Path, run: Any) -> dict[str, Any]:
    """Index Markdown metadata without copying or executing notebook code."""
    destination = root / "integrated-capabilities" / "knowledge-index"
    source_value = str(getattr(run.args, "knowledge_source", "") or "").strip()
    source = Path(source_value).expanduser() if source_value else DEFAULT_KNOWLEDGE_SOURCE
    if not source.is_dir():
        _json(destination / "summary.json", {
            "status": "skipped",
            "reason": "bundled knowledge reference corpus is unavailable; provide --knowledge-source for an operator corpus",
            "content_mode": "metadata-only",
            "executable_material_indexed": False,
        })
        _write(destination / "knowledge-index.jsonl", "")
        _write(destination / "topics.txt", "")
        return {"status": "skipped", "files": 0, "topics": 0, "references": 0}
    source = source.resolve()

    rows: list[dict[str, Any]] = []
    topics: set[str] = set()
    references: set[str] = set()
    executable_files = 0
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        suffix = path.suffix.casefold()
        executable_material = suffix in REFERENCE_EXECUTABLE_SUFFIXES
        executable_files += int(executable_material)
        text = raw.decode("utf-8", errors="replace") if suffix in REFERENCE_TEXT_SUFFIXES and len(raw) <= 4_000_000 else ""
        headings = [line.lstrip("#").strip() for line in text.splitlines() if line.startswith("#")][:20]
        title = headings[0] if headings else path.stem
        path_topics = {
            value.replace("_", " ").replace("-", " ").strip().casefold()
            for value in path.relative_to(source).parts[:-1]
            if value.strip()
        }
        path_topics.update(value.casefold() for value in re.findall(r"\b[A-Za-z][A-Za-z0-9+.-]{2,}\b", title))
        urls = sorted(set(URL_RE.findall(text)))
        topics.update(path_topics)
        references.update(urls)
        rows.append({
            "path": str(path.relative_to(source)),
            "title": title,
            "headings": headings,
            "topics": sorted(path_topics),
            "references": urls,
            "bytes": len(raw),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "kind": "executable-material-data" if executable_material else ("text" if suffix in REFERENCE_TEXT_SUFFIXES else "binary-or-opaque-data"),
            "content_mode": "metadata-only",
            "executable_material_indexed": False,
        })
    _write(destination / "knowledge-index.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))
    _write(destination / "topics.txt", "".join(f"{value}\n" for value in sorted(topics)))
    _json(destination / "summary.json", {
        "status": "success",
        "source": str(source),
        "files": len(rows),
        "topics": len(topics),
        "references": len(references),
        "executable_material_files": executable_files,
        "content_mode": "metadata-only",
        "executable_material_indexed": False,
    })
    return {
        "status": "success",
        "source": str(source),
        "source_mode": "operator" if source_value else "bundled",
        "files": len(rows),
        "topics": len(topics),
        "references": len(references),
        "executable_material_files": executable_files,
        "content_mode": "metadata-only",
        "executable_material_indexed": False,
    }


def _legacy_evidence(root: Path, run: Any, results: dict[str, Any]) -> dict[str, int]:
    """Collect only local evidence counts used by the legacy dispatch ledger."""
    verified = _existing_verified_200(root, run)
    urls = _urls(root, run)
    services = _service_records(root)
    ssh_services = _service_targets(root, run)
    target_flags = _target_evidence(str(getattr(run, "target", "")))
    industrial = results.get("industrial-protocol-followup", {})
    industrial_indicators = int(industrial.get("context_indicators", 0) or 0) if isinstance(industrial, dict) else 0
    camera_fingerprints = 0
    device_summary = root / "device-followup" / "summary.json"
    if device_summary.is_file() and not device_summary.is_symlink():
        try:
            payload = json.loads(device_summary.read_text(encoding="utf-8"))
            camera_fingerprints = int(payload.get("fingerprint_evidence", 0) or 0)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            camera_fingerprints = 0
    dictionary_value = str(getattr(run.args, "dictionary_source", "") or "").strip()
    dictionary_path = Path(dictionary_value).expanduser() if dictionary_value else ROOT / "data" / "wordlists" / "categories"
    advisory_value = str(getattr(run.args, "advisory_source", "") or "").strip()
    advisory_path = Path(advisory_value).expanduser() if advisory_value else DEFAULT_ADVISORY_SOURCE
    knowledge_value = str(getattr(run.args, "knowledge_source", "") or "").strip()
    knowledge_path = Path(knowledge_value).expanduser() if knowledge_value else DEFAULT_KNOWLEDGE_SOURCE
    dictionary_source = int(dictionary_path.is_dir() and not dictionary_path.is_symlink())
    advisory_source = int(advisory_path.is_dir() and not advisory_path.is_symlink())
    knowledge_source = int(knowledge_path.is_dir() and not knowledge_path.is_symlink())
    local_sources = dictionary_source + advisory_source + knowledge_source
    if "dictionary-corpus" in results and str(getattr(run.args, "dictionary_source", "") or "").strip() == "":
        dictionary_source = max(dictionary_source, 1)
    product_version = 0
    for row in services:
        text = json.dumps(row, ensure_ascii=False).casefold()
        if "product" in text or "version" in text or "technology" in text:
            product_version += 1
    range_inputs = 0
    path_value = str(getattr(run.args, "range_paths", "") or "").strip()
    if path_value and Path(path_value).expanduser().is_file():
        range_inputs = 1
    elif (ROOT / "data" / "wordlists" / "range.paths.txt").is_file():
        range_inputs = 1
    operator_range = 0
    try:
        operator_range = int(ipaddress.ip_network(str(getattr(run, "target", "")), strict=False).prefixlen >= 0)
    except ValueError:
        operator_range = 0
    dictionary_output = root / "integrated-capabilities" / "dictionary-corpus"
    filtered_entries = int(
        _nonempty_any(dictionary_output, ("*.txt", "*.json", "*.jsonl"))
        or str(results.get("dictionary-corpus", {}).get("status", "")) == "success"
    )
    crawl_output = int(_nonempty_any(root, ("web-fanout/crawl.urls.txt", "core/04-crawl/*.urls", "core/04-crawl/*.txt")))
    masscan_output = int(_nonempty_any(root, ("**/*masscan*", "**/*.masscan.*")))
    target_flags.update({
        "verified-http-origin": len(verified),
        "verified-https-origin": sum(urlsplit(value).scheme.casefold() == "https" for value in verified),
        "https-origin": sum(urlsplit(value).scheme.casefold() == "https" for value in verified),
        "verified-parameterized-url": sum("?" in value for value in verified),
        "parameterized-url": sum("?" in value for value in urls),
        "url-artifact": len(urls),
        "crawl-output": crawl_output,
        "http-response": len(verified),
        "services": len(services),
        "concrete-service": len(services),
        "concrete-host-or-service": len(services),
        "concrete-host": len(services),
        "concrete-http-service": int(bool(services) and bool(_service_origins(root))) or int(bool(verified)),
        "observed-ssh-service": len(ssh_services),
        "ics-keyword": industrial_indicators,
        "camera-fingerprint": camera_fingerprints,
        "verified-fingerprint": camera_fingerprints,
        "in-scope-camera-endpoint": camera_fingerprints,
        "local-dictionary-source": dictionary_source,
        "directory-dictionary": int(dictionary_source and not bool(getattr(run.args, "no_dictionaries", False))),
        "local-advisory-corpus": advisory_source,
        "local-notebook": knowledge_source,
        "local-path-dictionary": range_inputs,
        "bounded-paths": int(bool(range_inputs)),
        "operator-range": operator_range,
        "filtered-entries": filtered_entries,
        "operator-selected-tier": int(bool(str(getattr(run.args, "dictionary_tier", "") or "").strip())),
        "operator-selected-profile": int(bool(str(getattr(run.args, "integrated_capabilities", "") or "").strip())),
        "operator-selected-module": int(bool(str(getattr(run.args, "catalog_modules", "") or "").strip()) or bool(str(getattr(run.args, "integrated_capabilities", "") or "").strip())),
        "operator-options": int(bool(getattr(run, "option_overrides", {})) or bool(getattr(run, "tool_option_overrides", {})) or bool(getattr(run.args, "module_options", [])) or bool(getattr(run.args, "tool_options", []))),
        "discovered-host": int(_nonempty_any(root, ("queues/*.hosts.txt", "inventory/hosts.jsonl", "artifacts/queues/hosts.jsonl"))),
        "module-output": int(_nonempty_file(root / "module_status.jsonl")),
        "local-artifacts": int(bool(_read_texts(root)) or bool(results)),
        "offline-index": int(any(str(row.get("status", "")) in {"success", "planned"} for row in results.values() if isinstance(row, dict))),
        "typed-evidence": int(bool(results) or bool(_nonempty_file(root / "module_status.jsonl"))),
        "explicit-credential-audit": int(bool(getattr(run.args, "credential_audit", False) and getattr(run.args, "active", False) and not getattr(run.args, "dry_run", False))),
        "masscan-output": masscan_output,
    })
    return {
        **target_flags,
        "local-products": product_version,
        "local_products": product_version,
        "local_sources": local_sources,
    }


def _write_legacy_dispatch_plan(root: Path, selected: list[str], run: Any, results: dict[str, Any]) -> dict[str, Any]:
    evidence = _legacy_evidence(root, run, results)
    plan = legacy_dispatch_plan(selected, evidence)
    # The registry proves that each historical function has a callable
    # canonical bridge.  This second receipt records whether the selected
    # capability task actually reached that bridge in this run.  It does not
    # imply target contact: a planned/skipped result is still an intentional
    # adapter dispatch governed by the capability's evidence and activity
    # gates.
    for row in plan.get("functions", []):
        capability = str(row.get("canonical_capability", ""))
        result = results.get(capability)
        if not row.get("runtime_callable"):
            row["runtime_status"] = "configuration-error"
            continue
        if not isinstance(result, dict):
            row["runtime_status"] = "not-selected"
            row["adapter_result_status"] = "not-selected"
            continue
        result_status = str(result.get("status", "unknown"))
        row["adapter_result_status"] = result_status
        row["runtime_status"] = "adapter-failed" if result_status == "failed" else "adapter-dispatched"
    plan["observed_counts"] = evidence
    _json(root / "integrated-capabilities" / "legacy-dispatch-plan.json", plan)
    return plan


def write_execution_plan(root: Path, selected: list[str], args: Any) -> None:
    plan = execution_plan(selected)
    rows = []
    for name in selected:
        row = {"name": name, "implementation": "ah-puch-native", **CAPABILITY_CONTRACTS[name]}
        rows.append(row)
    _json(
        root / "integrated-capabilities" / "execution-plan.json",
        {
            "schema_version": 1,
            "selected": rows,
            "effective": plan,
            "active": bool(getattr(args, "active", False)),
            "legacy_matrix": legacy_matrix_summary(),
            "execution_model": "independent capability tasks are bounded and parallel; evidence-dependent stages remain ordered",
        },
    )


def _orchestration_evidence(root: Path, name: str, dry_run: bool) -> dict[str, Any]:
    plan = execution_plan(name)
    summary_path = root / "typed-pipeline" / "summary.json"
    summary: dict[str, Any] = {}
    if summary_path.is_file() and not summary_path.is_symlink():
        try:
            loaded = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                summary = loaded
        except (OSError, json.JSONDecodeError):
            summary = {}
    catalog_events = 0
    event_path = root / "module_status.jsonl"
    if event_path.is_file() and not event_path.is_symlink():
        for line in event_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("engine") in {"ahpuch_modules", "native_capability"}:
                catalog_events += 1
    if not summary:
        status = "planned" if dry_run else "partial"
        reason = "typed pipeline evidence is not present" if not dry_run else "dry-run plan has no execution evidence"
    else:
        status = str(summary.get("status", "partial"))
        reason = "typed pipeline and catalog evidence observed"
    return {
        "status": status,
        "reason": reason,
        "runtime_blocks": plan["runtime_blocks"],
        "catalog_ids": plan["catalog_ids"],
        "typed_pipeline_status": str(summary.get("status", "not-observed")),
        "typed_pipeline_rounds": int(summary.get("rounds", 0) or 0),
        "catalog_events": catalog_events,
    }


def run_selected(run: Any) -> dict[str, Any]:
    selected = selected_capabilities(getattr(run.args, "integrated_capabilities", ""))
    if not selected:
        return {"status": "not-selected", "capabilities": []}
    write_execution_plan(run.root, selected, run.args)
    def task(name: str) -> dict[str, Any]:
        if name == "complete-web-evidence":
            return _web_evidence(run.root, run)
        if name == "range-http-verification":
            return _range_http_verification(run.root, run)
        if name == "industrial-protocol-followup":
            return _industrial_protocol_followup(run.root, run)
        if name == "ssh-credential-audit":
            return _ssh_credential_audit(run.root, run)
        if name == "dictionary-corpus":
            source = Path(str(getattr(run.args, "dictionary_source", "") or ROOT / "data" / "wordlists" / "categories")).expanduser()
            tier = str(getattr(run.args, "dictionary_tier", "short"))
            output = run.root / "integrated-capabilities" / "dictionary-corpus" / f"web-dictionary-{tier}.txt"
            try:
                return build_dictionary(source, output, tier)
            except (OSError, RuntimeError, ValueError) as exc:
                return {"status": "unavailable", "error": f"{type(exc).__name__}: {exc}"}
        if name == "advisory-correlation":
            return _advisory_correlation(run.root, run)
        if name == "knowledge-index":
            return _knowledge_index(run.root, run)
        return _orchestration_evidence(run.root, name, bool(getattr(run.args, "dry_run", False)))

    requested_workers = getattr(run.args, "integrated_workers", 4)
    try:
        requested_workers = int(requested_workers)
    except (TypeError, ValueError):
        requested_workers = 4
    workers = max(1, min(8, requested_workers, len(selected)))
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    # These tasks write disjoint capability directories.  Their evidence
    # inputs are a snapshot produced by the ordered pipeline, so they can run
    # concurrently without racing the target boundary or the artifact bus.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(task, name): name for name in selected}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # one optional adapter must not erase sibling receipts
                errors[name] = f"{type(exc).__name__}: {exc}"
                results[name] = {"status": "failed", "error": errors[name]}
    results = {name: results.get(name, {"status": "failed", "error": "task did not return"}) for name in selected}
    dispatch = _write_legacy_dispatch_plan(run.root, selected, run, results)
    status = "success" if all(str(row.get("status", "success")) in {"success", "skipped", "planned"} for row in results.values()) else "partial"
    _json(run.root / "integrated-capabilities" / "summary.json", {
        "status": status,
        "selected": selected,
        "results": results,
        "parallel": {
            "workers": workers,
            "task_count": len(selected),
            "bounded": True,
            "errors": errors,
        },
        "legacy_dispatch": {
            "function_count": len(dispatch.get("functions", [])),
            "eligible_count": sum(bool(row.get("eligible")) for row in dispatch.get("functions", [])),
            "plan": "integrated-capabilities/legacy-dispatch-plan.json",
        },
    })
    return {"status": status, "selected": selected, "results": results, "parallel": {"workers": workers, "task_count": len(selected)}, "legacy_dispatch": dispatch}
