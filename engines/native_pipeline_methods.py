#!/usr/bin/env python3
"""Bounded built-in methods used by the typed reconnaissance pipeline.

The typed inventory contains capabilities that do not need a third-party
executable.  This module gives each such row a concrete execution contract and
keeps target contact behind the run's automatic boundary and activity gates. It never
installs software, invokes a shell, or persists API keys or raw secret
values.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

try:
    from . import advisory_store
    from .recon_pipeline import normalize_text
    from .dictionary_broker import resolve_info
    from .target_contract import (
        target_host_seed,
        target_http_origin_seeds,
        target_ip_seed,
        target_service_seeds,
        target_url_seeds,
    )
except ImportError:
    import advisory_store
    from recon_pipeline import normalize_text
    from dictionary_broker import resolve_info
    from target_contract import (
        target_host_seed,
        target_http_origin_seeds,
        target_ip_seed,
        target_service_seeds,
        target_url_seeds,
    )


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
ROUTE_RE = re.compile(r"[\"']((?:/|\.\.?/)[A-Za-z0-9_./?=&%:@+-]{2,512})[\"']")
SOURCE_MAP_RE = re.compile(r"(?:sourceMappingURL\s*=\s*|[\"'])([^\s\"']+\.map(?:\?[^\s\"']*)?)", re.I)
SECRET_PATTERNS = {
    "generic-api-key": re.compile(r"(?i)(?:api[_-]?key|token|secret)\s*[:=]\s*[\"']([^\"']{12,256})[\"']"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
}
SCHEMA_PATH_TOKENS = ("swagger", "openapi", "api-docs")
GRAPHQL_PATH_TOKENS = ("/graphql", "/graphiql", "/playground")
DEVICE_TERMS = ("modbus", "bacnet", "s7", "scada", "onvif", "rtsp", "camera", "nvr", "dvr")
INTRINSIC_PARAMETER_NAMES = ("debug", "admin", "test", "preview", "format", "callback", "redirect", "next", "lang", "locale", "page", "limit")
INTRINSIC_OPENAPI_PATHS = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/v3/api-docs")
INTRINSIC_GRAPHQL_PATHS = ("/graphql", "/graphiql", "/playground")
NATIVE_TOOL_IDS = frozenset({
    "native_target_boundary", "native_dns", "native_network", "native_http",
    "web_evidence_projection", "native_js_api", "jsfscan", "paraminer",
    "swagger_openapi", "graphql", "postman", "source_maps", "arachni",
    "zap_baseline", "zap_full", "nosqlmap", "hunter", "fofa",
    "native_device_ics", "native_advisory_correlation",
})


@dataclass
class NativeExecution:
    status: str
    reason: str
    text: str = ""
    records: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)
    receipt: dict[str, Any] = field(default_factory=dict)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def fetch_url(url: str, timeout: float, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    """Fetch one bounded URL. Tests replace this transport with local fixtures."""
    request_headers = {"User-Agent": "Ah-Puch/2.0", "Accept": "*/*"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=max(0.2, float(timeout))) as response:
            return int(getattr(response, "status", response.getcode()) or 0), response.read(1_000_000), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(1_000_000), dict(exc.headers.items()) if exc.headers else {}
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return 0, f"{type(exc).__name__}: {exc}".encode(), {}


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    path.chmod(0o600)
    return path


def _jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    return _write(path, "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))


def _allowed(run: Any, value: str, *, network: bool = False) -> bool:
    guard = getattr(run, "_network_allowed", None) if network else getattr(run, "_allowed", None)
    if not callable(guard):
        guard = getattr(run, "_allowed", None)
    return bool(guard(value)) if callable(guard) else True


def _timeout(run: Any) -> int:
    return max(1, min(int(getattr(run.args, "module_timeout", 30)), 30))


def _urls(values: list[str], run: Any) -> list[str]:
    result: list[str] = []
    for value in values:
        raw = str(value).strip()
        if not raw.startswith(("http://", "https://")):
            continue
        try:
            parsed = urlsplit(raw)
        except ValueError:
            continue
        if parsed.hostname and _allowed(run, raw):
            result.append(urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")))
    return list(dict.fromkeys(result))[: max(1, int(getattr(run.args, "pipeline_input_limit", 64)))]


def _dictionary_entries(run: Any, dictionary_class: str, *, limit: int = 256, technology: str = "") -> tuple[list[str], dict[str, Any]]:
    tier = str(getattr(run.args, "wordlist_tier", "micro") or "micro")
    if getattr(run.args, "no_dictionaries", False):
        return [], {
            "dictionary_class": dictionary_class,
            "dictionary_tier": tier,
            "dictionary_source": "disabled",
            "dictionary_path": "",
            "dictionary_available": False,
            "dictionary_entries": 0,
        }
    try:
        info = resolve_info(dictionary_class, tier=tier, technology=technology)
    except Exception as exc:
        return [], {
            "dictionary_class": dictionary_class,
            "dictionary_tier": tier,
            "dictionary_source": "error",
            "dictionary_path": "",
            "dictionary_available": False,
            "dictionary_entries": 0,
            "dictionary_error": f"{type(exc).__name__}: {exc}",
        }
    path = Path(str(info.get("path", "")))
    entries: list[str] = []
    if info.get("available") and path.is_file() and not path.is_symlink():
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                value = raw.strip()
                if not value or value.startswith("#") or "\x00" in value:
                    continue
                entries.append(value[:512])
                if len(entries) >= max(0, int(limit)):
                    break
        except OSError as exc:
            info = {**info, "source": "error", "available": False, "error": f"{type(exc).__name__}: {exc}"}
            entries = []
    return list(dict.fromkeys(entries)), {
        "dictionary_class": dictionary_class,
        "dictionary_tier": info.get("effective_tier") or info.get("requested_tier") or tier,
        "dictionary_source": info.get("source", ""),
        "dictionary_path": info.get("path", ""),
        "dictionary_available": bool(info.get("available")),
        "dictionary_entries": len(entries),
    }


def _hosts(values: list[str], run: Any) -> list[str]:
    result: list[str] = []
    for value in values:
        raw = str(value).strip().rstrip(".")
        if raw.startswith(("http://", "https://")):
            try:
                raw = urlsplit(raw).hostname or ""
            except ValueError:
                raw = ""
        try:
            if "/" in raw:
                ipaddress.ip_network(raw, strict=False)
                continue
        except ValueError:
            continue
        if raw and _allowed(run, raw, network=True):
            result.append(raw)
    return list(dict.fromkeys(result))[: max(1, int(getattr(run.args, "pipeline_input_limit", 64)))]


def _domain_hosts(values: list[str], run: Any) -> list[str]:
    result: list[str] = []
    for host in _hosts(values, run):
        try:
            ipaddress.ip_address(host.strip("[]"))
            continue
        except ValueError:
            result.append(host)
    return result


def _fofa_query_for(host: str) -> str:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return f'ip="{host.strip("[]")}"'
    except ValueError:
        return f'domain="{host}"'


def _normalized(tool: dict[str, Any], text: str, source: str, status: str = "success") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return normalize_text(text, list(tool["outputs"]), str(tool["id"]), source, status)


def _target_boundary(tool: dict[str, Any], run: Any, destination: Path) -> NativeExecution:
    target = str(run.target)
    lines = [target]
    host = target_host_seed(target)
    ip = target_ip_seed(target)
    if host:
        lines.append(host)
    if ip:
        lines.append(ip)
    lines.extend(target_http_origin_seeds(target))
    lines.extend(target_url_seeds(target))
    for service in target_service_seeds(target):
        parsed = urlsplit(service)
        if parsed.scheme in {"tcp", "udp"} and parsed.netloc:
            lines.append(f"{parsed.netloc}/{parsed.scheme}")
    text = "\n".join(dict.fromkeys(line for line in lines if line)) + "\n"
    records, rejected = _normalized(tool, text, "target-boundary.txt")
    artifact = _write(destination / "target-boundary.txt", text)
    return NativeExecution("success", "target boundary normalized", text, records, rejected, [artifact], {"targets": 1, "records": len(records)})


def _dns(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: list[str] = []
    for host in _hosts(inputs, run):
        try:
            answers = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            rows.append({"host": host, "status": "no-address", "error": f"{type(exc).__name__}: {exc}"})
            continue
        addresses: set[str] = set()
        for answer in answers:
            raw = str(answer[4][0]).split("%", 1)[0]
            try:
                address = str(ipaddress.ip_address(raw))
            except ValueError:
                continue
            if _allowed(run, address, network=True):
                addresses.add(address)
        rows.append({"host": host, "status": "success" if addresses else "no-address", "addresses": sorted(addresses)})
        lines.extend([host, *sorted(addresses)])
    text = "\n".join(lines) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "dns.jsonl")
    artifact = _jsonl(destination / "dns.jsonl", rows)
    return NativeExecution("success", "bounded native DNS attribution completed", text, records, rejected, [artifact], {"hosts": len(rows), "addresses": sum(len(row.get("addresses", [])) for row in rows)})


def _ports(expression: str) -> list[int]:
    ports: set[int] = set()
    for token in str(expression).split(","):
        token = token.strip()
        try:
            if "-" in token:
                start, end = (int(value) for value in token.split("-", 1))
                if 1 <= start <= end <= 65535 and end - start <= 1024:
                    ports.update(range(start, end + 1))
            elif token:
                value = int(token)
                if 1 <= value <= 65535:
                    ports.add(value)
        except ValueError:
            continue
    return sorted(ports)[:1024]


def _network(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    hosts = _hosts(inputs, run)
    ports = _ports(getattr(run.args, "range_ports", "80,443")) or [80, 443]
    rows: list[dict[str, Any]] = []
    lines: list[str] = []
    timeout = min(1.0, float(_timeout(run)))
    for host in hosts:
        for port in ports:
            status = "closed"
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    status = "open"
                    lines.append(f"{host}:{port}/tcp")
            except OSError:
                pass
            rows.append({"host": host, "port": port, "protocol": "tcp", "status": status})
    text = "\n".join(lines) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "network.jsonl")
    artifact = _jsonl(destination / "network.jsonl", rows)
    return NativeExecution("success", "bounded native TCP validation completed", text, records, rejected, [artifact], {"probes": len(rows), "open": len(lines)})


def _http(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    accepted_lines: list[str] = []
    for url in _urls(inputs, run):
        code, body, headers = fetch_url(url, _timeout(run))
        row = {
            "url": url,
            "status_code": code,
            "bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest() if code else "",
            "server": headers.get("Server", ""),
            "content_type": headers.get("Content-Type", ""),
            "location": headers.get("Location", ""),
        }
        rows.append(row)
        if code == 200:
            accepted_lines.append(url)
            if row["server"]:
                accepted_lines.append(f"Server: {row['server']}")
            if row["content_type"]:
                accepted_lines.append(f"Technology: content-type {row['content_type']}")
    text = "\n".join(accepted_lines) + ("\n" if accepted_lines else "")
    records, rejected = _normalized(tool, text, "http.jsonl")
    artifact = _jsonl(destination / "http.jsonl", rows)
    return NativeExecution("success", "bounded HTTP observation completed", text, records, rejected, [artifact], {"requests": len(rows), "status_200": sum(row["status_code"] == 200 for row in rows)})


def _safe_text_files(root: Path, *, limit: int = 4_000_000) -> list[tuple[Path, str]]:
    rows: list[tuple[Path, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.name.endswith("checksums.sha256"):
            continue
        if path.suffix.casefold() not in {".txt", ".log", ".json", ".jsonl", ".html", ".xml", ".js", ".map"}:
            continue
        try:
            if path.stat().st_size <= limit:
                rows.append((path, path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return rows[:2000]


def _projection(tool: dict[str, Any], run: Any, destination: Path) -> NativeExecution:
    found: set[str] = set()
    for _path, body in _safe_text_files(Path(run.root)):
        for match in URL_RE.findall(body):
            value = match.rstrip(".,;:)]}")
            if _allowed(run, value):
                found.add(value)
    text = "\n".join(sorted(found)) + ("\n" if found else "")
    records, rejected = _normalized(tool, text, "projection.txt")
    artifact = _write(destination / "projection.txt", text)
    return NativeExecution("success", "local web evidence projection completed", text, records, rejected, [artifact], {"urls": len(found), "contact": False})


def _javascript(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    candidates = [url for url in _urls(inputs, run) if urlsplit(url).path.casefold().endswith((".js", ".mjs"))]
    if not candidates:
        candidates = _urls(inputs, run)
    for url in candidates:
        code, body_bytes, headers = fetch_url(url, _timeout(run))
        body = body_bytes.decode("utf-8", errors="replace")
        content_type = headers.get("Content-Type", "").casefold()
        if code != 200 or ("javascript" not in content_type and not urlsplit(url).path.casefold().endswith((".js", ".mjs"))):
            rows.append({"url": url, "status_code": code, "analyzed": False})
            continue
        endpoints: set[str] = set()
        for absolute in URL_RE.findall(body):
            clean = absolute.rstrip(".,;:)]}")
            if _allowed(run, clean):
                endpoints.add(clean)
        for relative in ROUTE_RE.findall(body):
            candidate = urljoin(url, relative)
            if _allowed(run, candidate):
                endpoints.add(candidate)
        maps = {urljoin(url, value) for value in SOURCE_MAP_RE.findall(body) if _allowed(run, urljoin(url, value))}
        secret_types: list[str] = []
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(body):
                secret_types.append(name)
                lines.add(f"Secret candidate exposed in JavaScript: type={name} source={url} evidence_sha256={hashlib.sha256(body_bytes).hexdigest()}")
        lines.update(endpoints)
        lines.update(maps)
        rows.append({
            "url": url, "status_code": code, "analyzed": True, "bytes": len(body_bytes),
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(), "endpoints": sorted(endpoints),
            "source_maps": sorted(maps), "secret_candidate_types": secret_types,
        })
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "javascript.jsonl")
    artifact = _jsonl(destination / "javascript.jsonl", rows)
    return NativeExecution("success", "bounded JavaScript intelligence completed", text, records, rejected, [artifact], {"requests": len(rows), "analyzed": sum(bool(row.get("analyzed")) for row in rows)})


def _schema(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path, kind: str) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    dictionary_class = "technology" if kind == "graphql" else "api-path"
    dictionary_values, dictionary_receipt = _dictionary_entries(
        run,
        dictionary_class,
        limit=max(8, int(getattr(run.args, "pipeline_input_limit", 64))),
        technology="graphql" if kind == "graphql" else "",
    )
    intrinsic_paths = INTRINSIC_GRAPHQL_PATHS if kind == "graphql" else INTRINSIC_OPENAPI_PATHS
    dictionary_paths = [
        value if value.startswith("/") else f"/{value}"
        for value in dictionary_values
        if value and (kind != "graphql" or "graphql" in value.casefold() or "graphiql" in value.casefold())
    ]
    candidates: list[str] = []
    for seed in _urls(inputs, run):
        parsed = urlsplit(seed)
        if any(token in parsed.path.casefold() for token in (SCHEMA_PATH_TOKENS if kind == "openapi" else GRAPHQL_PATH_TOKENS)):
            candidates.append(seed)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        for path in (*intrinsic_paths, *dictionary_paths):
            candidate = urljoin(origin, path)
            if _allowed(run, candidate):
                candidates.append(candidate)
    for url in list(dict.fromkeys(candidates))[: max(1, int(getattr(run.args, "pipeline_input_limit", 64)))]:
        path = urlsplit(url).path.casefold()
        likely = any(token in path for token in (SCHEMA_PATH_TOKENS if kind == "openapi" else GRAPHQL_PATH_TOKENS))
        if not likely:
            continue
        code, body_bytes, headers = fetch_url(url, _timeout(run), {"Accept": "application/json"})
        body = body_bytes.decode("utf-8", errors="replace")
        detected = False
        parameters: set[str] = set()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if kind == "openapi" and isinstance(payload, dict) and ("openapi" in payload or "swagger" in payload):
            detected = True
            for endpoint, operation in (payload.get("paths") or {}).items():
                full = urljoin(url, str(endpoint))
                if _allowed(run, full):
                    lines.add(full)
                if isinstance(operation, dict):
                    for method in operation.values():
                        if isinstance(method, dict):
                            for parameter in method.get("parameters", []) or []:
                                if isinstance(parameter, dict) and parameter.get("name"):
                                    name = str(parameter["name"])
                                    parameters.add(name)
                                    if _allowed(run, full):
                                        lines.add(_mutated_url(full, name, ""))
            lines.add("Technology: OpenAPI schema")
        elif kind == "graphql" and code in {200, 400, 405} and (likely or "graphql" in body.casefold()):
            detected = True
            lines.add(url)
            lines.add("Technology: GraphQL endpoint")
        rows.append({"url": url, "status_code": code, "content_type": headers.get("Content-Type", ""), "detected": detected, "parameters": sorted(parameters)})
        lines.update(parameters)
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, f"{kind}.jsonl")
    artifact = _jsonl(destination / f"{kind}.jsonl", rows)
    return NativeExecution("success", f"bounded {kind} detection completed", text, records, rejected, [artifact], {"candidates": len(rows), "detected": sum(bool(row["detected"]) for row in rows), **dictionary_receipt})


def _postman(tool: dict[str, Any], run: Any, destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    for path, body in _safe_text_files(Path(run.root)):
        if "postman" not in body.casefold() and "_postman_id" not in body:
            continue
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            continue
        for value in URL_RE.findall(json.dumps(payload, ensure_ascii=False)):
            clean = value.rstrip(".,;:)]}")
            if _allowed(run, clean):
                lines.add(clean)
        rows.append({"artifact": str(path.relative_to(run.root)), "urls": len(lines)})
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "postman.jsonl")
    artifact = _jsonl(destination / "postman.jsonl", rows)
    return NativeExecution("success", "local Postman collection extraction completed", text, records, rejected, [artifact], {"collections": len(rows), "contact": False})


def _source_maps(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    for url in _urls(inputs, run):
        if not urlsplit(url).path.casefold().endswith((".js", ".mjs")):
            continue
        code, body_bytes, _headers = fetch_url(url, _timeout(run))
        body = body_bytes.decode("utf-8", errors="replace")
        maps = sorted({urljoin(url, value) for value in SOURCE_MAP_RE.findall(body) if _allowed(run, urljoin(url, value))}) if code == 200 else []
        rows.append({"url": url, "status_code": code, "source_maps": maps})
        lines.update(maps)
        for value in maps:
            lines.add(f"Exposed JavaScript source map candidate: {value}")
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "source-maps.jsonl")
    artifact = _jsonl(destination / "source-maps.jsonl", rows)
    return NativeExecution("success", "bounded source-map discovery completed", text, records, rejected, [artifact], {"scripts": len(rows), "source_maps": sum(len(row["source_maps"]) for row in rows)})


def _mutated_url(url: str, key: str, value: str) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append((key, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), ""))


def _hidden_parameters(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    maximum = max(1, min(int(getattr(run.args, "parameter_probe_limit", 24)), 100))
    dictionary_values, dictionary_receipt = _dictionary_entries(run, "parameter", limit=maximum)
    names = tuple(dict.fromkeys([*INTRINSIC_PARAMETER_NAMES, *dictionary_values]))
    requests = 0
    for url in _urls(inputs, run):
        baseline_code, baseline_body, _headers = fetch_url(url, _timeout(run))
        baseline_digest = hashlib.sha256(baseline_body).hexdigest()
        for name in names:
            if requests >= maximum:
                break
            candidate = _mutated_url(url, name, "ah-puch-probe")
            if not _allowed(run, candidate):
                continue
            code, body, _headers = fetch_url(candidate, _timeout(run))
            requests += 1
            changed = code != baseline_code or abs(len(body) - len(baseline_body)) >= max(32, len(baseline_body) // 10)
            rows.append({"url": url, "parameter": name, "status_code": code, "baseline_status": baseline_code, "differential": changed, "baseline_sha256": baseline_digest, "response_sha256": hashlib.sha256(body).hexdigest()})
            if changed:
                lines.add(candidate)
                lines.add(f"Exposed hidden parameter candidate: {name} at {url}")
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "hidden-parameters.jsonl")
    artifact = _jsonl(destination / "hidden-parameters.jsonl", rows)
    return NativeExecution("success", "bounded differential parameter discovery completed", text, records, rejected, [artifact], {"requests": requests, "candidates": sum(bool(row["differential"]) for row in rows), **dictionary_receipt})


def _nosql(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    maximum = max(1, min(int(getattr(run.args, "nosql_probe_limit", 12)), 50))
    for url in [value for value in _urls(inputs, run) if "?" in value][:maximum]:
        baseline_code, baseline_body, _headers = fetch_url(url, _timeout(run))
        parsed = urlsplit(url)
        names = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
        if not names:
            continue
        probe_name = names[0] + "[$ne]"
        candidate = _mutated_url(url, probe_name, "ah-puch-control")
        code, body, _headers = fetch_url(candidate, _timeout(run))
        differential = code != baseline_code or abs(len(body) - len(baseline_body)) >= max(32, len(baseline_body) // 10)
        rows.append({"url": url, "parameter": names[0], "operator": "$ne", "baseline_status": baseline_code, "status_code": code, "differential": differential, "baseline_sha256": hashlib.sha256(baseline_body).hexdigest(), "response_sha256": hashlib.sha256(body).hexdigest()})
        if differential:
            lines.add(f"Vulnerable NoSQL operator differential candidate: parameter={names[0]} url={url}")
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "nosql-validation.jsonl")
    artifact = _jsonl(destination / "nosql-validation.jsonl", rows)
    return NativeExecution("success", "bounded NoSQL differential validation completed", text, records, rejected, [artifact], {"probes": len(rows), "differentials": sum(bool(row["differential"]) for row in rows)})


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file() or path.is_symlink():
        return rows
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return rows
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _service_endpoint(value: str) -> dict[str, Any]:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return {}
    if parsed.scheme not in {"tcp", "udp"} or not parsed.hostname or parsed.port is None:
        return {}
    return {"host": parsed.hostname, "port": int(parsed.port), "protocol": parsed.scheme}


def _cpe_identity(value: Any) -> dict[str, str]:
    raw = str(value or "").strip()
    if not raw:
        return {}
    parts: list[str]
    if raw.startswith("cpe:2.3:"):
        parts = raw.split(":")
        if len(parts) < 6:
            return {}
        vendor, product, version = parts[3], parts[4], parts[5]
    elif raw.startswith("cpe:/"):
        parts = raw.split(":")
        if len(parts) < 5:
            return {}
        vendor, product, version = parts[2], parts[3], parts[4]
    else:
        return {}

    def clean(item: str) -> str:
        item = item.replace("\\:", ":").replace("_", " ").strip()
        return "" if item in {"", "*", "-"} else item

    return {"vendor": clean(vendor), "product": clean(product), "version": clean(version)}


def _version_from_text(value: str) -> tuple[str, str]:
    match = re.search(r"\b([A-Za-z][A-Za-z0-9._+-]{1,80})[/ ]v?(\d+(?:\.\d+){0,5}[A-Za-z0-9._+-]*)\b", value)
    return (match.group(1), match.group(2)) if match else ("", "")


def _advisory_observations(root: Path, inputs: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sources = [
        root / "artifacts" / "services.jsonl",
        root / "artifacts" / "queues" / "services.jsonl",
        root / "inventory" / "services.jsonl",
        root / "inventory" / "devices.jsonl",
    ]
    sources.extend(sorted((root / "typed-pipeline").glob("round-*/03-network/_fan_in/verified_records.jsonl")))
    sources.extend(sorted((root / "typed-pipeline").glob("round-*/09-fingerprint-waf-tls/_fan_in/verified_records.jsonl")))
    sources.extend(sorted((root / "typed-pipeline").glob("round-*/10-assessment/_fan_in/verified_records.jsonl")))
    products: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []

    def add_candidate(
        *,
        vendor: str = "",
        product: str = "",
        version: str = "",
        cpe: str = "",
        evidence_value: str = "",
        evidence_source: str = "",
        attributes: dict[str, Any] | None = None,
    ) -> None:
        cpe_identity = _cpe_identity(cpe)
        vendor = vendor or cpe_identity.get("vendor", "")
        product = product or cpe_identity.get("product", "")
        version = version or cpe_identity.get("version", "")
        vendor = " ".join(str(vendor).split())
        product = " ".join(str(product).split())
        version = " ".join(str(version).split())
        if not product or not version:
            if product or version or cpe:
                rejected.append({
                    "tool_id": "native_advisory_correlation",
                    "source": evidence_source or "advisory-correlation",
                    "candidate": evidence_value or product or cpe,
                    "reason": "incomplete-product-version-evidence",
                })
            return
        endpoint = _service_endpoint(evidence_value)
        key = (vendor.casefold(), product.casefold(), version, evidence_value)
        row = products.setdefault(
            key,
            {
                "vendor": vendor,
                "product": product,
                "version": version,
                "cpe": cpe,
                "evidence_value": evidence_value,
                "evidence_sources": [],
                "host": endpoint.get("host", ""),
                "port": endpoint.get("port", 0),
                "protocol": endpoint.get("protocol", ""),
                "attributes": {},
            },
        )
        if evidence_source and evidence_source not in row["evidence_sources"]:
            row["evidence_sources"].append(evidence_source)
        if attributes:
            row["attributes"].update({
                key: value for key, value in attributes.items()
                if key not in row["attributes"] and value not in (None, "", [], {})
            })

    for path in sources:
        for row in _read_jsonl(path):
            kind = str(row.get("kind", ""))
            value = str(row.get("value", ""))
            observations = row.get("observations") if isinstance(row.get("observations"), list) else [row]
            for observation in observations:
                if not isinstance(observation, dict):
                    continue
                attrs = observation.get("attributes", {}) if isinstance(observation.get("attributes"), dict) else {}
                cpe_values = []
                for field in ("cpe", "cpe23", "cpes"):
                    raw = attrs.get(field)
                    if isinstance(raw, list):
                        cpe_values.extend(str(item) for item in raw)
                    elif raw:
                        cpe_values.append(str(raw))
                source = f"{path.relative_to(root)}:{observation.get('tool_id', row.get('tool_id', 'unknown'))}"
                for cpe in cpe_values or [""]:
                    add_candidate(
                        vendor=str(attrs.get("vendor", "")),
                        product=str(attrs.get("product") or attrs.get("name") or attrs.get("service") or ""),
                        version=str(attrs.get("version") or attrs.get("firmware") or ""),
                        cpe=cpe,
                        evidence_value=value,
                        evidence_source=source,
                        attributes=attrs,
                    )
            if kind in {"technology", "fingerprint"} and value:
                product, version = _version_from_text(value)
                add_candidate(
                    product=product,
                    version=version,
                    evidence_value=value,
                    evidence_source=f"{path.relative_to(root)}:{row.get('tool_id', 'unknown')}",
                    attributes=row.get("attributes", {}) if isinstance(row.get("attributes"), dict) else {},
                )
    for value in inputs:
        product, version = _version_from_text(str(value))
        add_candidate(product=product, version=version, evidence_value=str(value), evidence_source="typed-input")
    return sorted(products.values(), key=lambda item: (item["product"].casefold(), item["version"], item["evidence_value"])), rejected


def _matching_advisories(advisories: list[dict[str, Any]], candidate: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    try:
        observed = Version(advisory_store._single_line(candidate["version"], "version", maximum=256))
    except (InvalidVersion, ValueError):
        return [], "invalid-observed-version"
    candidate_vendor, candidate_product = advisory_store._product_key(
        str(candidate.get("vendor", "")),
        str(candidate.get("product", "")),
    )
    matches: list[dict[str, Any]] = []
    for advisory in advisories:
        advisory_vendor, advisory_product = advisory_store._product_key(
            str(advisory.get("vendor", "")),
            str(advisory.get("product", "")),
        )
        if candidate_product != advisory_product:
            continue
        if candidate_vendor and candidate_vendor != advisory_vendor:
            continue
        constraint = str(advisory.get("version_constraint", ""))
        try:
            in_range = constraint == "*" or observed in SpecifierSet(constraint)
        except Exception:
            continue
        if in_range:
            matches.append(advisory)
    confidence = "cpe-product-version" if candidate.get("cpe") else ("vendor-product-version" if candidate.get("vendor") else "product-version")
    return sorted(matches, key=lambda row: (-float(row.get("cvss", 0.0)), str(row.get("id", "")))), confidence


def _advisory_correlation(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    store = str(getattr(run.args, "advisory_store", "") or "").strip()
    if not store:
        artifact = _jsonl(destination / "advisory-correlation.jsonl", [])
        return NativeExecution("skipped", "provide --advisory-store for offline advisory correlation", "", [], [], [artifact], {"contact": False, "store": "", "observations": 0, "matches": 0})
    try:
        advisories = advisory_store.load_advisories(Path(store).expanduser())
    except (OSError, ValueError) as exc:
        artifact = _jsonl(destination / "advisory-correlation.jsonl", [])
        return NativeExecution("unavailable", f"advisory store unavailable: {type(exc).__name__}: {exc}", "", [], [], [artifact], {"contact": False, "store": store, "observations": 0, "matches": 0})
    candidates, rejected = _advisory_observations(Path(run.root), inputs)
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    for candidate in candidates:
        matches, confidence = _matching_advisories(advisories, candidate)
        if not matches and confidence == "invalid-observed-version":
            rejected.append({
                "tool_id": str(tool["id"]),
                "source": "advisory-correlation",
                "candidate": candidate,
                "reason": "invalid-observed-version",
            })
            continue
        for advisory in matches:
            row = {
                "candidate": candidate,
                "advisory": advisory,
                "confidence": confidence,
                "exploitability": "not-claimed",
                "contact": False,
            }
            rows.append(row)
            evidence = candidate.get("evidence_value", "")
            reference = next(iter(advisory.get("references", []) or []), "")
            lines.add(
                "Candidate advisory match: "
                f"{advisory.get('id')} severity={advisory.get('severity', 'unknown')} "
                f"cvss={advisory.get('cvss', 0)} product={candidate.get('product')} "
                f"version={candidate.get('version')} evidence={evidence} "
                f"confidence={confidence} exploitability=not-claimed"
                + (f" reference={reference}" if reference else "")
            )
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, normalized_rejected = _normalized(tool, text, "advisory-correlation.jsonl")
    artifact = _jsonl(destination / "advisory-correlation.jsonl", rows)
    return NativeExecution(
        "success",
        "offline advisory correlation completed",
        text,
        records,
        [*rejected, *normalized_rejected],
        [artifact],
        {"contact": False, "store": store, "observations": len(candidates), "matches": len(rows), "exploitability_claimed": False},
    )


def _assessment_projection(tool: dict[str, Any], run: Any, destination: Path) -> NativeExecution:
    findings: set[str] = set()
    for path, body in _safe_text_files(Path(run.root)):
        if destination in path.parents:
            continue
        for line in body.splitlines():
            lowered = line.casefold()
            if any(token in lowered for token in ("cve-", "vulnerab", "exposed", "takeover", "secret")):
                findings.add(line.strip()[:4096])
    text = "\n".join(sorted(value for value in findings if value)) + ("\n" if findings else "")
    records, rejected = _normalized(tool, text, "assessment-projection.txt")
    artifact = _write(destination / "assessment-projection.txt", text)
    return NativeExecution("success", "local assessment evidence aggregation completed", text, records, rejected, [artifact], {"candidate_lines": len(findings), "contact": False})


def _successful_zap_contracts(root: Path) -> dict[str, dict[str, Any]]:
    """Load only successful same-run ZAP contracts from the outer fan-out."""
    path = root / "advanced-consumers" / "runs.jsonl"
    contracts: dict[str, dict[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return contracts
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        contract = str(row.get("contract_sha256", "")) if isinstance(row, dict) else ""
        if contract and row.get("status") == "success":
            contracts[contract] = row
    return contracts


def _zap_container(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    try:
        from .advanced_consumers import _local_zap_image, _zap, zap_backend, zap_contract_sha256
    except ImportError:
        from advanced_consumers import _local_zap_image, _zap, zap_backend, zap_contract_sha256

    active = str(tool["id"]) == "zap_full"
    rows: list[dict[str, Any]] = []
    artifacts: list[Path] = []
    lines: set[str] = set()
    image = str(getattr(run.args, "zap_image", "ghcr.io/zaproxy/zaproxy:stable"))
    options = (getattr(run, "tool_option_overrides", {}) or {}).get("zap", {})
    ajax = bool(options.get("ajax", 0))
    legacy_image_id = _local_zap_image(image)
    backend = zap_backend(active, image=image, image_id=legacy_image_id)
    image_id = str(backend.get("image_id", ""))
    runtime_kind = str(backend.get("kind", ""))
    runtime_identity = str(backend.get("identity", ""))
    completed = _successful_zap_contracts(Path(run.root))
    reused = 0
    for index, origin in enumerate(_urls(inputs, run), 1):
        outdir = destination / f"origin-{index:04d}"
        contract = (
            zap_contract_sha256(
                origin,
                image_id,
                active,
                ajax,
                options,
                runtime_kind=runtime_kind,
                runtime_identity=runtime_identity,
            )
            if backend.get("available")
            else ""
        )
        prior = completed.get(contract)
        matched_contract = contract
        # Preserve reuse of successful container records written by the
        # previous contract shape. This branch is only useful when a caller
        # supplies a known local image identity; native fallback records use
        # the backend-bound contract above and never collide with it.
        if not prior and legacy_image_id:
            legacy_contract = zap_contract_sha256(origin, legacy_image_id, active, ajax, options)
            prior = completed.get(legacy_contract)
            if prior:
                matched_contract = legacy_contract
        if prior:
            reused += 1
            result = {
                "origin": origin,
                "runner": "web-proxy-active" if active else "web-proxy-passive",
                "status": "success",
                "reason": "identical successful ZAP contract reused from outer advanced-consumer fan-out",
                "contract_sha256": matched_contract,
                "deduplicated": True,
                "reused_from": "advanced-consumers/runs.jsonl",
                "artifacts": prior.get("artifacts", []),
                "image_reference": image,
                "image_id": image_id,
                "pull_during_run": False,
            }
        else:
            result = _zap(
                origin,
                outdir,
                max(60, int(getattr(run.args, "module_timeout", 60))),
                image,
                active,
                ajax,
                options,
                image_id=image_id,
                backend=backend,
            )
        rows.append(result)
        for path in sorted(outdir.rglob("*")) if outdir.is_dir() else []:
            if not path.is_file() or path.is_symlink():
                continue
            artifacts.append(path)
            if path.suffix.casefold() != ".json":
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            sites = payload.get("site", []) if isinstance(payload, dict) else []
            for site in sites if isinstance(sites, list) else []:
                alerts = site.get("alerts", []) if isinstance(site, dict) else []
                for alert in alerts if isinstance(alerts, list) else []:
                    if not isinstance(alert, dict):
                        continue
                    name = str(alert.get("alert") or alert.get("name") or "unnamed alert")
                    risk = str(alert.get("riskdesc") or alert.get("risk") or "unknown")
                    instances = alert.get("instances", []) if isinstance(alert.get("instances", []), list) else []
                    observed_url = next((str(item.get("uri", "")) for item in instances if isinstance(item, dict) and item.get("uri")), origin)
                    lines.add(f"Vulnerable web assessment alert: {name}; risk={risk}; url={observed_url}")
    statuses = [str(row.get("status", "failed")) for row in rows]
    if not rows or all(status == "skipped" for status in statuses):
        status, reason = "skipped", "local ZAP container/native backend is unavailable; target runs never pull images"
    elif any(status in {"failed", "timeout"} for status in statuses):
        status, reason = ("partial" if any(value == "success" for value in statuses) else "failed"), "one or more bounded ZAP runs failed"
    else:
        status, reason = "success", f"bounded {runtime_kind or 'local'} ZAP assessment completed"
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "zap-runs.jsonl", "success" if status == "success" else "partial")
    ledger = _jsonl(destination / "zap-runs.jsonl", rows)
    artifacts.append(ledger)
    return NativeExecution(
        status,
        reason,
        text,
        records,
        rejected,
        list(dict.fromkeys(artifacts)),
        {
            "origins": len(rows),
            "statuses": statuses,
            "deduplicated": reused,
            "image_reference": image,
            "image_id": image_id,
            "runtime_kind": runtime_kind,
            "runtime_identity": runtime_identity,
            "backend_path": str(backend.get("path", "")),
            "pull_during_run": False,
        },
    )


def _api_enrichment(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    tool_id = str(tool["id"])
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    if tool_id == "hunter":
        hosts = _domain_hosts(inputs, run)
        if not hosts:
            return NativeExecution("not-applicable", "no DNS-name input is available for public contact enrichment")
        required_credentials = ("HUNTER_API_KEY",)
        missing_credentials = [name for name in required_credentials if not os.environ.get(name)]
        if missing_credentials:
            return NativeExecution(
                "skipped",
                "required credential environment is absent",
                receipt={
                    "contact": False,
                    "credential_env": list(required_credentials),
                    "missing_credentials": missing_credentials,
                    "credentials_persisted": False,
                },
            )
        key = os.environ["HUNTER_API_KEY"]
        for host in hosts:
            query = urlencode({"domain": host, "api_key": key, "limit": 100})
            code, body, _headers = fetch_url("https://api.hunter.io/v2/domain-search?" + query, _timeout(run), {"Accept": "application/json"})
            try:
                payload = json.loads(body.decode("utf-8", errors="replace"))
                response_status = "success" if 200 <= code < 300 else "provider-error"
            except json.JSONDecodeError:
                payload = {}
                response_status = "invalid-response"
            emails = sorted({str(row.get("value", "")) for row in ((payload.get("data") or {}).get("emails") or []) if isinstance(row, dict) and row.get("value")})
            rows.append({"provider": "domain-contact-enrichment", "host": host, "status": response_status, "status_code": code, "emails": emails})
            lines.update(f"Exposed public contact: {email} domain={host}" for email in emails)
    else:
        hosts = _hosts(inputs, run)
        if not hosts:
            return NativeExecution("not-applicable", "no host or IP input is available for Internet asset enrichment")
        required_credentials = ("FOFA_EMAIL", "FOFA_KEY")
        missing_credentials = [name for name in required_credentials if not os.environ.get(name)]
        if missing_credentials:
            return NativeExecution(
                "skipped",
                "required credential environment is absent",
                receipt={
                    "contact": False,
                    "credential_env": list(required_credentials),
                    "missing_credentials": missing_credentials,
                    "credentials_persisted": False,
                },
            )
        email, key = os.environ["FOFA_EMAIL"], os.environ["FOFA_KEY"]
        for host in hosts:
            query_value = base64.b64encode(_fofa_query_for(host).encode()).decode()
            query = urlencode({"email": email, "key": key, "qbase64": query_value, "size": 100, "fields": "host,ip,port,protocol,server"})
            code, body, _headers = fetch_url("https://fofa.info/api/v1/search/all?" + query, _timeout(run), {"Accept": "application/json"})
            try:
                payload = json.loads(body.decode("utf-8", errors="replace"))
                response_status = "success" if 200 <= code < 300 else "provider-error"
            except json.JSONDecodeError:
                payload = {}
                response_status = "invalid-response"
            results = payload.get("results", []) if isinstance(payload, dict) else []
            clean_results: list[list[Any]] = []
            for result in results if isinstance(results, list) else []:
                if not isinstance(result, list):
                    continue
                clean_results.append(result[:5])
                if len(result) > 1:
                    lines.add(str(result[1]))
                if len(result) > 3 and str(result[1]) and str(result[2]).isdigit():
                    lines.add(f"{result[1]}:{result[2]}/{str(result[3] or 'tcp').casefold()}")
                if len(result) > 4 and result[4]:
                    lines.add(f"Technology: {result[4]}")
            rows.append({"provider": "internet-asset-enrichment", "host": host, "status": response_status, "status_code": code, "results": clean_results})
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "api-enrichment.jsonl")
    artifact = _jsonl(destination / "api-enrichment.jsonl", rows)
    successful = sum(row.get("status") == "success" for row in rows)
    if successful == len(rows):
        status, reason = "success", "provider-key-gated API enrichment completed"
    elif successful:
        status, reason = "partial", "some provider-key-gated API queries returned errors"
    else:
        status, reason = "failed", "provider-key-gated API queries returned no usable responses"
    return NativeExecution(
        status,
        reason,
        text,
        records,
        rejected,
        [artifact],
        {
            "queries": len(rows),
            "successful_queries": successful,
            "status_codes": [row.get("status_code", 0) for row in rows],
            "contact": True,
            "credentials_persisted": False,
        },
    )


def _device(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    rows: list[dict[str, Any]] = []
    lines: set[str] = set()
    for value in inputs:
        lowered = str(value).casefold()
        matches = sorted(term for term in DEVICE_TERMS if term in lowered)
        ports = {int(match) for match in re.findall(r":(\d{1,5})(?:/|\b)", lowered) if 1 <= int(match) <= 65535}
        if 502 in ports:
            matches.append("modbus")
        if 47808 in ports:
            matches.append("bacnet")
        if 554 in ports:
            matches.append("rtsp")
        matches = sorted(set(matches))
        if matches:
            rows.append({"input": str(value), "technologies": matches})
            lines.update(f"Technology: {name} observed at {value}" for name in matches)
    text = "\n".join(sorted(lines)) + ("\n" if lines else "")
    records, rejected = _normalized(tool, text, "device-analysis.jsonl")
    artifact = _jsonl(destination / "device-analysis.jsonl", rows)
    return NativeExecution("success", "native device and industrial evidence analysis completed", text, records, rejected, [artifact], {"observations": len(rows), "contact": False})


def execute_native(tool: dict[str, Any], run: Any, inputs: list[str], destination: Path) -> NativeExecution:
    """Execute one inventory-native method or raise for an unmapped contract."""
    tool_id = str(tool["id"])
    if tool_id not in NATIVE_TOOL_IDS:
        raise KeyError(f"no native method contract for {tool_id}")
    if tool_id == "native_target_boundary":
        return _target_boundary(tool, run, destination)
    if tool_id == "native_dns":
        return _dns(tool, run, inputs, destination)
    if tool_id == "native_network":
        return _network(tool, run, inputs, destination)
    if tool_id == "native_http":
        return _http(tool, run, inputs, destination)
    if tool_id == "web_evidence_projection":
        return _projection(tool, run, destination)
    if tool_id in {"native_js_api", "jsfscan"}:
        return _javascript(tool, run, inputs, destination)
    if tool_id == "swagger_openapi":
        return _schema(tool, run, inputs, destination, "openapi")
    if tool_id == "graphql":
        return _schema(tool, run, inputs, destination, "graphql")
    if tool_id == "postman":
        return _postman(tool, run, destination)
    if tool_id == "source_maps":
        return _source_maps(tool, run, inputs, destination)
    if tool_id == "paraminer":
        return _hidden_parameters(tool, run, inputs, destination)
    if tool_id == "nosqlmap":
        return _nosql(tool, run, inputs, destination)
    if tool_id == "arachni":
        return _assessment_projection(tool, run, destination)
    if tool_id == "native_advisory_correlation":
        return _advisory_correlation(tool, run, inputs, destination)
    if tool_id in {"zap_baseline", "zap_full"}:
        return _zap_container(tool, run, inputs, destination)
    if tool_id in {"hunter", "fofa"}:
        return _api_enrichment(tool, run, inputs, destination)
    if tool_id == "native_device_ics":
        return _device(tool, run, inputs, destination)
    raise AssertionError(f"unreachable native method dispatch for {tool_id}")
