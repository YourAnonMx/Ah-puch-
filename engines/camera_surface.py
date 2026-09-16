#!/usr/bin/env python3
"""Detect and inventory camera, recorder, video, and embedded-device surfaces."""

from __future__ import annotations

import datetime as dt
import csv
import http.cookiejar
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "cameras"
URL_RE = re.compile(r"\b(?:https?|rtsp|rtsps)://[^\s\"'<>]+", re.I)
IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b")
SERVICE_RE = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\s+(?:open|filtered|closed)?\s*([A-Za-z0-9_.-]*)", re.I)
HOST_PORT_RE = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9_.-]{0,252}):(\d{1,5})\b")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

CAMERA_TERMS = {
    "camera", "cctv", "webcam", "ipcam", "nvr", "dvr", "video recorder",
    "surveillance", "onvif", "rtsp", "rtsps", "hikvision", "dahua",
    "axis communications", "blue iris", "netvideo", "videostream",
}
CAMERA_PORTS = {80, 443, 554, 8000, 8080, 8081, 8443, 8554, 8899, 9000, 37777}
STANDARD_PORTS = {
    21, 23, 80, 81, 82, 83, 84, 85, 88, 90, 91, 92, 99, 111, 161, 222,
    443, 550, 554, 556, 666, 777, 800, 808, 880, 1000, 1050, 1080, 1111,
    1303, 1311, 2000, 2002, 2003, 2022, 2080, 2082, 2086, 2095, 2121,
    2222, 2480, 3000, 3022, 3095, 3128, 3333, 3389, 4000, 4040, 4443,
    5000, 5002, 5005, 5050, 5080, 5222, 5500, 5555, 6002, 6666, 6887,
    7000, 7001, 7100, 7780, 8000, 8001, 8002, 8004, 8005, 8006, 8007,
    8008, 8009, 8010, 8011, 8015, 8022, 8029, 8031, 8032, 8069, 8074,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8091, 8094, 8095, 8099, 8111, 8181, 8249, 8282, 8291, 8292, 8293,
    8443, 8554, 8585, 8728, 8800, 8847, 8881, 8882, 8888, 8899, 8999,
    9000, 9001, 9080, 9082, 9988, 9999, 10000, 10443, 11111, 20000,
    20788, 20838, 22222, 25001, 25565, 28017, 34568, 37777, 45001,
    49081, 49090, 49153, 50000, 50080,
}
TLS_PORTS = {443, 4443, 7443, 8443, 9443, 10443}
RTSP_PORTS = {554, 8554}
RTSPS_PORTS = {322, 7441, 8322}
PORT_PROFILE_NAMES = ("quick", "standard", "comprehensive", "all", "custom")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", errors="replace")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def slug(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (clean or "target")[:120]


def target_host(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlsplit(target).hostname or target
    return target.strip("[]").rsplit(":", 1)[0] if target.count(":") == 1 else target.strip("[]")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_network_target(value: str) -> bool:
    if "://" in value or "/" not in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def host_within_target(host: str, target: str) -> bool:
    candidate = host.strip().strip("[]").lower().rstrip(".")
    if not candidate:
        return False
    if is_network_target(target):
        try:
            return ipaddress.ip_address(candidate) in ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
    base = target_host(target).strip("[]").lower().rstrip(".")
    if is_ip(base):
        return candidate == base
    return candidate == base or candidate.endswith("." + base)


def read_signatures() -> list[dict[str, Any]]:
    path = DATA / "device_fingerprints.json"
    signatures: list[dict[str, Any]] = []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        raw = {}
    signatures.extend(item for item in raw.get("fingerprints", []) if isinstance(item, dict))

    # The imported rule file is retained as data rather than executed as
    # shell. The JSON catalog contains normalized rules
    # already imported by Ah-Puch; this parser preserves any source rule that
    # is not represented there, including Rule2/Rule3 multi-signal groups and
    # response-line rules.
    source = DATA / "device-rules" / "model.rules"
    try:
        lines = [line.strip() for line in source.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        lines = []
    source_rows: list[dict[str, Any]] = []
    index = 0
    while index + 2 < len(lines):
        kind, model, signal = lines[index:index + 3]
        if kind not in {"Rule", "Rule2", "Rule3", "LenRule"}:
            index += 1
            continue
        row: dict[str, Any] = {"model": model, "signals": [signal], "rule": kind, "source": "device-rules"}
        index += 3
        if kind == "LenRule" and index < len(lines):
            try:
                row["response_lines"] = int(lines[index])
                row["match"] = "response-lines"
            except ValueError:
                pass
            index += 1
        source_rows.append(row)
    # Rule2/Rule3 are continuation records in the source format, not
    # independent signatures. Merge adjacent records for the same model so a
    # multi-signal rule keeps its required all-of semantics and cannot produce
    # a false positive from only its first signal.
    merged_rows: list[dict[str, Any]] = []
    index = 0
    while index < len(source_rows):
        current = dict(source_rows[index])
        signals = list(current.get("signals", []))
        kinds = [str(current.get("rule", "Rule"))]
        next_index = index + 1
        while next_index < len(source_rows):
            candidate = source_rows[next_index]
            if str(candidate.get("model", "")).casefold() != str(current.get("model", "")).casefold():
                break
            candidate_kind = str(candidate.get("rule", "Rule"))
            if candidate_kind not in {"Rule2", "Rule3"} or kinds[-1] not in {"Rule", "Rule2"}:
                break
            signals.extend(candidate.get("signals", []))
            kinds.append(candidate_kind)
            next_index += 1
        if len(kinds) > 1:
            current["signals"] = signals
            current["match"] = "all"
            current["rule"] = "+".join(kinds)
        merged_rows.append(current)
        index = next_index
    source_rows = merged_rows

    existing = {
        (
            str(item.get("model", "")).casefold(),
            tuple(str(value) for value in item.get("signals", [])),
            str(item.get("match", "")),
            str(item.get("response_lines", "")),
        )
        for item in signatures
    }
    for item in source_rows:
        key = (
            str(item.get("model", "")).casefold(),
            tuple(str(value) for value in item.get("signals", [])),
            str(item.get("match", "")),
            str(item.get("response_lines", "")),
        )
        if key not in existing:
            signatures.append(item)
            existing.add(key)
    return signatures


def read_ports() -> set[int]:
    ports = set(CAMERA_PORTS)
    for path in (DATA / "service_ports.txt", DATA / "device-rules" / "port.rules"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            for value in re.findall(r"\b\d{1,5}\b", raw):
                number = int(value)
                if 1 <= number <= 65535:
                    ports.add(number)
    return ports


def parse_port_expression(value: str) -> set[int]:
    """Parse comma-delimited ports and inclusive ranges."""
    ports: set[int] = set()
    for part in value.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"invalid port range: {token}")
            start, end = int(start_text), int(end_text)
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"port range outside 1-65535: {token}")
            ports.update(range(start, end + 1))
        elif token.isdigit() and 1 <= int(token) <= 65535:
            ports.add(int(token))
        else:
            raise ValueError(f"invalid port: {token}")
    return ports


def ports_for_profile(profile: str, custom: str = "") -> set[int]:
    selected = profile.strip().lower()
    if selected not in PORT_PROFILE_NAMES:
        raise ValueError(f"unknown device port profile: {profile}")
    if selected == "quick":
        return set(CAMERA_PORTS)
    if selected == "standard":
        return set(STANDARD_PORTS) | set(CAMERA_PORTS)
    if selected == "comprehensive":
        return read_ports()
    if selected == "all":
        return set(range(1, 65536))
    if not custom.strip():
        raise ValueError("custom device port profile requires a port expression")
    return parse_port_expression(custom)


def normalized_pattern(value: str) -> str:
    """Translate the source rule notation into a Python-compatible pattern."""
    # Fingerprint data escapes angle brackets for JSON/readability; they are
    # literal HTML delimiters, not word-boundary assertions.
    pattern = value.replace(r"\<", "<").replace(r"\>", ">")
    for escaped, plain in ((r"\/", "/"), (r"\=", "="), (r"\:", ":"), (r"\ ", " ")):
        pattern = pattern.replace(escaped, plain)
    return pattern


def signal_matches(pattern: str, text: str) -> bool:
    if not pattern:
        return False
    translated = normalized_pattern(pattern)
    try:
        return re.search(translated, text, re.I) is not None
    except re.error:
        literal = re.sub(r"\\(.)", r"\1", pattern)
        return literal.casefold() in text.casefold()


def _matched_fingerprint(item: dict[str, Any], *, rule: str, evidence: str) -> dict[str, Any]:
    """Preserve normalized identity metadata without coupling it to matching."""
    return {
        key: value
        for key, value in {
            "model": str(item.get("model", "")).strip(),
            "vendor": str(item.get("vendor", "")).strip(),
            "device_type": str(item.get("device_type", item.get("type", ""))).strip(),
            "version": str(item.get("version", "")).strip(),
            "rule": rule,
            "evidence": evidence,
        }.items()
        if value
    }


def fingerprint_matches(
    text: str,
    signatures: list[dict[str, Any]],
    *,
    response_bytes: int | None = None,
) -> list[dict[str, Any]]:
    """Return identity matches while preserving multi-signal and length rules."""
    results: list[dict[str, Any]] = []
    line_count = len(text.splitlines())
    for item in signatures:
        model = str(item.get("model", "")).strip()
        if not model:
            continue
        if item.get("match") == "response-lines":
            try:
                expected = int(item.get("response_lines", -1))
            except (TypeError, ValueError):
                continue
            guards = [str(value).strip() for value in item.get("signals", []) if str(value).strip()]
            # Response length is only a secondary discriminator.  A bare line
            # count is not device evidence and used to create false matches
            # for arbitrary text files.
            if guards and line_count == expected and all(signal_matches(value, text) for value in guards):
                results.append(_matched_fingerprint(item, rule="response-lines", evidence=str(expected)))
            continue
        if item.get("match") == "response-length":
            if response_bytes is None:
                continue
            try:
                minimum = int(item.get("response_bytes_min", item.get("response_bytes", -1)))
                maximum = int(item.get("response_bytes_max", item.get("response_bytes", -1)))
            except (TypeError, ValueError):
                continue
            guards = [str(value).strip() for value in item.get("signals", []) if str(value).strip()]
            if minimum < 0 or maximum < minimum or not guards:
                continue
            if minimum <= response_bytes <= maximum and all(signal_matches(value, text) for value in guards):
                results.append(_matched_fingerprint(item, rule="response-length", evidence=f"{minimum}-{maximum}"))
            continue
        signals = [str(value).strip() for value in item.get("signals", []) if str(value).strip()]
        if not signals:
            continue
        matches = [signal_matches(value, text) for value in signals]
        matched = all(matches) if item.get("match") == "all" else any(matches)
        if matched:
            results.append(_matched_fingerprint(item, rule=str(item.get("match", "any")), evidence=" && ".join(signals)))
    return results


def text_files(run_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in run_root.rglob("*"):
        if not path.is_file() or path.name.endswith(".command.json"):
            continue
        try:
            if path.stat().st_size > 8_000_000:
                continue
            path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append(path)
    return files


def add_evidence(evidence: list[dict[str, str]], source: str, kind: str, value: str) -> None:
    value = value.strip().rstrip(".,;:)]}")
    if value:
        evidence.append({"source": source, "kind": kind, "value": value[:500]})


def normalize_endpoint(host: str, port: int, scheme: str = "tcp") -> str:
    display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{display}:{port}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep device probes on their concrete target endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _open_device_request(request: urllib.request.Request, timeout: float, context: ssl.SSLContext | None):
    handlers: list[Any] = [_NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers).open(request, timeout=timeout)


def _probe_http09(host: str, port: int, timeout: float) -> bytes:
    """Read a bounded HTTP/0.9 body without redirect or header semantics."""
    chunks: list[bytes] = []
    total = 0
    with socket.create_connection((host, port), timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(b"GET /\r\n")
        while total < 200_000:
            chunk = stream.recv(min(16_384, 200_000 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks)


def probe_service(
    host: str,
    port: int,
    timeout: float,
    *,
    paths: list[str] | None = None,
    probe_mode: str = "all",
) -> dict[str, Any]:
    if probe_mode not in {"all", "web", "stream"}:
        raise ValueError(f"unknown device probe mode: {probe_mode}")
    result: dict[str, Any] = {"host": host, "port": port, "open": False, "transport": "tcp"}
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["open"] = True
    except (OSError, ValueError):
        return result
    if probe_mode != "web" and port in RTSP_PORTS | RTSPS_PORTS:
        try:
            display = f"[{host}]" if ":" in host and not host.startswith("[") else host
            raw_stream = socket.create_connection((host, port), timeout=timeout)
            if port in RTSPS_PORTS:
                try:
                    stream = ssl.create_default_context().wrap_socket(raw_stream, server_hostname=host)
                except BaseException:
                    raw_stream.close()
                    raise
                stream_scheme = "rtsps"
            else:
                stream = raw_stream
                stream_scheme = "rtsp"
            with stream:
                stream.settimeout(timeout)
                stream.sendall(f"OPTIONS {stream_scheme}://{display}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ah-puch/2\r\n\r\n".encode())
                banner = stream.recv(8192).decode("utf-8", errors="replace")
            if banner:
                result["protocol"] = stream_scheme
                result["banner"] = banner[:4000]
        except (OSError, ssl.SSLError) as exc:
            result["stream_error"] = f"{type(exc).__name__}: {exc}"
    if probe_mode == "stream":
        return result
    display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    schemes = ("https", "http") if port in TLS_PORTS else ("http", "https")
    transport_errors: list[dict[str, str]] = []
    for scheme in schemes:
        context = ssl.create_default_context() if scheme == "https" else None
        handlers: list[Any] = [_NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        opener = urllib.request.build_opener(*handlers)
        for candidate_path in ["/", *(paths or [])]:
            url = f"{scheme}://{display}:{port}{candidate_path}"
            request = urllib.request.Request(url, headers={"User-Agent": "ah-puch-surface/2"}, method="GET")
            response: Any = None
            try:
                response = opener.open(request, timeout=timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            except (OSError, urllib.error.URLError, ValueError) as exc:
                transport_errors.append({"scheme": scheme, "error": f"{type(exc).__name__}: {exc}"})
                continue
            try:
                raw_body = response.read(200_000)
                body = raw_body.decode("utf-8", errors="replace")
                title_match = TITLE_RE.search(body)
                result.update({
                    "url": url,
                    "protocol": scheme,
                    "status": getattr(response, "status", getattr(response, "code", 0)),
                    "server": response.headers.get("Server", ""),
                    "content_type": response.headers.get("Content-Type", ""),
                    "redirect_location": response.headers.get("Location", ""),
                    "headers": dict(response.headers.items()),
                    "title": title_match.group(1).strip() if title_match else "",
                    "body_sample": body[:16000],
                    "response_bytes": len(raw_body),
                    "_match_text": "\n".join((str(response.headers), body)),
                })
                break
            finally:
                try:
                    response.close()
                except Exception:
                    pass
        if result.get("status"):
            break
    if not result.get("status") and result.get("protocol") not in {"rtsp", "rtsps"} and port not in TLS_PORTS:
        try:
            raw_body = _probe_http09(host, port, timeout)
        except OSError as exc:
            transport_errors.append({"scheme": "http/0.9", "error": f"{type(exc).__name__}: {exc}"})
        else:
            if raw_body:
                body = raw_body.decode("utf-8", errors="replace")
                result.update({
                    "url": f"http://{display}:{port}/", "protocol": "http/0.9", "status": 200,
                    "headers": {}, "title": "", "body_sample": body[:16000],
                    "response_bytes": len(raw_body), "_match_text": body,
                })
    if transport_errors:
        result["transport_errors"] = transport_errors
    return result


def analyze(run_root: Path, target: str, active: bool, timeout: int, max_hosts: int = 24) -> dict[str, Any]:
    """Create camera/device artifacts and return discovered URLs and hosts."""
    destination = run_root / "09-camera-surfaces"
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    target_slug = slug(target)
    network_target = is_network_target(target)
    signatures = read_signatures()
    ports = read_ports()
    evidence: list[dict[str, str]] = []
    endpoints: dict[str, dict[str, Any]] = {}
    urls: list[str] = []
    hosts: set[str] = set()
    text_count = 0

    for path in text_files(run_root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text_count += 1
        relative = str(path.relative_to(run_root))
        lower = text.lower()
        local_surface_signal = False
        local_urls: list[str] = []
        for url in URL_RE.findall(text):
            clean = url.rstrip(".,;:)]}")
            parsed = urlsplit(clean)
            if parsed.hostname and host_within_target(parsed.hostname, target):
                urls.append(clean)
                local_urls.append(clean)
                hosts.add(parsed.hostname)
                if parsed.port:
                    endpoints.setdefault(normalize_endpoint(parsed.hostname, parsed.port, parsed.scheme), {"host": parsed.hostname, "port": parsed.port, "scheme": parsed.scheme})
        for match in IP_PORT_RE.finditer(text):
            host, raw_port = match.groups()
            port = int(raw_port)
            if port in ports and host_within_target(host, target):
                hosts.add(host)
                endpoints.setdefault(normalize_endpoint(host, port), {"host": host, "port": port, "scheme": "tcp"})
                add_evidence(evidence, relative, "service-endpoint", f"{host}:{port}")
        # Range scans write masscan rows as ``IP<TAB>port``.
        for match in re.finditer(r"^\s*([^\s,]+)\t(\d{1,5})(?:\s|$)", text, re.M):
            host, raw_port = match.groups()
            port = int(raw_port)
            if port in ports and host_within_target(host, target):
                hosts.add(host)
                endpoints.setdefault(normalize_endpoint(host, port), {"host": host, "port": port, "scheme": "tcp"})
                add_evidence(evidence, relative, "service-endpoint", f"{host}:{port}")
        for match in HOST_PORT_RE.finditer(text):
            host, raw_port = match.groups()
            port = int(raw_port)
            if port in ports and ("." in host or is_ip(host)) and host_within_target(host, target):
                hosts.add(host)
                endpoints.setdefault(normalize_endpoint(host, port), {"host": host, "port": port, "scheme": "tcp"})
        for match in SERVICE_RE.finditer(text):
            port, service = match.groups()
            number = int(port)
            if number in ports and not network_target:
                endpoint = normalize_endpoint(target_host(target), number)
                endpoints.setdefault(endpoint, {"host": target_host(target), "port": number, "scheme": "tcp", "service": service})
                add_evidence(evidence, relative, "service-port", f"{number}/{service or 'unknown'}")
        for term in sorted(CAMERA_TERMS):
            if term in lower:
                local_surface_signal = True
                add_evidence(evidence, relative, "indicator", term)
        for match in fingerprint_matches(text, signatures):
            local_surface_signal = True
            add_evidence(evidence, relative, "model-signature", f"{match['model']}: {match['evidence']}")
        # A fingerprint or camera indicator attached to a verified URL is an
        # actionable surface candidate even when the URL omitted its default
        # port. This is what lets later device follow-up consume technology
        # evidence instead of waiting for a separately formatted host:port row.
        if local_surface_signal:
            for clean in local_urls:
                parsed = urlsplit(clean)
                port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
                endpoints.setdefault(normalize_endpoint(parsed.hostname or "", port, parsed.scheme), {"host": parsed.hostname, "port": port, "scheme": parsed.scheme, "source": "fingerprint"})

    host = target_host(target)
    if not network_target and host:
        hosts.add(host)
    probe_hosts = sorted(hosts)[:max_hosts]
    probe_results: list[dict[str, Any]] = []
    inventory_records = 0
    if active and not network_target:
        for probe_host in probe_hosts:
            for port in sorted(CAMERA_PORTS):
                result = probe_service(probe_host, port, max(0.5, min(timeout, 5)))
                if result.get("open"):
                    probe_results.append(result)
                    endpoints.setdefault(normalize_endpoint(probe_host, port), {"host": probe_host, "port": port, "scheme": "tcp"})
                    add_evidence(evidence, "active-probe", "open-service", f"{probe_host}:{port}")
                    for field in ("server", "title", "body_sample"):
                        value = str(result.get(field, ""))
                        lower_value = value.lower()
                        for term in sorted(CAMERA_TERMS):
                            if term in lower_value:
                                add_evidence(evidence, "active-probe", "http-indicator", f"{term} ({probe_host}:{port})")
    else:
        probe_results.append({"status": "not-run", "reason": "passive profile or network range"})

    # The source inventory/report formats are comma-delimited rows with the
    # address at column 9, port at column 10, and model fields at 15-17.
    # Normalize those rows into the same endpoint/evidence queues when they
    # appear in a saved run or a supplied raw inventory.
    for path in text_files(run_root):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        relative = str(path.relative_to(run_root))
        for row in csv.reader(lines):
            if len(row) < 18:
                continue
            candidate_host = row[9].strip()
            try:
                candidate_port = int(row[10].strip())
            except (ValueError, IndexError):
                continue
            if not (1 <= candidate_port <= 65535) or not host_within_target(candidate_host, target):
                continue
            inventory_records += 1
            hosts.add(candidate_host)
            endpoints.setdefault(normalize_endpoint(candidate_host, candidate_port), {"host": candidate_host, "port": candidate_port, "scheme": "tcp", "source": "inventory"})
            add_evidence(evidence, relative, "inventory-endpoint", f"{candidate_host}:{candidate_port}")
            for column in (15, 16, 17):
                value = row[column].strip()
                if value and value.lower() not in {"unknown", "pending", "none", "false"}:
                    add_evidence(evidence, relative, "inventory-model", value)

    camera_evidence = [item for item in evidence if item["kind"] in {"indicator", "model-signature", "http-indicator", "inventory-model"}]
    service_evidence = [item for item in evidence if item["kind"] in {"service-endpoint", "service-port", "open-service", "inventory-endpoint"}]
    summary = {
        "created": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": target,
        "files_read": text_count,
        "ports_loaded": len(ports),
        "candidate_endpoints": len(endpoints),
        "camera_indicators": len(camera_evidence),
        "service_indicators": len(service_evidence),
        "inventory_records": inventory_records,
        "active_probe": bool(active and not network_target),
        "probe_results": len([item for item in probe_results if item.get("open")]),
    }
    write_text(destination / f"{target_slug}.camera-candidates.txt", "\n".join(sorted(endpoints)) + ("\n" if endpoints else ""))
    write_text(destination / f"{target_slug}.camera-services.txt", "\n".join(json.dumps(item, ensure_ascii=False, sort_keys=True) for item in probe_results) + ("\n" if probe_results else ""))
    write_text(destination / f"{target_slug}.camera-model-hints.txt", "\n".join(f"{item['kind']}\t{item['value']}\t{item['source']}" for item in camera_evidence) + ("\n" if camera_evidence else ""))
    write_text(destination / f"{target_slug}.camera-evidence.txt", "\n".join(f"{item['kind']}\t{item['value']}\t{item['source']}" for item in evidence) + ("\n" if evidence else ""))
    write_json(destination / f"{target_slug}.camera-summary.json", {**summary, "endpoints": sorted(endpoints), "hosts": sorted(hosts), "probe": probe_results})
    write_json(destination / f"{target_slug}.camera-state.json", {"target": target, "complete": True, "hosts": sorted(hosts), "endpoints": sorted(endpoints), "updated": summary["created"]})
    write_text(run_root / "queues" / f"{target_slug}.camera.candidates.txt", "\n".join(sorted(endpoints)) + ("\n" if endpoints else ""))
    write_text(run_root / "queues" / f"{target_slug}.camera.urls.txt", "\n".join(sorted(set(urls))) + ("\n" if urls else ""))
    return {"summary": summary, "urls": sorted(set(urls)), "hosts": sorted(hosts), "endpoints": sorted(endpoints)}
