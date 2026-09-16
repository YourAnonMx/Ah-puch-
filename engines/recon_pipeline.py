#!/usr/bin/env python3
"""Typed, evidence-first orchestration primitives for the recon pipeline.

The module is deliberately independent of target contact. It owns the durable
method-result contract, phase barriers, additive fan-in and convergence ledger.
Actual contact remains behind the canonical run target boundary.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit, urlunsplit

try:
    from .service_routing import canonical_service, parse_service
except ImportError:
    from service_routing import canonical_service, parse_service

try:
    from .runner_registry import TOOL_INVENTORY
except ImportError:
    from runner_registry import TOOL_INVENTORY


SCHEMA_VERSION = 1
TERMINAL_STATES = frozenset({
    "success", "clean-negative", "partial", "failed", "timeout", "unavailable",
    "not-applicable", "skipped", "planned", "disabled", "invalid-output",
})
PROMOTABLE_STATES = frozenset({"success", "partial"})
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
HOST_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Fa-f:.])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
SERVICE_RE = re.compile(r"\b([^\s:/]+|\[[0-9A-Fa-f:]+\]):(\d{1,5})/(tcp|udp)\b", re.I)
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SENSITIVE_FIELD_NAMES = frozenset({
    "authorization", "auth", "auth_header", "api-key", "api_key", "apikey",
    "api-secret", "api_secret", "bearer", "client-secret", "client_secret",
    "credential", "credentials", "key", "passwd", "password", "secret",
    "token", "x-api-key",
})


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    path.chmod(0o600)


def _json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _safe_text(value: Any, limit: int = 16384) -> str:
    return str(value or "").replace("\x00", "").replace("\r", " ").strip()[:limit]


def _field_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().casefold()).strip("_")


def _is_sensitive_field(value: Any) -> bool:
    normalized = _field_name(value)
    dashed = normalized.replace("_", "-")
    return normalized in SENSITIVE_FIELD_NAMES or dashed in SENSITIVE_FIELD_NAMES


def _redact_command_tokens(command: list[Any]) -> list[str]:
    result: list[str] = []
    redact_next = False
    previous_header = ""
    for raw in command:
        token = _safe_text(raw, 8192)
        lower = token.casefold()
        if redact_next or previous_header in {"authorization", "proxy_authorization"}:
            result.append("[REDACTED]")
            redact_next = False
            previous_header = ""
            continue
        if "=" in token:
            key, _value = token.split("=", 1)
            result.append(f"{key}=[REDACTED]" if _is_sensitive_field(key) else token)
            continue
        if _is_sensitive_field(token.lstrip("-")):
            result.append(token)
            redact_next = True
            previous_header = _field_name(token)
            continue
        if lower.startswith(("basic ", "bearer ")):
            result.append("[REDACTED]")
            continue
        result.append(token)
    return result


def _sanitize_receipt(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in sorted(value.items(), key=lambda row: str(row[0])):
            if _is_sensitive_field(key):
                result[str(key)] = "[REDACTED]"
            elif str(key) == "command" and isinstance(item, list):
                result[str(key)] = _redact_command_tokens(item)
            elif str(key) == "commands" and isinstance(item, list):
                result[str(key)] = [
                    " ".join(_redact_command_tokens(str(entry).split())) if isinstance(entry, str) else _sanitize_receipt(entry)
                    for entry in item
                ]
            else:
                result[str(key)] = _sanitize_receipt(item)
        return result
    if isinstance(value, list):
        return [_sanitize_receipt(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_receipt(item) for item in value]
    if isinstance(value, str) and value.casefold().startswith(("basic ", "bearer ")):
        return "[REDACTED]"
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_url(value: str) -> str:
    raw = _safe_text(value).rstrip(".,;:)]}")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    authority = f"[{host}]" if ":" in host else host
    if port and port != default_port:
        authority = f"{authority}:{port}"
    path = parsed.path or "/"
    query_names = sorted({key for key, _value in parse_qsl(parsed.query, keep_blank_values=True) if key})
    query = "&".join(f"{name}=" for name in query_names)
    return urlunsplit((parsed.scheme.lower(), authority, path, query, ""))


def canonical_host(value: str) -> str:
    raw = _safe_text(value).lower().rstrip(".")
    if raw.startswith(("http://", "https://")):
        try:
            raw = (urlsplit(raw).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    if not raw or len(raw) > 253:
        return ""
    try:
        return str(ipaddress.ip_address(raw.strip("[]")))
    except ValueError:
        pass
    if not HOST_RE.fullmatch(raw):
        return ""
    return raw


def _record(kind: str, value: str, tool_id: str, source: str, status: str, **attributes: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "value": value,
        "tool_id": tool_id,
        "source": source,
        "status": status,
        "attributes": {key: value for key, value in sorted(attributes.items()) if value is not None and value != "" and value != () and value != []},
    }


def _json_objects(text: str) -> list[dict[str, Any]]:
    """Return bounded JSON/JSONL objects without treating arbitrary text as JSON."""
    values: list[Any] = []
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            values.append(json.loads(stripped))
        except json.JSONDecodeError:
            pass
    if not values:
        for line in text.splitlines()[:10000]:
            candidate = line.strip().rstrip(",")
            if not candidate.startswith(("{", "[")):
                continue
            try:
                values.append(json.loads(candidate))
            except json.JSONDecodeError:
                continue
    result: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if len(result) >= 20000:
            return
        if isinstance(value, dict):
            result.append(value)
            for nested in value.values():
                if isinstance(nested, (dict, list)):
                    visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    for value in values:
        visit(value)
    return result


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [str(value)]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float)) and not isinstance(item, bool)]
    return []


def _structured_records(
    text: str,
    kinds: set[str],
    tool_id: str,
    source: str,
    status: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse common JSON/JSONL/XML runner outputs into the shared typed schema."""
    accepted: dict[tuple[str, str], dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []

    def add(kind: str, value: str, **attributes: Any) -> None:
        cleaned = _safe_text(value, 4096)
        if kind not in kinds or not cleaned:
            return
        if kind == "url":
            cleaned = canonical_url(cleaned)
        elif kind == "origin":
            url = canonical_url(cleaned)
            if url:
                parsed = urlsplit(url)
                cleaned = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            else:
                cleaned = ""
        elif kind == "host":
            cleaned = canonical_host(cleaned)
            if cleaned:
                try:
                    if ipaddress.ip_address(cleaned):
                        cleaned = ""
                except ValueError:
                    pass
        elif kind == "ip":
            try:
                cleaned = str(ipaddress.ip_address(cleaned.strip("[]")))
            except ValueError:
                cleaned = ""
        elif kind == "service":
            cleaned = canonical_service(cleaned, attributes)
            endpoint = parse_service(cleaned)
            if endpoint:
                attributes.update({"host": endpoint.host, "port": endpoint.port, "protocol": endpoint.protocol})
        if not cleaned:
            return
        accepted[(kind, cleaned)] = _record(kind, cleaned, tool_id, source, status, **attributes)

    for row in _json_objects(text):
        urls: list[str] = []
        for field in ("url", "input", "matched-at", "matched_at", "endpoint", "final_url", "final-url"):
            urls.extend(value for value in _string_values(row.get(field)) if value.startswith(("http://", "https://")))
        for url in urls:
            add("url", url)
            add("origin", url)

        hosts: list[str] = []
        ips: list[str] = []
        for field in ("host", "hostname", "domain", "fqdn"):
            hosts.extend(_string_values(row.get(field)))
        for field in ("ip", "address"):
            ips.extend(_string_values(row.get(field)))
        for host in hosts:
            try:
                ips.append(str(ipaddress.ip_address(host.strip("[]"))))
            except ValueError:
                add("host", host)
        for ip in ips:
            add("ip", ip)

        service_host = next((canonical_host(value) for value in [*ips, *hosts] if canonical_host(value)), "")
        protocol = str(row.get("protocol", row.get("transport", "tcp"))).casefold()
        protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
        ports: list[int] = []
        raw_port = row.get("port")
        if isinstance(raw_port, (int, str)) and str(raw_port).isdigit():
            ports.append(int(raw_port))
        raw_ports = row.get("ports")
        if isinstance(raw_ports, list):
            for item in raw_ports:
                candidate = item.get("port") if isinstance(item, dict) else item
                if isinstance(candidate, (int, str)) and str(candidate).isdigit():
                    ports.append(int(candidate))
        if service_host:
            for port in sorted(set(number for number in ports if 1 <= number <= 65535)):
                service_attributes = {
                    key: row.get(key)
                    for key in ("service", "name", "product", "version", "extrainfo", "tunnel")
                    if row.get(key) not in (None, "", [], {})
                }
                add(
                    "service", f"{service_host}:{port}/{protocol}",
                    host=service_host, port=port, protocol=protocol, **service_attributes,
                )

        for field in ("tech", "technologies", "technology", "webserver", "server", "product"):
            for value in _string_values(row.get(field)):
                add("technology", value, field=field)
        for field in ("title", "banner", "hash", "favicon_hash"):
            for value in _string_values(row.get(field)):
                add("fingerprint", value, field=field)

        finding_values: list[str] = []
        for field in ("finding", "vulnerability", "description", "cve"):
            finding_values.extend(_string_values(row.get(field)))
        template = str(row.get("template-id", row.get("template_id", ""))).strip()
        info = row.get("info")
        if template and isinstance(info, dict):
            name = str(info.get("name", "")).strip()
            severity = str(info.get("severity", "")).strip()
            matched = next(iter(urls), "")
            finding_values.append(" ".join(value for value in (template, severity, name, matched) if value))
        for value in finding_values:
            if value:
                add("finding", value, cves=sorted({item.upper() for item in CVE_RE.findall(value)}))

    xml_start = text.find("<?xml")
    if xml_start < 0:
        xml_start = text.find("<nmaprun")
    if xml_start >= 0:
        try:
            root = ET.fromstring(text[xml_start:].strip())
        except ET.ParseError as exc:
            rejected.append({"candidate": source, "reason": f"invalid-xml:{exc}", "tool_id": tool_id, "source": source})
        else:
            for host_node in root.findall(".//host"):
                addresses = [str(node.attrib.get("addr", "")) for node in host_node.findall("address")]
                names = [str(node.attrib.get("name", "")) for node in host_node.findall("./hostnames/hostname")]
                for address in addresses:
                    add("ip", address)
                for name in names:
                    add("host", name)
                service_host = next((canonical_host(value) for value in [*addresses, *names] if canonical_host(value)), "")
                for port_node in host_node.findall("./ports/port"):
                    state_node = port_node.find("state")
                    if state_node is not None and str(state_node.attrib.get("state", "")) != "open":
                        continue
                    port_text = str(port_node.attrib.get("portid", ""))
                    protocol = str(port_node.attrib.get("protocol", "tcp")).casefold()
                    service_node = port_node.find("service")
                    service_attributes = {
                        field: str(service_node.attrib.get(field, "")).strip()
                        for field in ("name", "product", "version", "extrainfo", "tunnel")
                        if service_node is not None and str(service_node.attrib.get(field, "")).strip()
                    }
                    if service_host and port_text.isdigit() and 1 <= int(port_text) <= 65535:
                        port = int(port_text)
                        add(
                            "service", f"{service_host}:{port}/{protocol}",
                            host=service_host, port=port, protocol=protocol, **service_attributes,
                        )
                    if service_node is not None:
                        description = " ".join(
                            str(service_node.attrib.get(field, "")).strip()
                            for field in ("name", "product", "version", "extrainfo")
                            if str(service_node.attrib.get(field, "")).strip()
                        )
                        add("technology", description, port=int(port_text) if port_text.isdigit() else 0)
                        add("fingerprint", description, port=int(port_text) if port_text.isdigit() else 0)

    # Nmap grepable output is still common in native/catalog handoffs.
    for line in text.splitlines():
        host_match = re.search(r"^Host:\s+(\S+).*?Ports:\s+(.+)$", line)
        if not host_match:
            continue
        host = canonical_host(host_match.group(1))
        for entry in host_match.group(2).split(","):
            fields = entry.strip().split("/")
            if len(fields) < 3 or fields[1] != "open" or not fields[0].isdigit():
                continue
            port, protocol = int(fields[0]), fields[2].casefold()
            if host and 1 <= port <= 65535 and protocol in {"tcp", "udp"}:
                add(
                    "service", f"{host}:{port}/{protocol}", host=host, port=port,
                    protocol=protocol, name=fields[4] if len(fields) > 4 else "",
                )
            if len(fields) > 4 and fields[4]:
                add("technology", fields[4], port=port)
    return sorted(accepted.values(), key=lambda row: (row["kind"], row["value"])), rejected


def normalize_text(text: str, output_kinds: Iterable[str], tool_id: str, source: str, status: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract typed observations while retaining rejected candidates separately."""
    kinds = set(output_kinds)
    accepted: dict[tuple[str, str], dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    urls = {canonical_url(match.group(0)) for match in URL_RE.finditer(text)}
    urls.discard("")
    if "url" in kinds or "origin" in kinds or "path" in kinds or "parameter" in kinds:
        for url in sorted(urls):
            parsed = urlsplit(url)
            if "url" in kinds:
                accepted[("url", url)] = _record("url", url, tool_id, source, status)
            origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            if "origin" in kinds:
                accepted[("origin", origin)] = _record("origin", origin, tool_id, source, status)
            if "path" in kinds:
                accepted[("path", f"{origin}{parsed.path or '/'}")] = _record("path", f"{origin}{parsed.path or '/'}", tool_id, source, status)
            if "parameter" in kinds:
                for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
                    if name:
                        accepted[("parameter", name)] = _record("parameter", name, tool_id, source, status, url=url)
    if "ip" in kinds:
        for match in IP_RE.finditer(text):
            try:
                value = str(ipaddress.ip_address(match.group(0)))
            except ValueError:
                rejected.append({"candidate": match.group(0), "reason": "invalid-ip", "tool_id": tool_id, "source": source})
                continue
            accepted[("ip", value)] = _record("ip", value, tool_id, source, status)
    if "host" in kinds:
        candidates = set(HOST_RE.findall(text))
        for url in urls:
            candidates.add(urlsplit(url).hostname or "")
        for candidate in sorted(candidates):
            value = canonical_host(candidate)
            if value:
                accepted[("host", value)] = _record("host", value, tool_id, source, status)
    if "service" in kinds:
        for match in SERVICE_RE.finditer(text):
            host = canonical_host(match.group(1))
            port = int(match.group(2))
            protocol = match.group(3).lower()
            if host and 1 <= port <= 65535:
                value = canonical_service(
                    f"{host}:{port}/{protocol}",
                    {"host": host, "port": port, "protocol": protocol},
                )
                accepted[("service", value)] = _record("service", value, tool_id, source, status, host=host, port=port, protocol=protocol)
    if "finding" in kinds:
        for number, line in enumerate(text.splitlines(), start=1):
            cleaned = _safe_text(line, 4096)
            lowered = cleaned.casefold()
            if not cleaned or not (CVE_RE.search(cleaned) or any(token in lowered for token in ("vulnerab", "confirmed", "exposed", "takeover", "secret"))):
                continue
            digest = hashlib.sha256(cleaned.encode()).hexdigest()
            accepted[("finding", digest)] = _record("finding", cleaned, tool_id, source, status, line=number, cves=sorted({value.upper() for value in CVE_RE.findall(cleaned)}))
    if "technology" in kinds or "fingerprint" in kinds:
        for number, line in enumerate(text.splitlines(), start=1):
            cleaned = _safe_text(line, 2048)
            if not cleaned or len(cleaned) > 1024:
                continue
            lowered = cleaned.casefold()
            if not any(token in lowered for token in ("server:", "powered-by", "technology", "tls", "ssl", "waf", "certificate", "product", "version")):
                continue
            kind = "technology" if "technology" in kinds else "fingerprint"
            digest = hashlib.sha256(cleaned.encode()).hexdigest()
            accepted[(kind, digest)] = _record(kind, cleaned, tool_id, source, status, line=number)
    structured, structured_rejected = _structured_records(text, kinds, tool_id, source, status)
    for row in structured:
        accepted[(str(row["kind"]), str(row["value"]))] = row
    rejected.extend(structured_rejected)
    return sorted(accepted.values(), key=lambda row: (row["kind"], row["value"])), rejected


@dataclass(frozen=True)
class MethodPlan:
    tool_id: str
    runner_id: str
    block: str
    status: str
    reason: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    adapter: str = ""
    contact: str = "none"
    command: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id, "runner_id": self.runner_id, "block": self.block,
            "status": self.status, "reason": self.reason, "inputs": list(self.inputs),
            "outputs": list(self.outputs), "adapter": self.adapter,
            "contact": self.contact, "command": list(self.command),
        }


@dataclass
class MethodResult:
    plan: MethodPlan
    status: str
    reason: str = ""
    records: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    receipt: dict[str, Any] = field(default_factory=dict)
    human_lines: list[str] = field(default_factory=list)
    native_artifacts: list[Path] = field(default_factory=list)


class ResultStore:
    """Persist one complete, nonempty evidence envelope per method and round."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.pipeline_root = self.root / "typed-pipeline"

    def method_directory(self, block: str, tool_id: str, round_number: int) -> Path:
        if block not in TOOL_INVENTORY["blocks"] or not SAFE_ID_RE.fullmatch(tool_id):
            raise ValueError("unsafe block or tool identity")
        return self.pipeline_root / f"round-{round_number:02d}" / block / tool_id

    def _evidence_artifacts(self, destination: Path, paths: Iterable[Path]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[Path] = set()
        for path in sorted({Path(item) for item in paths}, key=lambda item: str(item)):
            try:
                resolved = path.resolve()
                destination_resolved = destination.resolve()
            except OSError:
                continue
            if resolved in seen or not resolved.is_file() or resolved.is_symlink():
                continue
            try:
                relative = resolved.relative_to(destination_resolved)
            except ValueError:
                try:
                    relative = resolved.relative_to(self.root.resolve())
                except ValueError:
                    continue
            seen.add(resolved)
            rows.append({
                "path": str(relative),
                "size": resolved.stat().st_size,
                "sha256": _sha256(resolved),
            })
        return rows

    def write(self, result: MethodResult, round_number: int) -> Path:
        if result.status not in TERMINAL_STATES:
            raise ValueError(f"method result is not terminal: {result.status}")
        destination = self.method_directory(result.plan.block, result.plan.tool_id, round_number)
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        records = sorted(result.records, key=lambda row: (str(row.get("kind", "")), str(row.get("value", ""))))
        rejected = sorted(result.rejected, key=_json_line)
        records_path = destination / "records.jsonl"
        rejected_path = destination / "rejected.jsonl"
        _atomic_write(records_path, "".join(_json_line(row) + "\n" for row in records))
        _atomic_write(rejected_path, "".join(_json_line(row) + "\n" for row in rejected))
        native_artifacts = list(result.native_artifacts)
        native_path = destination / "native.txt"
        native_listing = []
        for path in native_artifacts:
            try:
                native_listing.append(str(Path(path).resolve().relative_to(destination.resolve())))
            except (OSError, ValueError):
                native_listing.append(Path(path).name)
        native_text = (
            f"status={result.status}\n"
            f"reason={result.reason or result.plan.reason or 'no native artifact emitted'}\n"
        )
        if native_listing:
            native_text += "native_artifacts:\n" + "".join(f"- {item}\n" for item in sorted(set(native_listing)))
        _atomic_write(native_path, native_text)
        native_artifacts.append(native_path)
        commands = result.receipt.get("commands", [])
        if isinstance(commands, list) and commands:
            command_text = "\n".join(
                " ".join(_redact_command_tokens(str(value).split()))
                for value in commands
                if _safe_text(value, 8192)
            ) + "\n"
        else:
            command_text = f"status={result.status}\nreason={result.reason or result.plan.reason or 'native or deferred method'}\n"
        command_path = destination / "command.txt"
        _atomic_write(command_path, command_text)
        result_path = destination / "result.txt"
        lines = [
            "AH-PUCH METHOD RESULT",
            f"Tool: {result.plan.tool_id}",
            f"Runner: {result.plan.runner_id}",
            f"Block: {result.plan.block}",
            f"Status: {result.status}",
            f"Reason: {result.reason or result.plan.reason or '-'}",
            f"Accepted records: {len(records)}",
            f"Rejected records: {len(rejected)}",
            "",
            "Results:",
        ]
        if result.human_lines:
            lines.extend(_safe_text(value, 4096) for value in result.human_lines if _safe_text(value, 4096))
        elif records:
            lines.extend(f"[{row['kind']}] {row['value']}" for row in records)
        else:
            lines.append("No findings or observations were accepted for this method.")
        _atomic_write(result_path, "\n".join(lines).rstrip() + "\n")
        evidence_inputs = [records_path, rejected_path, command_path, result_path, *native_artifacts]
        evidence_artifacts = self._evidence_artifacts(destination, evidence_inputs)
        receipt = {
            "schema_version": SCHEMA_VERSION,
            **result.plan.as_dict(),
            "status": result.status,
            "reason": result.reason or result.plan.reason,
            "accepted_records": len(records),
            "rejected_records": len(rejected),
            "evidence_artifacts": evidence_artifacts,
            "checksums_file": "checksums.sha256",
            **result.receipt,
        }
        receipt = _sanitize_receipt(receipt)
        _atomic_write(destination / "receipt.json", json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        checksum_files = [path for path in sorted(destination.iterdir()) if path.is_file() and path.name != "checksums.sha256"]
        _atomic_write(destination / "checksums.sha256", "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_files))
        return destination


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


class FanIn:
    """Union every method observation without discarding provenance or disagreement."""

    def __init__(self, store: ResultStore):
        self.store = store

    def build(self, block: str, round_number: int, expected_tools: Iterable[str]) -> dict[str, Any]:
        block_root = self.store.pipeline_root / f"round-{round_number:02d}" / block
        output = block_root / "_fan_in"
        by_key: dict[tuple[str, str], dict[str, Any]] = {}
        rejected: list[dict[str, Any]] = []
        statuses: dict[str, str] = {}
        for tool_id in sorted(set(expected_tools)):
            method = block_root / tool_id
            try:
                receipt = json.loads((method / "receipt.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                statuses[tool_id] = "missing"
                continue
            statuses[tool_id] = str(receipt.get("status", "missing"))
            for row in read_jsonl(method / "records.jsonl"):
                key = (str(row.get("kind", "")), str(row.get("value", "")))
                if not all(key):
                    continue
                merged = by_key.setdefault(key, {"schema_version": SCHEMA_VERSION, "kind": key[0], "value": key[1], "observations": []})
                observation = {field: row.get(field) for field in ("tool_id", "source", "status", "attributes")}
                if observation not in merged["observations"]:
                    merged["observations"].append(observation)
            rejected.extend(read_jsonl(method / "rejected.jsonl"))
        records: list[dict[str, Any]] = []
        for row in by_key.values():
            row["observations"] = sorted(row["observations"], key=_json_line)
            row["tools"] = sorted({str(item.get("tool_id", "")) for item in row["observations"] if item.get("tool_id")})
            row["promotable"] = any(str(item.get("status", "")) in PROMOTABLE_STATES for item in row["observations"])
            records.append(row)
        records.sort(key=lambda row: (row["kind"], row["value"]))
        promoted = [row for row in records if row["promotable"]]
        _atomic_write(output / "all_records.jsonl", "".join(_json_line(row) + "\n" for row in records))
        _atomic_write(output / "verified_records.jsonl", "".join(_json_line(row) + "\n" for row in promoted))
        _atomic_write(output / "rejected_records.jsonl", "".join(_json_line(row) + "\n" for row in sorted(rejected, key=_json_line)))
        for kind in sorted({str(row["kind"]) for row in records} | {"host", "ip", "service", "origin", "url", "path", "parameter", "technology", "fingerprint", "finding"}):
            values = [str(row["value"]) for row in promoted if row["kind"] == kind]
            _atomic_write(output / f"verified_{kind}s.txt", "\n".join(values) + ("\n" if values else ""))
        coverage = ["tool\tstatus\trecords\tunique\toverlapped"]
        unique = ["tool\tunique_records"]
        comparison = ["kind\tvalue\tmethod_count\tmethods"]
        for tool_id in sorted(statuses):
            observed = [row for row in records if tool_id in row["tools"]]
            unique_count = sum(1 for row in observed if len(row["tools"]) == 1)
            coverage.append(f"{tool_id}\t{statuses[tool_id]}\t{len(observed)}\t{unique_count}\t{len(observed)-unique_count}")
            unique.append(f"{tool_id}\t{unique_count}")
        for row in records:
            comparison.append(f"{row['kind']}\t{row['value']}\t{len(row['tools'])}\t{','.join(row['tools'])}")
        _atomic_write(output / "coverage_by_tool.tsv", "\n".join(coverage) + "\n")
        _atomic_write(output / "unique_by_tool.tsv", "\n".join(unique) + "\n")
        _atomic_write(output / "method_comparison.tsv", "\n".join(comparison) + "\n")
        return {"block": block, "round": round_number, "records": len(records), "promotable": len(promoted), "statuses": statuses, "output": str(output)}


def write_barrier(store: ResultStore, block: str, round_number: int, expected_tools: Iterable[str], *, continue_on_partial: bool = True) -> dict[str, Any]:
    root = store.pipeline_root / f"round-{round_number:02d}" / block
    statuses: dict[str, str] = {}
    for tool_id in sorted(set(expected_tools)):
        try:
            receipt = json.loads((root / tool_id / "receipt.json").read_text(encoding="utf-8"))
            statuses[tool_id] = str(receipt.get("status", "missing"))
        except (OSError, json.JSONDecodeError):
            statuses[tool_id] = "missing"
    nonterminal = sorted(tool for tool, status in statuses.items() if status not in TERMINAL_STATES)
    adverse = sorted(tool for tool, status in statuses.items() if status in {"failed", "timeout", "partial"})
    ready = not nonterminal
    proceed = ready and (continue_on_partial or not adverse)
    payload = {
        "schema_version": SCHEMA_VERSION, "block": block, "round": round_number,
        "ready": ready, "proceed": proceed, "continue_on_partial": continue_on_partial,
        "statuses": statuses, "nonterminal": nonterminal, "adverse": adverse,
    }
    _atomic_write(root / "phase_barrier.json", json.dumps(payload, indent=2, sort_keys=True) + "\n")
    lines = [f"Block: {block}", f"Round: {round_number}", f"Ready: {str(ready).lower()}", f"Proceed: {str(proceed).lower()}", "", "Method states:"]
    lines.extend(f"{tool}: {statuses[tool]}" for tool in sorted(statuses))
    _atomic_write(root / "phase_barrier.txt", "\n".join(lines) + "\n")
    return payload


class ConvergenceLedger:
    def __init__(self, store: ResultStore, max_rounds: int):
        if not 1 <= int(max_rounds) <= 10:
            raise ValueError("maximum recon rounds must be between 1 and 10")
        self.store = store
        self.max_rounds = int(max_rounds)
        self.rows: list[dict[str, Any]] = []

    def observe(self, round_number: int, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
        identities = sorted({f"{row.get('kind','')}\t{row.get('value','')}" for row in records if row.get("promotable", True)})
        digest = hashlib.sha256("\n".join(identities).encode()).hexdigest()
        prior = self.rows[-1] if self.rows else None
        current = {
            "round": round_number, "records": len(identities), "sha256": digest,
            "new_records": len(set(identities) - set(prior.get("identities", []))) if prior else len(identities),
            "converged": bool(prior and prior.get("sha256") == digest),
            "identities": identities,
        }
        self.rows.append(current)
        public = [{key: value for key, value in row.items() if key != "identities"} for row in self.rows]
        _atomic_write(self.store.pipeline_root / "convergence.json", json.dumps({"schema_version": SCHEMA_VERSION, "max_rounds": self.max_rounds, "rounds": public}, indent=2, sort_keys=True) + "\n")
        _atomic_write(self.store.pipeline_root / "convergence.txt", "\n".join(f"round={row['round']} records={row['records']} new={row['new_records']} converged={str(row['converged']).lower()} sha256={row['sha256']}" for row in public) + "\n")
        return current

    def should_continue(self) -> bool:
        return bool(self.rows and not self.rows[-1]["converged"] and len(self.rows) < self.max_rounds)


def inventory_tools(profile: str, block: str | None = None) -> list[dict[str, Any]]:
    values = [dict(row) for row in TOOL_INVENTORY["tools"] if profile in row["profiles"]]
    if block:
        values = [row for row in values if row["block"] == block]
    return sorted(values, key=lambda row: (TOOL_INVENTORY["blocks"].index(row["block"]), row["id"]))
