#!/usr/bin/env python3
"""Canonical service parsing and evidence-driven downstream routing."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit


_HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
_TLS_HINTS = frozenset({"https", "ssl", "tls", "wss", "secure-http", "http-over-tls"})
_HTTP_HINTS = frozenset(
    {
        "http", "http-alt", "http-proxy", "web", "webui", "web-ui", "www",
        "nginx", "apache", "tomcat", "jetty", "iis", "lighttpd", "caddy",
    }
)
_HTTP_PORTS = frozenset(
    {
        80, 81, 3000, 4000, 5000, 5601, 7001, 7080, 7777, 8000, 8001,
        8008, 8080, 8081, 8088, 8888, 8983, 9000, 9090,
    }
)
_HTTPS_PORTS = frozenset({443, 4443, 5443, 6443, 7443, 8443, 8843, 9443, 10443})


@dataclass(frozen=True, order=True)
class ServiceEndpoint:
    """One observed transport endpoint with a stable URI representation."""

    host: str
    port: int
    protocol: str

    @property
    def authority(self) -> str:
        display = f"[{self.host}]" if ":" in self.host else self.host
        return f"{display}:{self.port}"

    @property
    def uri(self) -> str:
        return f"{self.protocol}://{self.authority}"


def canonical_host(value: object) -> str:
    raw = str(value or "").strip().strip("[]").rstrip(".")
    if not raw or any(character.isspace() for character in raw):
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    try:
        ascii_host = raw.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return ""
    return ascii_host if _HOST_RE.fullmatch(ascii_host) else ""


def parse_service(value: object, attributes: dict[str, Any] | None = None) -> ServiceEndpoint | None:
    """Parse canonical service URIs and the retired ``host:port/proto`` form."""
    attrs = attributes if isinstance(attributes, dict) else {}
    protocol = str(attrs.get("protocol", "")).strip().casefold()
    host = canonical_host(attrs.get("host", ""))
    try:
        port = int(attrs.get("port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if host and protocol in {"tcp", "udp"} and 1 <= port <= 65535:
        return ServiceEndpoint(host, port, protocol)

    raw = str(value or "").strip()
    if raw.startswith(("tcp://", "udp://")):
        parsed = urlsplit(raw)
        protocol = parsed.scheme.casefold()
        host = canonical_host(parsed.hostname or "")
        try:
            port = int(parsed.port or 0)
        except ValueError:
            return None
    elif "/" in raw:
        authority, protocol = raw.rsplit("/", 1)
        protocol = protocol.casefold().strip()
        if ":" not in authority:
            return None
        host_text, port_text = authority.rsplit(":", 1)
        host = canonical_host(host_text)
        if not port_text.isdigit():
            return None
        port = int(port_text)
    else:
        return None
    if not host or protocol not in {"tcp", "udp"} or not 1 <= port <= 65535:
        return None
    return ServiceEndpoint(host, port, protocol)


def canonical_service(value: object, attributes: dict[str, Any] | None = None) -> str:
    endpoint = parse_service(value, attributes)
    return endpoint.uri if endpoint else ""


def observation_hints(row: dict[str, Any]) -> list[str]:
    """Collect bounded service/product evidence without losing provenance."""
    values: list[str] = []
    direct = row.get("attributes", {})
    sources = [direct] if isinstance(direct, dict) else []
    for observation in row.get("observations", []):
        if isinstance(observation, dict) and isinstance(observation.get("attributes"), dict):
            sources.append(observation["attributes"])
    for attributes in sources:
        for key in ("service", "name", "product", "version", "extrainfo", "technology", "fingerprint", "banner", "tunnel"):
            value = attributes.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                values.append(str(value).strip()[:1024])
        nested = attributes.get("hints")
        if isinstance(nested, list):
            values.extend(str(value).strip()[:1024] for value in nested if str(value).strip())
    return list(dict.fromkeys(values))


def _tokens(hints: Iterable[object]) -> set[str]:
    tokens: set[str] = set()
    for hint in hints:
        text = str(hint or "").casefold()
        tokens.update(value for value in re.split(r"[^a-z0-9+.-]+", text) if value)
    return tokens


def http_probe_target(value: object, attributes: dict[str, Any] | None = None) -> str:
    """Return an HTTPX-compatible authority for any observed TCP service."""
    endpoint = parse_service(value, attributes)
    return endpoint.authority if endpoint and endpoint.protocol == "tcp" else ""


def origin_candidates(
    value: object,
    attributes: dict[str, Any] | None = None,
    *,
    hints: Iterable[object] = (),
) -> list[str]:
    """Derive bounded HTTP origins only from port or service fingerprint evidence."""
    endpoint = parse_service(value, attributes)
    if endpoint is None or endpoint.protocol != "tcp":
        return []
    tokens = _tokens(hints)
    secure = endpoint.port in _HTTPS_PORTS or bool(tokens & _TLS_HINTS)
    web = endpoint.port in _HTTP_PORTS or secure or bool(tokens & _HTTP_HINTS)
    if not web:
        return []
    schemes = ("https", "http") if secure else ("http", "https")
    return [f"{scheme}://{endpoint.authority}" for scheme in schemes]


def origins_from_record(row: dict[str, Any]) -> list[str]:
    return origin_candidates(
        row.get("value", ""),
        row.get("attributes") if isinstance(row.get("attributes"), dict) else None,
        hints=observation_hints(row),
    )
