#!/usr/bin/env python3
"""Evidence-driven industrial protocol routing for observed services."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

try:
    from .service_routing import ServiceEndpoint, observation_hints, parse_service
except ImportError:
    from service_routing import ServiceEndpoint, observation_hints, parse_service


@dataclass(frozen=True)
class IndustrialProfile:
    name: str
    transports: frozenset[str]
    standard_ports: frozenset[int]
    fingerprint_tokens: frozenset[str]
    nmap_scripts: tuple[str, ...]


@dataclass(frozen=True)
class IndustrialRoute:
    endpoint: ServiceEndpoint
    protocol: str
    evidence: tuple[str, ...]
    nmap_scripts: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "service": self.endpoint.uri,
            "host": self.endpoint.host,
            "port": self.endpoint.port,
            "transport": self.endpoint.protocol,
            "industrial_protocol": self.protocol,
            "evidence": list(self.evidence),
            "nmap_scripts": list(self.nmap_scripts),
        }


INDUSTRIAL_PROFILES: tuple[IndustrialProfile, ...] = (
    IndustrialProfile("modbus", frozenset({"tcp"}), frozenset({502}), frozenset({"modbus"}), ("modbus-discover",)),
    IndustrialProfile("s7", frozenset({"tcp"}), frozenset({102}), frozenset({"s7", "siemens", "iso-tsap"}), ("s7-info",)),
    IndustrialProfile("bacnet", frozenset({"tcp", "udp"}), frozenset({47808}), frozenset({"bacnet"}), ("bacnet-info",)),
    IndustrialProfile("dnp3", frozenset({"tcp", "udp"}), frozenset({20000}), frozenset({"dnp3"}), ()),
    IndustrialProfile("ethernet-ip", frozenset({"tcp", "udp"}), frozenset({44818}), frozenset({"enip", "ethernet-ip", "ethernet/ip"}), ("enip-info",)),
    IndustrialProfile("omron-fins", frozenset({"tcp", "udp"}), frozenset({9600}), frozenset({"omron", "fins"}), ("omron-info",)),
)


def industrial_keywords() -> tuple[str, ...]:
    values = {profile.name for profile in INDUSTRIAL_PROFILES}
    for profile in INDUSTRIAL_PROFILES:
        values.update(profile.fingerprint_tokens)
    values.update({"scada", "industrial-control"})
    return tuple(sorted(values))


def _fingerprint_tokens(values: Iterable[object]) -> tuple[set[str], str]:
    text = " ".join(str(value or "").casefold() for value in values)
    tokens = set(re.findall(r"[a-z0-9]+(?:[-+][a-z0-9]+)*", text))
    normalized = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return tokens, normalized


def routes_for_service(
    value: object,
    attributes: dict[str, Any] | None = None,
    *,
    hints: Iterable[object] = (),
) -> list[IndustrialRoute]:
    """Return exact observed endpoints justified by port or fingerprint evidence."""
    endpoint = parse_service(value, attributes)
    if endpoint is None:
        return []
    tokens, normalized = _fingerprint_tokens(hints)
    routes: list[IndustrialRoute] = []
    for profile in INDUSTRIAL_PROFILES:
        if endpoint.protocol not in profile.transports:
            continue
        evidence: list[str] = []
        if endpoint.port in profile.standard_ports:
            evidence.append("standard-port")
        matched = sorted(
            token
            for token in profile.fingerprint_tokens
            if token in tokens or token.replace("/", "-") in normalized
        )
        if matched:
            evidence.extend(f"fingerprint:{token}" for token in matched)
        if evidence:
            routes.append(IndustrialRoute(endpoint, profile.name, tuple(evidence), profile.nmap_scripts))
    return sorted(routes, key=lambda route: (route.endpoint.uri, route.protocol))


def routes_from_record(row: dict[str, Any]) -> list[IndustrialRoute]:
    return routes_for_service(
        row.get("value", ""),
        row.get("attributes") if isinstance(row.get("attributes"), dict) else None,
        hints=observation_hints(row),
    )


def nmap_command(executable: str, route: IndustrialRoute) -> list[str]:
    """Build an exact-port Nmap follow-up without substituting a default port."""
    command = [str(executable)]
    try:
        if ipaddress.ip_address(route.endpoint.host).version == 6:
            command.append("-6")
    except ValueError:
        pass
    if route.endpoint.protocol == "udp":
        command.append("-sU")
    command.extend(["-sV", "-Pn", "-p", str(route.endpoint.port)])
    if route.nmap_scripts:
        command.extend(["--script", ",".join(route.nmap_scripts)])
    command.append(route.endpoint.host)
    return command
