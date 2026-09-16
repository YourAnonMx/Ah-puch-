#!/usr/bin/env python3
"""Structured handoff and target-boundary enforcement for catalog module 9.

Only validated requested ports may reach the Open Ports subprocess. Only
current socket observations attached to the target may become service evidence.
Passive Shodan-only observations remain provenance inside the module artifact.
"""
from __future__ import annotations

import ipaddress
from typing import Any

try:
    from .artifact_bus import ArtifactBus
    from .catalog_artifact_runtime import _embedded_json, _project_host_assets, _result_path
except ImportError:
    from artifact_bus import ArtifactBus
    from catalog_artifact_runtime import _embedded_json, _project_host_assets, _result_path

_DEFAULT_PORTSPEC = "1-1024"


def _parse_ports(portspec: object) -> list[int]:
    text = str(portspec or "").strip()
    if not text:
        raise ValueError("port expression is empty")
    ports: set[int] = set()
    for raw in text.split(","):
        token = raw.strip()
        if not token:
            raise ValueError("empty port token")
        if "-" in token:
            fields = token.split("-")
            if len(fields) != 2:
                raise ValueError(f"invalid port range: {token}")
            start, end = (int(value) for value in fields)
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range: {token}")
            ports.add(port)
    return sorted(ports)


def _format_ports(ports: list[int]) -> str:
    values = sorted(set(int(port) for port in ports if 1 <= int(port) <= 65535))
    if not values:
        return ""
    ranges: list[str] = []
    start = previous = values[0]
    for port in values[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def _effective_ports(run: Any, input_value: str) -> tuple[str, str]:
    requested_spec = str(getattr(run, "option_overrides", {}).get("ports", _DEFAULT_PORTSPEC) or _DEFAULT_PORTSPEC)
    try:
        requested = _parse_ports(requested_spec)
    except (TypeError, ValueError) as exc:
        return "", f"invalid requested port expression: {exc}"

    return _format_ports(requested), ""


def _write_gate(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int, reason: str) -> None:
    module_id = str(item.get("id", "9"))
    name = str(item.get("name", "Open Ports Scan"))
    destination = run.module_root / f"{module_id}-{base.slug(name)}" / str(index)
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    run.write_module_text(
        destination,
        {
            "engine": "ahpuch_modules",
            "module_id": module_id,
            "module": name,
            "script": str(item.get("script", "open_ports.py")),
            "class": base.module_class(item),
            "input": input_value,
            "reason": reason,
        },
        "gated",
        "Open Ports Scan was not started because the requested TCP endpoint was rejected.\n",
    )


def _open_ports_from_result(path: Any) -> dict[str, Any]:
    payload = _embedded_json(path, "open_ports.json")
    if not isinstance(payload, dict) or payload.get("state") != "success":
        return {}
    try:
        canonical_ip = str(ipaddress.ip_address(str(payload.get("ip", "")).strip()))
    except ValueError:
        return {}
    rows = payload.get("open_ports", [])
    if not isinstance(rows, list):
        return {}
    verified: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("verified_current") is not True:
            continue
        try:
            port = int(row.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        verified.append(
            {
                "port": port,
                "service": str(row.get("service", "") or "").strip(),
                "source": str(row.get("source", "") or "").strip(),
            }
        )
    return {**payload, "ip": canonical_ip, "verified_ports": verified}


def _service_within_target(run: Any, input_value: str, ip: str, port: int) -> bool:
    del input_value
    endpoint_allowed = getattr(run, "_endpoint_allowed_current", None) or getattr(run, "_endpoint_allowed", None)
    if callable(endpoint_allowed):
        return bool(endpoint_allowed(ip, port, "open-port", "tcp"))
    allow_network = getattr(run, "_network_allowed", run._allowed)
    return bool(allow_network(ip))


def _project_module_9(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    result = _result_path(base, run, item, index)
    payload = _open_ports_from_result(result)
    if not payload:
        return

    ip = str(payload["ip"])
    source_host = str(payload.get("host", "") or "").strip().lower().rstrip(".")
    promoted_hosts, observed_hosts = _project_host_assets(
        base,
        run,
        source_host=source_host,
        addresses=[ip],
        hosts=[],
        producer="catalog-module:9-open-ports",
    )

    bus = ArtifactBus(run.root, run.target)
    observed_services = promoted_services = 0
    for row in payload["verified_ports"]:
        port = int(row["port"])
        within_target = _service_within_target(run, input_value, ip, port)
        if bus.observe(
            "service",
            "",
            producer="catalog-module:9-open-ports",
            source=str(result.relative_to(run.root)),
            status="verified",
            within_target=within_target,
            attributes={
                "host": ip,
                "port": port,
                "protocol": "tcp",
                "service": str(row.get("service", "") or "open-port"),
                "source": str(row.get("source", "")),
                "target_input": input_value,
            },
        ):
            observed_services += 1
            if within_target:
                promoted_services += 1
    if observed_services:
        bus.save()

    run.event(
        {
            "engine": "catalog_artifact_handoff",
            "module_id": "9",
            "module": str(item.get("name", "Open Ports Scan")),
            "status": "success",
            "observed_hosts": observed_hosts,
            "promoted_hosts": len(promoted_hosts),
            "observed_services": observed_services,
            "promoted_services": promoted_services,
            "quarantined_services": observed_services - promoted_services,
        }
    )


def install(base: Any) -> Any:
    """Wrap catalog dispatch exactly once for module 9 scope enforcement/projection."""
    base.OPTION_DEFAULTS.setdefault("ports", _DEFAULT_PORTSPEC)
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_catalog_open_ports", False):
        return base

    class CatalogOpenPortsUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_catalog_open_ports = True

        def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
            if str(item.get("id", "")) != "9":
                super().run_catalog_module(item, input_value, index)
                return

            effective_ports, reason = _effective_ports(self, input_value)
            if reason:
                _write_gate(base, self, item, input_value, index, reason)
                return

            effective_item = dict(item)
            effective_item["options"] = list(dict.fromkeys([*item.get("options", []), "ports"]))
            previous = self.option_overrides.get("ports", None)
            had_previous = "ports" in self.option_overrides
            self.option_overrides["ports"] = effective_ports
            try:
                super().run_catalog_module(effective_item, input_value, index)
            finally:
                if had_previous:
                    self.option_overrides["ports"] = previous
                else:
                    self.option_overrides.pop("ports", None)
            _project_module_9(base, self, effective_item, input_value, index)

    CatalogOpenPortsUnifiedRun.__name__ = "CatalogOpenPortsUnifiedRun"
    CatalogOpenPortsUnifiedRun.__qualname__ = "CatalogOpenPortsUnifiedRun"
    base.UnifiedRun = CatalogOpenPortsUnifiedRun
    return base
