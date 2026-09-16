#!/usr/bin/env python3
"""SRC03 target-boundary and terminal-service hardening for network profiles.

This layer does not add a scanner. It constrains the existing network runtime:
requested ports are validated before Masscan/Nmap, discovered candidates are
not promoted as verified services, and terminal services are checked against
the target boundary at the artifact-bus edge.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

try:
    from . import artifact_bus, network_device_runtime, network_runtime
except ImportError:
    import artifact_bus
    import network_device_runtime
    import network_runtime

_INSTALLED = False
_RAW_NETWORK: Callable[..., dict[str, Any]] | None = None
_ORIGINAL_INGEST: Callable[..., int] | None = None
_MAX_PORTS = 65535
_VALIDATION_RUNNERS = frozenset({"network-service", "network-udp"})
_COMPLETED = frozenset({"success", "partial"})


def _parse_ports(value: object, *, max_ports: int = _MAX_PORTS) -> list[int]:
    text = str(value or "").strip()
    if not text:
        return []
    values: set[int] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            raise ValueError("empty port token")
        separator = "-" if "-" in token else (":" if ":" in token else "")
        if separator:
            left, right = token.split(separator, 1)
            if not left.isdigit() or not right.isdigit():
                raise ValueError(f"invalid port range: {token}")
            start, end = int(left), int(right)
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"invalid port range: {token}")
            if len(values) + (end - start + 1) > max_ports:
                raise ValueError(f"port selection exceeds limit {max_ports}")
            values.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"invalid port: {token}")
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {token}")
            values.add(port)
        if len(values) > max_ports:
            raise ValueError(f"port selection exceeds limit {max_ports}")
    return sorted(values)


def _format_ports(values: list[int]) -> str:
    ports = sorted(set(int(value) for value in values if 1 <= int(value) <= 65535))
    if not ports:
        return ""
    groups: list[str] = []
    start = previous = ports[0]
    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue
        groups.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    groups.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(groups)


def _filter_ports(run: Any, target: str, portspec: object) -> tuple[str, str, bool]:
    try:
        requested = _parse_ports(portspec)
    except (TypeError, ValueError) as exc:
        return "", f"invalid network port expression: {exc}", True
    if not requested:
        return "", "", False

    allow_network = getattr(run, "_network_allowed", run._allowed)
    if not bool(allow_network(str(target))):
        return "", "network target is outside the automatic target boundary", True
    return _format_ports(requested), "", False


def _endpoint_allowed(run: Any | None, target_input: str, host: str, port: int) -> bool:
    if run is None:
        return False
    allow_network = getattr(run, "_network_allowed", run._allowed)
    # A concrete address may be the transport identity of the original target
    # hostname, so either the observation or its dispatch identity must match.
    if not bool(allow_network(host)) and not bool(allow_network(target_input)):
        return False
    return bool(1 <= int(port) <= 65535)


def _owner_from_allow(allow_network: Callable[[str], bool]) -> Any | None:
    owner = getattr(allow_network, "__self__", None)
    return owner if owner is not None else network_device_runtime._ACTIVE_RUN


def _hardened_ingest_network_profile(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow_network: Callable[[str], bool],
) -> int:
    """Promote only terminal Nmap validation rows, never Masscan discovery rows."""
    path = root / "network-profile-runtime" / "runs.jsonl"
    run = _owner_from_allow(allow_network)
    count = 0
    for row in network_device_runtime._jsonl(path):
        status = str(row.get("status", "unknown")).strip().lower() or "unknown"
        runner = str(row.get("runner", "network-profile")).strip() or "network-profile"
        if runner not in _VALIDATION_RUNNERS or status not in _COMPLETED:
            continue
        target_input = str(row.get("host", "") or "").strip()
        services = row.get("services", []) if isinstance(row.get("services"), list) else []
        for service in services:
            if not isinstance(service, dict):
                continue
            host = artifact_bus.canonical_host(str(service.get("host", "")))
            try:
                port = int(service.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            protocol = str(service.get("protocol", "tcp")).strip().lower() or "tcp"
            if not host or not (1 <= port <= 65535) or protocol not in {"tcp", "udp"}:
                continue
            basis = str(service.get("target_input", "") or target_input or host)
            if run is not None:
                within_target = _endpoint_allowed(run, basis, host, port)
            else:
                within_target = bool(allow_network(host))
            host_kind = "ip" if artifact_bus.canonical_ip(host) else "host"
            producer = f"network-profile/{runner}"
            bus.observe(
                host_kind,
                host,
                producer=producer,
                source="network-profile-runtime/runs.jsonl",
                status=status,
                within_target=within_target,
                attributes={"network_observation": True, "target_input": basis},
            )
            bus.observe(
                "service",
                "",
                producer=producer,
                source="network-profile-runtime/runs.jsonl",
                status=status,
                within_target=within_target,
                attributes={
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "service": "network-profile",
                    "target_input": basis,
                },
            )
            count += 1
    return count


def _sanitize_terminal_ledger(root: Path, target: str, run: Any) -> dict[str, int]:
    path = root / "network-profile-runtime" / "runs.jsonl"
    rows = network_device_runtime._jsonl(path)
    changed = 0
    quarantined = 0
    terminal_services = 0
    for row in rows:
        runner = str(row.get("runner", ""))
        if runner not in _VALIDATION_RUNNERS:
            continue
        target_input = str(row.get("host", "") or target)
        raw_services = row.get("services", []) if isinstance(row.get("services"), list) else []
        retained: list[dict[str, Any]] = []
        for service in raw_services:
            if not isinstance(service, dict):
                continue
            host = artifact_bus.canonical_host(str(service.get("host", "")))
            try:
                port = int(service.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            if not host or not 1 <= port <= 65535:
                continue
            if _endpoint_allowed(run, target_input, host, port):
                retained.append({**service, "target_input": target_input})
                terminal_services += 1
            else:
                quarantined += 1
        if retained != raw_services:
            changed += 1
            row["services"] = retained
            row["quarantined_services"] = int(row.get("quarantined_services", 0) or 0) + (len(raw_services) - len(retained))
    if changed:
        network_device_runtime._write_network_ledger(root, rows)
    return {"changed_rows": changed, "quarantined_services": quarantined, "terminal_services": terminal_services}


def _scoped_original_network(root: Path, target: str, profile: dict, **kwargs: Any) -> dict[str, Any]:
    if _RAW_NETWORK is None:
        raise RuntimeError("raw network adapter is unavailable")
    run = network_device_runtime._ACTIVE_RUN
    if run is None or not bool(kwargs.get("active")):
        return _RAW_NETWORK(root, target, profile, **kwargs)

    local_profile = dict(profile)
    local_kwargs = dict(kwargs)
    options = {
        key: dict(value) if isinstance(value, dict) else value
        for key, value in (kwargs.get("tool_options") or {}).items()
    }
    nmap_options = dict(options.get("nmap", {}))
    masscan_options = dict(options.get("masscan", {}))

    tcp_requested = nmap_options.get("ports", masscan_options.get("ports", local_profile.get("tcp_ports", "")))
    udp_requested = nmap_options.get("udp_ports", local_profile.get("udp_ports", ""))
    tcp_spec, tcp_error, tcp_constrained = _filter_ports(run, target, tcp_requested)
    udp_spec, udp_error, udp_constrained = _filter_ports(run, target, udp_requested) if local_profile.get("udp_enabled") else ("", "", False)
    error = tcp_error or udp_error
    if error:
        network_device_runtime._write_network_ledger(
            root,
            [{"runner": "network-profile", "status": "quarantined", "target": target, "reason": error, "services": []}],
        )
        return {"runs": 1, "statuses": {"quarantined": 1}, "services": 0, "reason": error}

    if tcp_constrained:
        local_profile["tcp_ports"] = tcp_spec
        nmap_options["ports"] = tcp_spec
        masscan_options["ports"] = tcp_spec
        # --top-ports would ignore the filtered explicit set.
        nmap_options.pop("top_ports", None)
    if udp_constrained:
        local_profile["udp_ports"] = udp_spec
        nmap_options["udp_ports"] = udp_spec
    if not tcp_spec and not (local_profile.get("udp_enabled") and udp_spec):
        reason = "no requested network ports remain inside the target boundary"
        network_device_runtime._write_network_ledger(
            root,
            [{"runner": "network-profile", "status": "quarantined", "target": target, "reason": reason, "services": []}],
        )
        return {"runs": 1, "statuses": {"quarantined": 1}, "services": 0, "reason": reason}

    options["nmap"] = nmap_options
    options["masscan"] = masscan_options
    local_kwargs["tool_options"] = options
    result = _RAW_NETWORK(root, target, local_profile, **local_kwargs)
    summary = _sanitize_terminal_ledger(root, target, run)
    result = dict(result)
    result["services"] = summary["terminal_services"]
    result["quarantined_services"] = summary["quarantined_services"]
    return result


def install(runtime_module: Any) -> Any:
    global _INSTALLED, _RAW_NETWORK, _ORIGINAL_INGEST
    if _INSTALLED or getattr(runtime_module, "_ah_puch_network_scope", False):
        return runtime_module
    if network_device_runtime._ORIGINAL_NETWORK is None:
        raise RuntimeError("network_device_runtime must be installed before network_scope_runtime")

    _RAW_NETWORK = network_device_runtime._ORIGINAL_NETWORK
    _ORIGINAL_INGEST = network_device_runtime.ingest_network_profile
    network_device_runtime._ORIGINAL_NETWORK = _scoped_original_network
    network_device_runtime.ingest_network_profile = _hardened_ingest_network_profile
    runtime_module._ah_puch_network_scope = True
    _INSTALLED = True
    return runtime_module
