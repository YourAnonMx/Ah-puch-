#!/usr/bin/env python3
"""SRC09 file-integrity and artifact-bus boundary hardening.

This layer adds no probing capability. It rejects symlinked device inputs and
resume artifacts, keeps normalized device-data imports on regular files,
requires concrete endpoint scope before a device service/fingerprint can become
promotable on the shared artifact bus, re-checks every promoted service again
immediately before downstream network/device dispatch, and prevents technology
enrichment from following redirects beyond its approved endpoint. It is
intentionally narrow and should be folded into the underlying device/file/bus
helpers once SRC09 parity is stable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from . import artifact_bus, device_contract_runtime, device_data, device_surface_v2, network_device_runtime, runner_v2
except ImportError:
    import artifact_bus
    import device_contract_runtime
    import device_data
    import device_surface_v2
    import network_device_runtime
    import runner_v2

_INSTALLED = False
_ORIGINAL_STATE_CANDIDATES = device_contract_runtime._state_candidates
_ORIGINAL_LOAD_RESUME = device_contract_runtime._load_resume
_ORIGINAL_CHECKPOINT = device_contract_runtime._checkpoint
_ORIGINAL_WRITE_SIDECAR = device_contract_runtime._write_sidecar
_ORIGINAL_LOAD_DEVICE_DATA = device_data.load_device_data
_ORIGINAL_IMPORT_DEVICE_DATA = device_data.import_device_data
_ORIGINAL_CANONICAL_NETWORK_INPUTS = network_device_runtime._canonical_network_inputs
_ORIGINAL_DEVICE_RUN_BOUNDED = device_surface_v2.run_bounded

_DEVICE_PROTOCOL_TRANSPORT = {
    "tcp": "tcp",
    "http": "tcp",
    "https": "tcp",
    "rtsp": "tcp",
    "rtsps": "tcp",
    "ssh": "tcp",
    "telnet": "tcp",
    "ftp": "tcp",
    "onvif": "tcp",
    "ws": "tcp",
    "wss": "tcp",
    "mqtt": "tcp",
    "mqtts": "tcp",
    "udp": "udp",
    "snmp": "udp",
    "coap": "udp",
    "bacnet": "udp",
}


def _sha256(path: Path) -> str:
    """Compatibility export for the canonical device checkpoint digest."""
    return device_contract_runtime._sha256(Path(path))


def _regular_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def _safe_state_candidates(path: Path) -> list[Path]:
    candidate = Path(path)
    if candidate.is_symlink():
        return []
    return [value for value in _ORIGINAL_STATE_CANDIDATES(candidate) if _regular_file(value)]


def _safe_resume(path: Path | None, expected: str):
    if path is None:
        return None, [], ""
    candidate_root = Path(path)
    if candidate_root.is_symlink():
        return None, [], "resume path is a symlink"
    for candidate in _safe_state_candidates(candidate_root):
        sidecar = device_contract_runtime._sidecar(candidate)
        if not _regular_file(sidecar):
            continue
        try:
            metadata = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(metadata, dict):
            continue
        inventory_name = str(metadata.get("inventory_file", "")).strip()
        if not inventory_name:
            continue
        inventory_path = sidecar.parent / inventory_name
        try:
            inventory_path.resolve().relative_to(sidecar.parent.resolve())
        except (OSError, ValueError):
            continue
        if not _regular_file(inventory_path):
            continue
        resolved, rows, status = _ORIGINAL_LOAD_RESUME(candidate, expected)
        if resolved is not None:
            return resolved, rows, status
    return None, [], "resume checkpoint requires regular non-symlink state, sidecar and inventory files"


def _safe_checkpoint(root: Path, target: str, result: dict[str, Any]) -> Path | None:
    candidate = _ORIGINAL_CHECKPOINT(root, target, result)
    return candidate if candidate is not None and _regular_file(candidate) else None


def _safe_write_sidecar(checkpoint: Path, contract_sha: str, material: dict[str, Any], inventory: list[dict[str, Any]]) -> None:
    candidate = Path(checkpoint)
    if not _regular_file(candidate):
        raise ValueError("device checkpoint must be a regular non-symlink file")
    sidecar = device_contract_runtime._sidecar(candidate)
    snapshot = device_contract_runtime._snapshot(candidate)
    if sidecar.is_symlink() or snapshot.is_symlink():
        raise ValueError("device resume sidecar/snapshot may not be a symlink")
    _ORIGINAL_WRITE_SIDECAR(candidate, contract_sha, material, inventory)


def _safe_load_device_data(path: Path | str) -> dict[str, Any]:
    candidate = Path(path)
    if not _regular_file(candidate):
        raise device_data.DeviceDataError("normalized device data must be a regular non-symlink file")
    return _ORIGINAL_LOAD_DEVICE_DATA(candidate)


def _safe_import_device_data(
    sources: Iterable[Path | str],
    destination: Path | str,
    *,
    provenance_label: str,
) -> dict[str, Any]:
    paths = [Path(source) for source in sources]
    if not paths or any(not _regular_file(path) for path in paths):
        raise device_data.DeviceDataError("device-data sources must be regular non-symlink files")
    target = Path(destination)
    if target.is_symlink():
        raise device_data.DeviceDataError("device-data destination may not be a symlink")
    return _ORIGINAL_IMPORT_DEVICE_DATA(paths, target, provenance_label=provenance_label)


def _device_run_bounded(command: list[str], *args: Any, **kwargs: Any):
    """Keep WhatWeb technology enrichment on its approved initial endpoint."""
    effective = list(command)
    if effective and Path(str(effective[0])).name.casefold() == "whatweb":
        if not any(str(value).startswith("--follow-redirect") for value in effective[1:]):
            effective.insert(1, "--follow-redirect=never")
        if not any(str(value).startswith("--max-redirects") for value in effective[1:]):
            effective.insert(2, "--max-redirects=0")
    return _ORIGINAL_DEVICE_RUN_BOUNDED(effective, *args, **kwargs)


def _bound_run(allow_network: Callable[[str], bool]) -> Any | None:
    run = getattr(allow_network, "__self__", None)
    return run if run is not None else network_device_runtime._ACTIVE_RUN


def _endpoint_context(allow_network: Callable[[str], bool]) -> tuple[Any | None, bool, Callable[[str, int, str, str], bool]]:
    run = _bound_run(allow_network)
    if run is None:
        return None, True, lambda host, port, protocol="tcp", service="": bool(allow_network(host))
    current = getattr(run, "_endpoint_allowed_current", None)
    if callable(current):
        checker = lambda host, port, protocol="tcp", service="": bool(current(host, port, service, protocol))
    else:
        endpoint = getattr(run, "_endpoint_allowed", None)
        checker = (
            (lambda host, port, protocol="tcp", service="": bool(endpoint(host, port, service, protocol)))
            if callable(endpoint)
            else (lambda host, port, protocol="tcp", service="": bool(allow_network(host)))
        )
    return run, True, checker


def ingest_device_inventory_endpoint_aware(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow_network: Callable[[str], bool],
) -> int:
    """Project device evidence while requiring concrete endpoint scope."""
    _run, policy_ok, checker = _endpoint_context(allow_network)
    count = 0
    paths = [
        path for path in root.rglob("device-inventory.jsonl")
        if "artifacts" not in path.parts and "inventory" not in path.parts and not path.is_symlink()
    ]
    for path in sorted(set(paths)):
        relative = str(path.relative_to(root))
        for row in network_device_runtime._jsonl(path):
            host = artifact_bus.canonical_host(str(row.get("host", "")))
            if not host:
                continue
            state = str(row.get("state", "unknown")).strip().lower() or "unknown"
            online = row.get("online") is True or state == "up"
            status = "verified" if online else ("observed-down" if state == "down" else "device-observed")
            host_within_target = bool(policy_ok and allow_network(host))

            try:
                port = int(row.get("port", 0) or 0)
            except (TypeError, ValueError):
                port = 0
            protocol = str(row.get("protocol", "tcp")).strip().lower() or "tcp"
            declared_transport = str(row.get("transport", "")).strip().lower()
            transport = declared_transport if declared_transport in {"tcp", "udp"} else _DEVICE_PROTOCOL_TRANSPORT.get(protocol, "")
            endpoint_within_target = bool(
                host_within_target
                and 1 <= port <= 65535
                and transport
                and checker(host, port, transport, protocol)
            )

            kind = "ip" if artifact_bus.canonical_ip(host) else "host"
            bus.observe(
                kind,
                host,
                producer="device-surface",
                source=relative,
                status=status,
                within_target=host_within_target,
                attributes={"device": True, "state": state},
            )
            if 1 <= port <= 65535 and transport:
                bus.observe(
                    "service",
                    "",
                    producer="device-surface",
                    source=relative,
                    status=status,
                    within_target=endpoint_within_target,
                    attributes={
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "transport": transport,
                        "service": "device-surface",
                        "state": state,
                        "target_boundary": "inside" if endpoint_within_target else "quarantined",
                    },
                )

            models = row.get("models", []) if isinstance(row.get("models"), list) else []
            vendors = row.get("vendors", []) if isinstance(row.get("vendors"), list) else []
            legacy_vendor = row.get("vendor")
            if legacy_vendor:
                vendors = [*vendors, legacy_vendor]
            for model in models:
                bus.observe(
                    "fingerprint",
                    str(model),
                    producer="device-surface",
                    source=relative,
                    status=status,
                    within_target=endpoint_within_target,
                    attributes={"namespace": "device-model", "host": host, "state": state},
                )
            for vendor in vendors:
                bus.observe(
                    "fingerprint",
                    str(vendor),
                    producer="device-surface",
                    source=relative,
                    status=status,
                    within_target=endpoint_within_target,
                    attributes={"namespace": "device-vendor", "host": host, "state": state},
                )
            technology_values: list[object] = []
            for key in ("technology", "technologies"):
                value = row.get(key)
                if isinstance(value, list):
                    technology_values.extend(value)
                elif value:
                    technology_values.append(value)
            for technology in technology_values:
                bus.observe(
                    "technology",
                    str(technology),
                    producer="device-surface",
                    source=relative,
                    status=status,
                    within_target=endpoint_within_target,
                    attributes={"host": host, "state": state},
                )
            count += 1
    return count


def filter_canonical_network_inputs(
    run: Any,
    hosts: list[str],
    services: dict[str, dict[str, set[int]]],
) -> tuple[list[str], dict[str, dict[str, set[int]]]]:
    """Re-check every promotable bus service at the immediate dispatch edge."""
    allow_network = getattr(run, "_network_allowed", getattr(run, "_allowed", lambda _value: False))
    _run, policy_ok, checker = _endpoint_context(allow_network)
    if not policy_ok:
        return [], {}
    safe_hosts = sorted({str(host) for host in hosts if host and allow_network(str(host))})
    filtered: dict[str, dict[str, set[int]]] = {}
    for host, protocols in services.items():
        for protocol in ("tcp", "udp"):
            for raw_port in protocols.get(protocol, set()):
                try:
                    port = int(raw_port)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535 and checker(str(host), port, protocol, ""):
                    filtered.setdefault(str(host), {"tcp": set(), "udp": set()})[protocol].add(port)
    return safe_hosts, filtered


def _canonical_network_inputs_endpoint_aware(run: Any) -> tuple[list[str], dict[str, dict[str, set[int]]]]:
    hosts, services = _ORIGINAL_CANONICAL_NETWORK_INPUTS(run)
    return filter_canonical_network_inputs(run, hosts, services)


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    device_contract_runtime._state_candidates = _safe_state_candidates
    device_contract_runtime._load_resume = _safe_resume
    device_contract_runtime._checkpoint = _safe_checkpoint
    device_contract_runtime._write_sidecar = _safe_write_sidecar

    device_data.load_device_data = _safe_load_device_data
    device_data.import_device_data = _safe_import_device_data
    device_surface_v2.load_device_data = _safe_load_device_data
    device_contract_runtime.load_device_data = _safe_load_device_data
    runner_v2.import_device_data = _safe_import_device_data
    device_surface_v2.run_bounded = _device_run_bounded

    network_device_runtime.ingest_device_inventory_status_aware = ingest_device_inventory_endpoint_aware
    network_device_runtime.artifact_bus.ingest_device_inventory = ingest_device_inventory_endpoint_aware
    artifact_bus.ingest_device_inventory = ingest_device_inventory_endpoint_aware
    network_device_runtime._canonical_network_inputs = _canonical_network_inputs_endpoint_aware
    _INSTALLED = True
