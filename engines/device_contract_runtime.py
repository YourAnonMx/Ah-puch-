#!/usr/bin/env python3
"""SRC09 exact-endpoint and resumable-device contract guard.

The existing device engines remain the only scanners/probers. This layer wraps
those engines with one canonical contract: concrete endpoint scope at every
network edge, one policy refresh per execution boundary, strong resume identity,
verified inventory carry-forward, and quarantine of evidence that cannot be
promoted under the current target boundary.
"""
from __future__ import annotations

import contextvars
import hashlib
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    from . import camera_surface, device_surface_v2, network_device_runtime
    from .device_data import load_device_data, service_ports
except ImportError:
    import camera_surface
    import device_surface_v2
    import network_device_runtime
    from device_data import load_device_data, service_ports

_CURRENT_RUN: contextvars.ContextVar[Any | None] = contextvars.ContextVar("ah_puch_device_run", default=None)
_INSTALLED = False
_ORIGINAL_RUNTIME_DEVICE: Any | None = None
_ORIGINAL_CAMERA_ANALYZE = camera_surface.analyze
_ORIGINAL_DISCOVER = device_surface_v2._discover_network_services
_ORIGINAL_NMAP_DISCOVER = device_surface_v2._nmap_discover
_ORIGINAL_PROBE = device_surface_v2._probe_with_retries


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _current_endpoint_checker(run: Any | None) -> Callable[[str, int, str, str], bool]:
    """Return a no-I/O checker for the automatic target boundary."""
    if run is None:
        return lambda _host, _port, _protocol="tcp", _service="": True
    current = getattr(run, "_endpoint_allowed_current", None)
    if callable(current):
        return lambda host, port, protocol="tcp", service="": bool(current(host, port, service, protocol))
    endpoint = getattr(run, "_endpoint_allowed", None)
    if callable(endpoint):
        return lambda host, port, protocol="tcp", service="": bool(endpoint(host, port, service, protocol))
    allow_network = getattr(run, "_network_allowed", getattr(run, "_allowed", lambda _value: False))
    return lambda host, port, protocol="tcp", service="": bool(
        1 <= int(port) <= 65535 and str(protocol).lower() in {"tcp", "udp"} and allow_network(str(host))
    )


def _endpoint_allowed(run: Any | None, host: str, port: int, protocol: str = "tcp", service: str = "") -> bool:
    return _current_endpoint_checker(run)(str(host), int(port), protocol, service)


def _url_allowed_current(
    run: Any | None,
    value: str,
    checker: Callable[[str, int, str, str], bool],
) -> bool:
    if run is None:
        return True
    try:
        parsed = urlsplit(str(value))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return bool(run._allowed(str(value)) and checker(parsed.hostname, port, "tcp", "http"))


def _url_allowed(run: Any | None, value: str) -> bool:
    return _url_allowed_current(run, value, _current_endpoint_checker(run))


def _parse_endpoint(value: str) -> tuple[str, int, str] | None:
    try:
        parsed = urlsplit(str(value))
    except ValueError:
        return None
    if not parsed.scheme or not parsed.hostname or parsed.port is None:
        return None
    protocol = "udp" if parsed.scheme.lower() == "udp" else "tcp"
    return parsed.hostname, int(parsed.port), protocol


def _effective_scan_ports(run: Any | None, target: str, ports: set[int]) -> set[int]:
    if run is None:
        return set(ports)
    if camera_surface.is_network_target(target):
        return set(ports) if str(target).strip() == str(getattr(run, "target", "")).strip() else set()
    host = camera_surface.target_host(target)
    checker = _current_endpoint_checker(run)
    return {port for port in ports if checker(host, port, "tcp", "")}


def _guarded_discover(target: str, ports: set[int], **kwargs: Any):
    run = _CURRENT_RUN.get()
    effective = _effective_scan_ports(run, target, set(ports))
    if not effective:
        return {}, {
            "runner": "device-range",
            "status": "gated",
            "reason": "target boundary rejects every requested device port",
            "target_hosts": 0,
            "network": target,
            "probe_count": 0,
        }
    services, evidence = _ORIGINAL_DISCOVER(target, effective, **kwargs)
    if run is None:
        return services, evidence
    checker = _current_endpoint_checker(run)
    filtered: dict[str, set[int]] = {}
    quarantined = 0
    for host, found in services.items():
        accepted = {port for port in found if checker(str(host), int(port), "tcp", "")}
        quarantined += len(set(found) - accepted)
        if accepted:
            filtered[str(host)] = accepted
    evidence = dict(evidence)
    evidence["target_boundary_ports"] = len(effective)
    evidence["quarantined_ports"] = quarantined
    evidence["target_hosts"] = len(filtered)
    return filtered, evidence


def _guarded_nmap_discover(host: str, ports: set[int], timeout: int, destination: Path) -> set[int]:
    run = _CURRENT_RUN.get()
    checker = _current_endpoint_checker(run)
    effective = {port for port in ports if checker(host, int(port), "tcp", "")}
    if not effective:
        return set()
    observed = _ORIGINAL_NMAP_DISCOVER(host, effective, timeout, destination)
    checker = _current_endpoint_checker(run)
    return {port for port in observed if checker(host, int(port), "tcp", "")}


def _guarded_probe(host: str, port: int, **kwargs: Any) -> dict[str, Any]:
    run = _CURRENT_RUN.get()
    if not _current_endpoint_checker(run)(host, int(port), "tcp", ""):
        return {
            "host": host,
            "port": int(port),
            "open": False,
            "state": "quarantined",
            "error": "endpoint outside the current target boundary",
            "attempts": 0,
        }
    return _ORIGINAL_PROBE(host, int(port), **kwargs)


def _rewrite_camera_projection(run_root: Path, target: str, result: dict[str, Any]) -> None:
    """Rewrite executable camera queues/state to the filtered projection."""
    target_slug = camera_surface.slug(target)
    destination = run_root / "09-camera-surfaces"
    endpoints = sorted({str(value) for value in result.get("endpoints", []) if value})
    urls = sorted({str(value) for value in result.get("urls", []) if value})
    hosts = sorted({str(value) for value in result.get("hosts", []) if value})
    endpoint_text = "\n".join(endpoints) + ("\n" if endpoints else "")
    url_text = "\n".join(urls) + ("\n" if urls else "")
    camera_surface.write_text(destination / f"{target_slug}.camera-candidates.txt", endpoint_text)
    camera_surface.write_text(run_root / "queues" / f"{target_slug}.camera.candidates.txt", endpoint_text)
    camera_surface.write_text(run_root / "queues" / f"{target_slug}.camera.urls.txt", url_text)

    for name in (f"{target_slug}.camera-summary.json", f"{target_slug}.camera-state.json"):
        path = destination / name
        try:
            payload = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except (OSError, json.JSONDecodeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        payload["target"] = target
        payload["hosts"] = hosts
        payload["endpoints"] = endpoints
        if name.endswith("camera-summary.json"):
            payload["urls"] = urls
        camera_surface.write_json(path, payload)


def _guarded_camera_analyze(
    run_root: Path,
    target: str,
    active: bool,
    timeout: int,
    max_hosts: int = 24,
    **kwargs: Any,
) -> dict[str, Any]:
    """Keep the legacy extractor passive inside the canonical device runtime."""
    run = _CURRENT_RUN.get()
    local = {"active": active, "timeout": timeout, "max_hosts": max_hosts, **kwargs}
    requested_active = bool(local.get("active"))
    if run is not None and requested_active:
        # Active device contact belongs to device_surface_v2, where exact port
        # scope is enforced. The legacy extractor remains evidence-only.
        local["active"] = False
    result = _ORIGINAL_CAMERA_ANALYZE(run_root, target, **local)
    if run is None:
        return result
    checker = _current_endpoint_checker(run)
    endpoints: list[str] = []
    for value in result.get("endpoints", []):
        parsed = _parse_endpoint(str(value))
        if parsed and checker(parsed[0], parsed[1], parsed[2], ""):
            endpoints.append(str(value))
    urls = [str(value) for value in result.get("urls", []) if _url_allowed_current(run, str(value), checker)]
    hosts = [
        str(value)
        for value in result.get("hosts", [])
        if getattr(run, "_network_allowed", run._allowed)(str(value))
    ]
    filtered = dict(result)
    filtered["endpoints"] = sorted(set(endpoints))
    filtered["urls"] = sorted(set(urls))
    filtered["hosts"] = list(dict.fromkeys(hosts))
    summary = dict(filtered.get("summary", {}))
    summary["src09_active_downgraded"] = requested_active
    filtered["summary"] = summary
    _rewrite_camera_projection(run_root, target, filtered)
    return filtered


def _device_data_digest(path: Path | None) -> str:
    if path is None or not path.is_file():
        return ""
    return _sha256(path)


def _configured_ports(profile: str, custom: str, device_data_path: Path | None) -> list[int]:
    ports = set(camera_surface.ports_for_profile(profile, custom))
    if device_data_path is not None:
        artifact = load_device_data(device_data_path)
        ports.update(service_ports(artifact))
    return sorted(ports)


def _contract(target: str, kwargs: dict[str, Any], run: Any | None) -> tuple[str, dict[str, Any]]:
    data_path = kwargs.get("device_data_path")
    if data_path is not None and not isinstance(data_path, Path):
        data_path = Path(data_path)
    ports = _configured_ports(
        str(kwargs.get("port_profile", "quick")),
        str(kwargs.get("custom_ports", "")),
        data_path,
    )
    material = {
        "target": str(target),
        "target_boundary": "automatic",
        "active": bool(kwargs.get("active")),
        "port_profile": str(kwargs.get("port_profile", "quick")),
        "custom_ports": str(kwargs.get("custom_ports", "")),
        "configured_ports": ports,
        "model_filter": str(kwargs.get("model_filter", "")),
        "vendor_filter": str(kwargs.get("vendor_filter", "")),
        "probe_mode": str(kwargs.get("probe_mode", "all")),
        "technology_enrichment": bool(kwargs.get("technology_enrichment", True)),
        "connect_timeout": kwargs.get("connect_timeout"),
        "session_timeout": int(kwargs.get("session_timeout", 900)),
        "retries": int(kwargs.get("retries", 1)),
        "scan_rate": int(kwargs.get("scan_rate", 500)),
        "export_mode": str(kwargs.get("export_mode", "redacted")),
        "max_hosts": int(kwargs.get("max_hosts", 24)),
        "chunk_prefix": int(kwargs.get("chunk_prefix", 0)),
        "device_data_sha256": _device_data_digest(data_path),
    }
    raw = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest(), material


def _sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".src09-contract.json")


def _snapshot(path: Path) -> Path:
    return path.with_name(path.name + ".src09-inventory.jsonl")


def _state_candidates(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        return []
    values = list(path.rglob("*.device-network-state.json")) + list(path.rglob("*.device-state.json"))
    try:
        return sorted(set(values), key=lambda value: (value.stat().st_mtime_ns, str(value)), reverse=True)
    except OSError:
        return sorted(set(values), reverse=True)


def _load_resume(path: Path | None, expected: str) -> tuple[Path | None, list[dict[str, Any]], str]:
    if path is None:
        return None, [], ""
    for candidate in _state_candidates(path):
        sidecar = _sidecar(candidate)
        try:
            row = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if str(row.get("contract_sha256", "")) != expected:
            continue
        checkpoint_digest = str(row.get("checkpoint_sha256", "")).strip()
        if not checkpoint_digest:
            continue
        try:
            if _sha256(candidate) != checkpoint_digest:
                continue
        except OSError:
            continue
        inventory_name = str(row.get("inventory_file", "")).strip()
        digest = str(row.get("inventory_sha256", "")).strip()
        if not inventory_name or not digest:
            continue
        inventory_path = sidecar.parent / inventory_name
        try:
            inventory_path.resolve().relative_to(sidecar.parent.resolve())
        except (OSError, ValueError):
            continue
        if not inventory_path.is_file() or _sha256(inventory_path) != digest:
            continue
        rows: list[dict[str, Any]] = []
        for line in inventory_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return candidate, rows, "verified"
    return None, [], "resume checkpoint lacks a matching SRC09 contract/checkpoint/inventory seal"


def _row_allowed_current(
    run: Any | None,
    row: dict[str, Any],
    checker: Callable[[str, int, str, str], bool],
) -> bool:
    host = str(row.get("host", "")).strip()
    try:
        port = int(row.get("port", 0))
    except (TypeError, ValueError):
        return False
    protocol = str(row.get("protocol", "tcp")).strip().lower() or "tcp"
    return bool(host and checker(host, port, protocol, ""))


def _row_allowed(run: Any | None, row: dict[str, Any]) -> bool:
    return _row_allowed_current(run, row, _current_endpoint_checker(run))


def _inventory_key(row: dict[str, Any]) -> tuple[str, int, str]:
    try:
        port = int(row.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    return str(row.get("host", "")), port, str(row.get("protocol", "tcp"))


def _write_inventory_files(root: Path, rows: list[dict[str, Any]], quarantined: list[dict[str, Any]]) -> None:
    destination = root / "09-camera-surfaces"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    selected = [row for row in rows if row.get("selected", True)]
    groups = (
        ("device-inventory.jsonl", selected),
        ("device-identified.jsonl", [row for row in selected if row.get("identified")]),
        ("device-unknown.jsonl", [row for row in selected if not row.get("identified")]),
        ("device-quarantined-endpoints.jsonl", quarantined),
    )
    for name, values in groups:
        path = destination / name
        path.write_text(
            "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in values),
            encoding="utf-8",
        )
        path.chmod(0o600)


def _checkpoint(root: Path, target: str, result: dict[str, Any]) -> Path | None:
    value = str(result.get("checkpoint", "")).strip()
    summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
    if not value:
        value = str(summary.get("device_checkpoint", "")).strip()
    if value:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / candidate
        if candidate.is_file():
            return candidate
    destination = root / "09-camera-surfaces"
    candidates = list(destination.glob(f"{camera_surface.slug(target)}.device-network-state.json"))
    candidates += list(destination.glob(f"{camera_surface.slug(target)}.device-state.json"))
    return candidates[0] if len(candidates) == 1 else None


def _write_sidecar(checkpoint: Path, contract_sha: str, material: dict[str, Any], inventory: list[dict[str, Any]]) -> None:
    snapshot = _snapshot(checkpoint)
    snapshot.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in inventory),
        encoding="utf-8",
    )
    snapshot.chmod(0o600)
    sidecar = _sidecar(checkpoint)
    sidecar.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "contract_sha256": contract_sha,
                "contract": material,
                "checkpoint_sha256": _sha256(checkpoint),
                "inventory_file": snapshot.name,
                "inventory_sha256": _sha256(snapshot),
                "inventory_count": len(inventory),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    sidecar.chmod(0o600)


def _filter_result(root: Path, target: str, result: dict[str, Any], prior: list[dict[str, Any]], run: Any | None) -> dict[str, Any]:
    current = [row for row in result.get("inventory", []) if isinstance(row, dict)]
    combined: dict[tuple[str, int, str], dict[str, Any]] = {}
    quarantined: list[dict[str, Any]] = []
    checker = _current_endpoint_checker(run)
    for row in [*prior, *current]:
        if _row_allowed_current(run, row, checker):
            combined[_inventory_key(row)] = dict(row)
        else:
            quarantined.append({**row, "quarantine_reason": "endpoint outside the current target boundary"})
    rows = sorted(combined.values(), key=_inventory_key)
    _write_inventory_files(root, rows, quarantined)

    hosts = {
        str(value)
        for value in result.get("hosts", [])
        if value and (run is None or getattr(run, "_network_allowed", run._allowed)(str(value)))
    }
    hosts.update(str(row.get("host", "")) for row in rows if row.get("host"))
    endpoints = {
        camera_surface.normalize_endpoint(str(row["host"]), int(row["port"]), str(row.get("protocol", "tcp")))
        for row in rows
        if row.get("host") and row.get("port") and row.get("online")
    }
    urls = {
        str(value)
        for value in result.get("urls", [])
        if value and _url_allowed_current(run, str(value), checker)
    }
    for row in rows:
        evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
        value = str(evidence.get("url", ""))
        if value and _url_allowed_current(run, value, checker):
            urls.add(value)

    summary = dict(result.get("summary", {})) if isinstance(result.get("summary"), dict) else {}
    summary["device_inventory"] = len(rows)
    summary["device_identified"] = sum(1 for row in rows if row.get("identified"))
    summary["device_unknown"] = sum(1 for row in rows if not row.get("identified"))
    summary["device_target_quarantined_endpoints"] = len(quarantined)
    summary["device_resume_inventory_imported"] = len(prior)
    if quarantined and not rows:
        summary["device_target_boundary_status"] = "gated"
        summary["device_scan_complete"] = False
        # runtime.run_camera_surface uses this field as its terminal reducer.
        summary["device_network_complete"] = False
    elif quarantined:
        summary["device_target_boundary_status"] = "filtered"
    else:
        summary["device_target_boundary_status"] = "ok"

    filtered = dict(result)
    filtered["inventory"] = rows
    filtered["hosts"] = sorted(hosts)
    filtered["endpoints"] = sorted(endpoints)
    filtered["urls"] = sorted(urls)
    filtered["summary"] = summary
    return filtered


def _gated_result(target: str, reason: str) -> dict[str, Any]:
    return {
        "summary": {
            "device_target_boundary_status": "gated",
            "device_scan_complete": False,
            "device_network_complete": False,
            "device_inventory": 0,
            "device_identified": 0,
            "device_unknown": 0,
            "device_target_boundary_reason": reason,
        },
        "urls": [],
        "hosts": [],
        "endpoints": [],
        "inventory": [],
        "target": target,
    }


def install(runtime_module: Any) -> Any:
    """Install the SRC09 device contract exactly once over the composed adapter."""
    global _INSTALLED, _ORIGINAL_RUNTIME_DEVICE
    if _INSTALLED or getattr(runtime_module, "_ah_puch_device_contract", False):
        return runtime_module

    _ORIGINAL_RUNTIME_DEVICE = runtime_module.analyze_device_runtime
    camera_surface.analyze = _guarded_camera_analyze
    device_surface_v2._discover_network_services = _guarded_discover
    device_surface_v2._nmap_discover = _guarded_nmap_discover
    device_surface_v2._probe_with_retries = _guarded_probe

    def analyze_device_runtime(root: Path, target: str, **kwargs: Any) -> dict[str, Any]:
        run = network_device_runtime._ACTIVE_RUN
        contract_sha, material = _contract(target, kwargs, run)
        requested_resume = kwargs.get("resume_state")
        resume_path = Path(requested_resume) if requested_resume is not None else None
        resolved_resume, prior_inventory, resume_status = _load_resume(resume_path, contract_sha)
        local = dict(kwargs)
        if requested_resume is not None:
            local["resume_state"] = resolved_resume
            if run is not None:
                run.event(
                    {
                        "engine": "device_resume_contract",
                        "status": "verified" if resolved_resume else "rejected",
                        "reason": resume_status,
                        "requested": str(requested_resume),
                        "resolved": str(resolved_resume or ""),
                        "probe_count": 0,
                    }
                )

        token = _CURRENT_RUN.set(run)
        try:
            result = _ORIGINAL_RUNTIME_DEVICE(root, target, **local)
        finally:
            _CURRENT_RUN.reset(token)

        filtered = _filter_result(root, target, result, prior_inventory, run)
        checkpoint = _checkpoint(root, target, filtered)
        if checkpoint is not None:
            _write_sidecar(checkpoint, contract_sha, material, filtered.get("inventory", []))
            summary = dict(filtered.get("summary", {}))
            summary["device_src09_contract"] = str(_sidecar(checkpoint).relative_to(root))
            summary["device_src09_contract_sha256"] = contract_sha
            filtered["summary"] = summary
        return filtered

    runtime_module.analyze_device_runtime = analyze_device_runtime
    runtime_module._ah_puch_device_contract = True
    _INSTALLED = True
    return runtime_module
