#!/usr/bin/env python3
"""Phase-6 network/device handoff and terminal-evidence integration.

This layer is intentionally orchestration-only: it does not add new probing
capabilities. It constrains the existing network/device adapters to canonical,
within_target artifact-bus inputs and projects only terminal observations back to
the shared bus. Repository tests remain loopback/reserved/synthetic.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    from . import artifact_bus, device_runtime, network_runtime
except ImportError:
    import artifact_bus
    import device_runtime
    import network_runtime

_INSTALLED = False
_ACTIVE_RUN: Any | None = None
_ORIGINAL_SYNC = artifact_bus.sync_sources
_ORIGINAL_NETWORK: Callable[..., dict[str, Any]] | None = None
_ORIGINAL_DEVICE: Callable[..., dict[str, Any]] | None = None
_COMPLETED = frozenset({"success", "partial"})


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _promotable_observation(observation: object) -> bool:
    return bool(
        isinstance(observation, dict)
        and observation.get("within_target")
        and observation.get("observed")
        and str(observation.get("status", "")) in artifact_bus.PROMOTABLE_STATUSES
    )


def ingest_network_profile(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow_network: Callable[[str], bool],
) -> int:
    """Project only terminal service observations recorded by network_runtime."""
    path = root / "network-profile-runtime" / "runs.jsonl"
    count = 0
    for row in _jsonl(path):
        status = str(row.get("status", "unknown")).strip().lower() or "unknown"
        runner = str(row.get("runner", "network-profile")).strip() or "network-profile"
        services = row.get("services", []) if isinstance(row.get("services"), list) else []
        if status not in _COMPLETED:
            continue
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
                attributes={"network_observation": True},
            )
            bus.observe(
                "service",
                "",
                producer=producer,
                source="network-profile-runtime/runs.jsonl",
                status=status,
                within_target=within_target,
                attributes={"host": host, "port": port, "protocol": protocol, "service": "network-profile"},
            )
            count += 1
    return count


def ingest_device_inventory_status_aware(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow_network: Callable[[str], bool],
) -> int:
    """Keep down/unknown device rows as provenance without positive promotion."""
    count = 0
    paths = [
        path for path in root.rglob("device-inventory.jsonl")
        if "artifacts" not in path.parts and "inventory" not in path.parts
    ]
    for path in sorted(set(paths)):
        relative = str(path.relative_to(root))
        for row in _jsonl(path):
            host = artifact_bus.canonical_host(str(row.get("host", "")))
            if not host:
                continue
            state = str(row.get("state", "unknown")).strip().lower() or "unknown"
            online = row.get("online") is True or state == "up"
            status = "verified" if online else ("observed-down" if state == "down" else "device-observed")
            within_target = bool(allow_network(host))
            kind = "ip" if artifact_bus.canonical_ip(host) else "host"
            bus.observe(
                kind,
                host,
                producer="device-surface",
                source=relative,
                status=status,
                within_target=within_target,
                attributes={"device": True, "state": state},
            )
            port = row.get("port")
            if port:
                bus.observe(
                    "service",
                    "",
                    producer="device-surface",
                    source=relative,
                    status=status,
                    within_target=within_target,
                    attributes={
                        "host": host,
                        "port": port,
                        "protocol": row.get("protocol", "tcp"),
                        "service": "device-surface",
                        "state": state,
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
                    within_target=within_target,
                    attributes={"namespace": "device-model", "host": host, "state": state},
                )
            for vendor in vendors:
                bus.observe(
                    "fingerprint",
                    str(vendor),
                    producer="device-surface",
                    source=relative,
                    status=status,
                    within_target=within_target,
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
                    within_target=within_target,
                    attributes={"host": host, "state": state},
                )
            count += 1
    return count


def _sync_sources_with_network(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    graph: Any,
    allow: Callable[[str], bool],
    allow_network: Callable[[str], bool] | None = None,
) -> dict[str, int]:
    network_allow = allow_network or allow
    counts = _ORIGINAL_SYNC(bus, root, graph, allow, network_allow)
    counts["network"] = ingest_network_profile(bus, root, network_allow)
    return counts


def _canonical_network_inputs(run: Any) -> tuple[list[str], dict[str, dict[str, set[int]]]]:
    """Read target-eligible host/IP/service values from the common bus."""
    bus = artifact_bus.ArtifactBus(run.root, run.target)
    artifact_bus.ingest_graph(bus, getattr(run, "graph", None))
    ingest_network_profile(bus, run.root, getattr(run, "_network_allowed", run._allowed))
    bus.save()
    allow_network = getattr(run, "_network_allowed", run._allowed)
    hosts = {
        str(row["value"])
        for kind in ("host", "ip")
        for row in bus.records(kind, promotable_only=True)
        if allow_network(str(row["value"]))
    }
    services: dict[str, dict[str, set[int]]] = {}
    for row in bus.records("service", promotable_only=True):
        for observation in row.get("observations", []):
            if not _promotable_observation(observation):
                continue
            attributes = observation.get("attributes", {})
            if not isinstance(attributes, dict):
                continue
            host = artifact_bus.canonical_host(str(attributes.get("host", "")))
            protocol = str(attributes.get("protocol", "tcp")).strip().lower() or "tcp"
            try:
                port = int(attributes.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            if not host or protocol not in {"tcp", "udp"} or not (1 <= port <= 65535):
                continue
            if not allow_network(host):
                continue
            hosts.add(host)
            services.setdefault(host, {"tcp": set(), "udp": set()})[protocol].add(port)
    return sorted(hosts), services


def _write_network_ledger(root: Path, rows: list[dict[str, Any]]) -> None:
    path = root / "network-profile-runtime" / "runs.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    path.chmod(0o600)


def _network_from_bus(root: Path, target: str, profile: dict, **kwargs: Any) -> dict[str, Any]:
    if _ORIGINAL_NETWORK is None:
        raise RuntimeError("network adapter not installed")
    run = _ACTIVE_RUN
    active = bool(kwargs.get("active"))
    if run is None or not active:
        return _ORIGINAL_NETWORK(root, target, profile, **kwargs)

    # A CIDR supplied by the operator is the bounded discovery container. Its
    # discovered services must still pass allow_target before becoming bus rows.
    if network_runtime._target_kind(target) == "cidr":
        result = _ORIGINAL_NETWORK(root, target, profile, **kwargs)
    else:
        hosts, services = _canonical_network_inputs(run)
        limit = max(1, int(kwargs.get("host_limit", 1)))
        rows: list[dict[str, Any]] = []
        for host in hosts[:limit]:
            local_profile = dict(profile)
            tcp_ports = sorted(services.get(host, {}).get("tcp", set()))
            udp_ports = sorted(services.get(host, {}).get("udp", set()))
            if tcp_ports:
                local_profile["tcp_ports"] = ",".join(str(value) for value in tcp_ports)
            if udp_ports and local_profile.get("udp_enabled"):
                local_profile["udp_ports"] = ",".join(str(value) for value in udp_ports)
            local_kwargs = dict(kwargs)
            local_kwargs["host_limit"] = 1
            _ORIGINAL_NETWORK(root, host, local_profile, **local_kwargs)
            rows.extend(_jsonl(root / "network-profile-runtime" / "runs.jsonl"))
        if not rows:
            rows = [{
                "runner": "network-profile",
                "status": "skipped",
                "reason": "no promotable target network artifact inputs",
                "services": [],
            }]
        _write_network_ledger(root, rows)
        counts: dict[str, int] = {}
        service_count = 0
        for row in rows:
            status = str(row.get("status", "unknown"))
            counts[status] = counts.get(status, 0) + 1
            if status in _COMPLETED and isinstance(row.get("services"), list):
                service_count += len(row["services"])
        result = {"runs": len(rows), "statuses": counts, "services": service_count, "canonical_input_hosts": len(hosts)}

    bus = artifact_bus.ArtifactBus(root, target)
    ingest_network_profile(bus, root, getattr(run, "_network_allowed", run._allowed))
    bus.save()
    return result


def _merge_device_results(root: Path, target: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    inventory: list[dict[str, Any]] = []
    hosts: set[str] = set()
    urls: set[str] = set()
    endpoints: set[str] = set()
    complete = True
    for result in results:
        inventory.extend(row for row in result.get("inventory", []) if isinstance(row, dict))
        hosts.update(str(value) for value in result.get("hosts", []) if value)
        urls.update(str(value) for value in result.get("urls", []) if value)
        endpoints.update(str(value) for value in result.get("endpoints", []) if value)
        summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
        if summary.get("device_scan_complete") is False or summary.get("device_network_complete") is False:
            complete = False
    device_runtime._rewrite_inventory(root, inventory)
    identified = sum(1 for row in inventory if row.get("identified"))
    return {
        "target": target,
        "hosts": sorted(hosts),
        "urls": sorted(urls),
        "endpoints": sorted(endpoints),
        "inventory": inventory,
        "summary": {
            "device_input_mode": "artifact-bus-services",
            "device_inventory": len(inventory),
            "identified": identified,
            "unknown": len(inventory) - identified,
            "device_network_complete": complete,
            "device_scan_complete": complete,
            "canonical_hosts": len(hosts),
        },
    }


def _device_from_bus(root: Path, target: str, **kwargs: Any) -> dict[str, Any]:
    if _ORIGINAL_DEVICE is None:
        raise RuntimeError("device adapter not installed")
    run = _ACTIVE_RUN
    if run is None:
        return _ORIGINAL_DEVICE(root, target, **kwargs)
    # Resume owns its validated checkpoint contract. The underlying device
    # runtime still re-checks every resumed/discovered host through allow_target.
    if kwargs.get("resume_state") is not None:
        return _ORIGINAL_DEVICE(root, target, **kwargs)

    hosts, services = _canonical_network_inputs(run)
    target_kind = network_runtime._target_kind(target)
    if target_kind == "cidr" and services:
        selected = [host for host in hosts if services.get(host)][: max(1, int(kwargs.get("max_hosts", 1)))]
    elif target_kind != "cidr":
        exact = artifact_bus.canonical_host(network_runtime._host_value(target))
        selected = [host for host in hosts if host == exact]
    else:
        selected = []
    if not selected:
        return _ORIGINAL_DEVICE(root, target, **kwargs)

    results: list[dict[str, Any]] = []
    for host in selected:
        local = dict(kwargs)
        tcp_ports = sorted(services.get(host, {}).get("tcp", set()))
        if tcp_ports:
            local["port_profile"] = "custom"
            local["custom_ports"] = ",".join(str(value) for value in tcp_ports)
        local["max_hosts"] = 1
        results.append(_ORIGINAL_DEVICE(root, host, **local))
    return _merge_device_results(root, target, results)


def _filter_followup_candidates(run: Any) -> int:
    """Re-check industrial follow-up candidates immediately before dispatch."""
    path = run.core_root / "09-ics" / f"{run.v2.base.slug(run.target) if hasattr(run, 'v2') else ''}.ics-candidates.txt"
    if not path.is_file():
        # The base slug helper is available through the class module rather than
        # the instance. Find the single canonical candidate file if present.
        matches = sorted((run.core_root / "09-ics").glob("*.ics-candidates.txt")) if (run.core_root / "09-ics").is_dir() else []
        path = matches[0] if len(matches) == 1 else path
    if not path.is_file() or path.is_symlink():
        return 0
    try:
        values = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        return 0
    allow_network = getattr(run, "_network_allowed", run._allowed)
    kept: list[str] = []
    for value in values:
        if value.startswith(("http://", "https://")):
            allowed = bool(run._allowed(value))
        else:
            host = urlsplit(value).hostname if "://" in value else value
            allowed = bool(host and allow_network(host))
        if allowed:
            kept.append(value)
    path.write_text("\n".join(sorted(set(kept))) + ("\n" if kept else ""), encoding="utf-8")
    path.chmod(0o600)
    return len(values) - len(set(kept))


def _followup_value_allowed(run: Any, value: str) -> bool:
    """Evaluate the current target boundary for one industrial follow-up input."""
    allow_network = getattr(run, "_network_allowed", run._allowed)
    if value.startswith(("http://", "https://")):
        return bool(run._allowed(value))
    host = urlsplit(value).hostname if "://" in value else value
    return bool(host and allow_network(host))


def install(runtime_module: Any) -> Any:
    global _INSTALLED, _ORIGINAL_NETWORK, _ORIGINAL_DEVICE
    if _INSTALLED or getattr(runtime_module, "_ah_puch_network_device", False):
        return runtime_module

    _ORIGINAL_NETWORK = runtime_module.run_network_profile
    _ORIGINAL_DEVICE = runtime_module.analyze_device_runtime
    artifact_bus.ingest_device_inventory = ingest_device_inventory_status_aware
    if getattr(_ORIGINAL_SYNC, "_ah_puch_src01_projection", False):
        _sync_sources_with_network._ah_puch_src01_projection = True  # type: ignore[attr-defined]
    artifact_bus.sync_sources = _sync_sources_with_network
    runtime_module.run_network_profile = _network_from_bus
    runtime_module.analyze_device_runtime = _device_from_bus

    # Preserve exact timeout rather than reducing an all-timeout enabled stage
    # to generic failure. All other no-work/unavailable/gated states stay non-success.
    original_aggregate = runtime_module._aggregate_status

    def aggregate_status(counts: dict[str, int], *, enabled: bool, disabled_status: str = "skipped") -> str:
        if enabled and counts.get("timeout", 0) and not counts.get("success", 0) and not counts.get("partial", 0):
            return "timeout"
        return original_aggregate(counts, enabled=enabled, disabled_status=disabled_status)

    runtime_module._aggregate_status = aggregate_status

    base = runtime_module.v2.base
    current = base.UnifiedRun

    class NetworkDeviceUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_network_device = True

        def run_native(self) -> None:
            global _ACTIVE_RUN
            previous = _ACTIVE_RUN
            _ACTIVE_RUN = self
            try:
                super().run_native()
            finally:
                _ACTIVE_RUN = previous

        def run_camera_surface(self) -> None:
            global _ACTIVE_RUN
            previous = _ACTIVE_RUN
            _ACTIVE_RUN = self
            try:
                super().run_camera_surface()
            finally:
                _ACTIVE_RUN = previous

        def dispatch_followups(self) -> None:
            dropped = _filter_followup_candidates(self)
            if dropped:
                self.event({
                    "engine": "industrial_followup_boundary",
                    "status": "success",
                    "dropped_unapproved_candidates": dropped,
                    "probe_count": 0,
                })
            if self.args.dry_run:
                self.event({"engine": "follow_up", "status": "planned", "reason": "--dry-run"})
                return
            if not self.args.follow_up or self.args.follow_up_rounds < 1:
                self.event({"engine": "follow_up", "status": "skipped", "reason": "follow-up disabled"})
                return

            camera_file = self.queue_root / f"{base.slug(self.target)}.camera.candidates.txt"
            ics_file = self.core_root / "09-ics" / f"{base.slug(self.target)}.ics-candidates.txt"
            camera_values = [
                line.strip()
                for line in camera_file.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip()
            ] if camera_file.is_file() else []
            ics_values = [
                line.strip()
                for line in ics_file.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip()
            ] if ics_file.is_file() else []
            modules = {str(item.get("name")): item for item in base.load_modules()}
            camera_names = (
                "Server Info", "HTTP Headers", "HTTP/2 and HTTP/3 Support Checker", "TLS Security Configuration",
            )
            ics_names = ("Open Ports Scan", "Server Info", "UDP Service Sampler", "IP Info")
            plan = self.root / "queues" / f"{base.slug(self.target)}.follow-up-plan.jsonl"
            plan.parent.mkdir(parents=True, exist_ok=True)
            rounds = max(1, min(self.args.follow_up_rounds, 3))
            dispatched = 0
            revoked_before_dispatch = 0
            with plan.open("w", encoding="utf-8") as handle:
                for round_number in range(1, rounds + 1):
                    if round_number > 1 and not (camera_values or ics_values):
                        break
                    for kind, values, names in (("camera", camera_values, camera_names), ("ics", ics_values, ics_names)):
                        for value in values[: self.args.range_host_limit]:
                            if kind == "camera" and not value.startswith(("http://", "https://")):
                                continue
                            for name in names:
                                item = modules.get(name)
                                if not item:
                                    continue
                                # Re-check the target boundary after queue creation and at the
                                # immediate execution edge before plan/dispatch.
                                if kind == "ics" and not _followup_value_allowed(self, value):
                                    revoked_before_dispatch += 1
                                    self.event({
                                        "engine": "industrial_followup_boundary",
                                        "status": "quarantined",
                                        "reason": "candidate outside target before follow-up dispatch",
                                        "module": name,
                                        "input": value,
                                        "probe_count": 0,
                                    })
                                    continue
                                handle.write(json.dumps({
                                    "round": round_number,
                                    "kind": kind,
                                    "module": name,
                                    "input": value,
                                }, ensure_ascii=False) + "\n")
                                self.run_catalog_module(item, value, dispatched + 1)
                                dispatched += 1
            try:
                plan.chmod(0o600)
            except OSError:
                pass
            self.event({
                "engine": "follow_up",
                "status": "success",
                "rounds": rounds,
                "camera_inputs": len(camera_values),
                "ics_inputs": len(ics_values),
                "dispatched": dispatched,
                "revoked_before_dispatch": revoked_before_dispatch,
                "plan": str(plan.relative_to(self.root)),
            })

    NetworkDeviceUnifiedRun.__name__ = "NetworkDeviceUnifiedRun"
    NetworkDeviceUnifiedRun.__qualname__ = "NetworkDeviceUnifiedRun"
    base.UnifiedRun = NetworkDeviceUnifiedRun
    runtime_module._ah_puch_network_device = True
    _INSTALLED = True
    return runtime_module
