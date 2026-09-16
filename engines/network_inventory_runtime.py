#!/usr/bin/env python3
"""Target-bounded normalized service inventory for SRC03.

The legacy inventory parser may extract useful Nmap product/version metadata,
but raw XML is not a target boundary. This adapter keeps that metadata
only for endpoints already promotable in the canonical artifact bus and adds
bus-native services that have no XML row.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

try:
    from .artifact_bus import ArtifactBus, canonical_host
except ImportError:
    from artifact_bus import ArtifactBus, canonical_host

_INSTALLED = False
_ORIGINAL_BUILD: Callable[[Path], dict[str, int]] | None = None


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


def _service_key(host: object, protocol: object, port: object) -> tuple[str, str, int] | None:
    canonical = canonical_host(str(host or ""))
    protocol_text = str(protocol or "tcp").strip().lower() or "tcp"
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return None
    if not canonical or protocol_text not in {"tcp", "udp"} or not 1 <= port_number <= 65535:
        return None
    return canonical, protocol_text, port_number


def _promotable_services(root: Path, target: str) -> dict[tuple[str, str, int], dict[str, Any]]:
    bus = ArtifactBus(root, target)
    result: dict[tuple[str, str, int], dict[str, Any]] = {}
    for row in bus.records("service", promotable_only=True):
        for observation in row.get("observations", []):
            if not isinstance(observation, dict):
                continue
            if not observation.get("within_target") or not observation.get("observed"):
                continue
            attributes = observation.get("attributes", {})
            if not isinstance(attributes, dict):
                continue
            key = _service_key(attributes.get("host"), attributes.get("protocol", "tcp"), attributes.get("port"))
            if key is None:
                continue
            current = result.setdefault(
                key,
                {
                    "host": key[0],
                    "protocol": key[1],
                    "port": key[2],
                    "service": str(attributes.get("service", "") or ""),
                    "source": "artifacts/bus.jsonl",
                    "producers": [],
                    "statuses": [],
                },
            )
            producer = str(observation.get("producer", "") or "")
            status = str(observation.get("status", "") or "")
            if producer and producer not in current["producers"]:
                current["producers"].append(producer)
            if status and status not in current["statuses"]:
                current["statuses"].append(status)
            if not current.get("service") and attributes.get("service"):
                current["service"] = str(attributes["service"])
    return result


def _target_from_run(root: Path) -> str:
    path = root / "manifest.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return ""
    return str(payload.get("target", "") or "") if isinstance(payload, dict) else ""


def build_inventory(root: Path) -> dict[str, int]:
    """Run the accepted inventory builder, then enforce canonical service keys."""
    if _ORIGINAL_BUILD is None:
        raise RuntimeError("inventory runtime adapter not installed")
    summary = dict(_ORIGINAL_BUILD(root))
    target = _target_from_run(root)
    bus_path = root / "artifacts" / "bus.jsonl"
    if not target or not bus_path.is_file():
        return summary

    allowed = _promotable_services(root, target)
    services_path = root / "inventory" / "services.jsonl"
    raw_rows = _jsonl(services_path)
    retained: dict[tuple[str, str, int], dict[str, Any]] = {}
    for row in raw_rows:
        key = _service_key(row.get("host"), row.get("protocol", "tcp"), row.get("port"))
        if key is None or key not in allowed:
            continue
        retained[key] = row

    for key, bus_row in allowed.items():
        if key in retained:
            row = retained[key]
            row["canonical_bus"] = True
            row["bus_producers"] = list(bus_row.get("producers", []))
            row["bus_statuses"] = list(bus_row.get("statuses", []))
            if not row.get("service") and bus_row.get("service"):
                row["service"] = bus_row["service"]
            continue
        retained[key] = {
            "host": key[0],
            "protocol": key[1],
            "port": key[2],
            "service": bus_row.get("service", ""),
            "source": "artifacts/bus.jsonl",
            "canonical_bus": True,
            "bus_producers": list(bus_row.get("producers", [])),
            "bus_statuses": list(bus_row.get("statuses", [])),
        }

    rows = [retained[key] for key in sorted(retained)]
    services_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    services_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    services_path.chmod(0o600)
    summary["services"] = len(rows)
    summary_path = root / "inventory" / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.chmod(0o600)
    return summary


def install(runtime_module: Any) -> Any:
    global _INSTALLED, _ORIGINAL_BUILD
    if _INSTALLED or getattr(runtime_module, "_ah_puch_network_inventory_scope", False):
        return runtime_module
    _ORIGINAL_BUILD = runtime_module.build_normalized_inventory
    runtime_module.build_normalized_inventory = build_inventory
    runtime_module._ah_puch_network_inventory_scope = True
    _INSTALLED = True
    return runtime_module
