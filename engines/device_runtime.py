#!/usr/bin/env python3
"""Resumable network-scale device workflow built on the native device engine."""
from __future__ import annotations

import ipaddress
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

try:
    from . import camera_surface as base
    from . import device_surface_v2 as device
except ImportError:
    import camera_surface as base
    import device_surface_v2 as device


def _state_path(run_root: Path, target: str) -> Path:
    destination = run_root / "09-camera-surfaces"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    return destination / f"{base.slug(target)}.device-network-state.json"


def _inventory_checkpoint_path(state_path: Path) -> Path:
    return state_path.with_name(state_path.stem.replace(".device-network-state", "") + ".device-network-inventory.jsonl")


def _load_inventory_file(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _network_contract(target: str, chunk_prefix: int, port_profile: str, custom_ports: str, model_filter: str, vendor_filter: str) -> str:
    value = json.dumps(
        {
            "target": target,
            "chunk_prefix": chunk_prefix,
            "port_profile": port_profile,
            "custom_ports": custom_ports,
            "model_filter": model_filter,
            "vendor_filter": vendor_filter,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(value.encode()).hexdigest()


def _load_state(path: Path, target: str, expected_contract: str = "") -> dict[str, Any]:
    if not path.is_file():
        return {"target": target, "completed_chunks": [], "inventory": []}
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"target": target, "completed_chunks": [], "inventory": []}
    if str(row.get("target", "")) != target:
        return {"target": target, "completed_chunks": [], "inventory": []}
    if expected_contract and str(row.get("contract_sha256", "")) != expected_contract:
        return {"target": target, "completed_chunks": [], "inventory": []}
    if not isinstance(row.get("completed_chunks", []), list):
        return {"target": target, "completed_chunks": [], "inventory": []}
    inventory = row.get("inventory", [])
    if inventory and (not isinstance(inventory, list) or any(not isinstance(value, dict) for value in inventory)):
        return {"target": target, "completed_chunks": [], "inventory": []}
    if not inventory:
        inventory_name = str(row.get("inventory_file", "")).strip()
        if inventory_name:
            candidate = Path(inventory_name)
            if not candidate.is_absolute():
                candidate = path.parent / candidate
            try:
                candidate.resolve().relative_to(path.parent.resolve())
            except (OSError, ValueError):
                candidate = Path()
            if candidate and candidate.is_file():
                expected_digest = str(row.get("inventory_sha256", ""))
                if expected_digest and _sha256_file(candidate) == expected_digest:
                    inventory = _load_inventory_file(candidate)
    result = dict(row)
    result["inventory"] = list(inventory or [])
    return result


def _write_state(path: Path, state: dict[str, Any], inventory: list[dict[str, Any]]) -> None:
    inventory_path = _inventory_checkpoint_path(path)
    inventory_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    inventory_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in inventory),
        encoding="utf-8",
    )
    inventory_path.chmod(0o600)
    compact = dict(state)
    compact.pop("inventory", None)
    compact["inventory_file"] = inventory_path.name
    compact["inventory_sha256"] = _sha256_file(inventory_path)
    compact["inventory_count"] = len(inventory)
    path.write_text(json.dumps(compact, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _chunks(network: ipaddress._BaseNetwork, requested_prefix: int) -> list[ipaddress._BaseNetwork]:
    if requested_prefix <= 0:
        target_prefix = max(network.prefixlen, 24 if network.version == 4 else 120)
    else:
        maximum = 32 if network.version == 4 else 128
        target_prefix = max(network.prefixlen, min(maximum, requested_prefix))
    if target_prefix == network.prefixlen:
        return [network]
    return list(network.subnets(new_prefix=target_prefix))


def _key(row: dict[str, Any]) -> tuple[str, int, str]:
    host = str(row.get("host", ""))
    try:
        port = int(row.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    return host, port, str(row.get("protocol", "tcp"))


def _rewrite_inventory(run_root: Path, rows: list[dict[str, Any]]) -> None:
    destination = run_root / "09-camera-surfaces"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    selected = [row for row in rows if row.get("selected", True)]
    identified = [row for row in selected if row.get("identified")]
    unknown = [row for row in selected if not row.get("identified")]
    for name, values in (
        ("device-inventory.jsonl", selected),
        ("device-identified.jsonl", identified),
        ("device-unknown.jsonl", unknown),
    ):
        path = destination / name
        path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in values), encoding="utf-8")
        path.chmod(0o600)


def analyze(
    run_root: Path,
    target: str,
    *,
    active: bool,
    timeout: int,
    max_hosts: int = 24,
    port_profile: str = "quick",
    custom_ports: str = "",
    model_filter: str = "",
    vendor_filter: str = "",
    resume_state: Path | None = None,
    technology_enrichment: bool = True,
    workers: int = 24,
    allow_target: Callable[[str], bool] | None = None,
    scan_rate: int = 500,
    chunk_prefix: int = 0,
    chunk_limit: int = 256,
    connect_timeout: float | None = None,
    session_timeout: int = 900,
    retries: int = 1,
    run_tags: list[str] | None = None,
    export_mode: str = "redacted",
    egress_label: str = "",
    device_data_path: Path | None = None,
    probe_mode: str = "all",
    wordlist_tier: str = "micro",
    use_dictionaries: bool = True,
) -> dict[str, Any]:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return device.analyze(
            run_root,
            target,
            active=active,
            timeout=timeout,
            max_hosts=max_hosts,
            port_profile=port_profile,
            custom_ports=custom_ports,
            model_filter=model_filter,
            vendor_filter=vendor_filter,
            resume_state=resume_state,
            technology_enrichment=technology_enrichment,
            workers=workers,
            allow_target=allow_target,
            scan_rate=scan_rate,
            connect_timeout=connect_timeout,
            session_timeout=session_timeout,
            retries=retries,
            run_tags=run_tags,
            export_mode=export_mode,
            egress_label=egress_label,
            device_data_path=device_data_path,
            probe_mode=probe_mode,
            wordlist_tier=wordlist_tier,
            use_dictionaries=use_dictionaries,
        )
    if not active:
        return device.analyze(
            run_root,
            target,
            active=False,
            timeout=timeout,
            max_hosts=max_hosts,
            port_profile=port_profile,
            custom_ports=custom_ports,
            model_filter=model_filter,
            vendor_filter=vendor_filter,
            resume_state=resume_state,
            technology_enrichment=technology_enrichment,
            workers=workers,
            allow_target=allow_target,
            scan_rate=scan_rate,
            connect_timeout=connect_timeout,
            session_timeout=session_timeout,
            retries=retries,
            run_tags=run_tags,
            export_mode=export_mode,
            egress_label=egress_label,
            device_data_path=device_data_path,
            probe_mode=probe_mode,
            wordlist_tier=wordlist_tier,
            use_dictionaries=use_dictionaries,
        )

    canonical_state_path = _state_path(run_root, target)
    read_state_path = resume_state if resume_state and resume_state.is_file() else canonical_state_path
    contract_sha256 = _network_contract(target, chunk_prefix, port_profile, custom_ports, model_filter, vendor_filter)
    state = _load_state(read_state_path, target, contract_sha256)
    # Never overwrite a checkpoint supplied from a previous run. Resumed state
    # is imported into the current run and immediately receives a new local
    # checkpoint under this run's evidence tree. Inventory from that checkpoint
    # is only reusable if the current target boundary still accepts it.
    state_path = canonical_state_path
    allowed = allow_target or (lambda _value: True)
    completed = set(str(value) for value in state.get("completed_chunks", []))
    inventory_map: dict[tuple[str, int, str], dict[str, Any]] = {}
    resume_filtered_inventory = 0
    for row in state.get("inventory", []):
        if not isinstance(row, dict):
            continue
        host = str(row.get("host", "")).strip()
        if not host or not allowed(host):
            resume_filtered_inventory += 1
            continue
        inventory_map[_key(row)] = dict(row)
    all_chunks = _chunks(network, chunk_prefix)
    scanned_now = 0
    urls: set[str] = set()
    hosts: set[str] = set()
    endpoints: set[str] = set()
    remaining_host_budget = max(1, max_hosts)
    chunk_outcomes: list[dict[str, Any]] = []

    for chunk in all_chunks:
        chunk_text = str(chunk)
        if chunk_text in completed:
            continue
        if scanned_now >= max(1, chunk_limit) or remaining_host_budget <= 0:
            break
        result = device.analyze(
            run_root,
            chunk_text,
            active=True,
            timeout=timeout,
            max_hosts=remaining_host_budget,
            port_profile=port_profile,
            custom_ports=custom_ports,
            model_filter=model_filter,
            vendor_filter=vendor_filter,
            resume_state=None,
            technology_enrichment=technology_enrichment,
            workers=workers,
            allow_target=allow_target,
            scan_rate=scan_rate,
            connect_timeout=connect_timeout,
            session_timeout=session_timeout,
            retries=retries,
            run_tags=run_tags,
            export_mode=export_mode,
                egress_label=egress_label,
                device_data_path=device_data_path,
                probe_mode=probe_mode,
                wordlist_tier=wordlist_tier,
                use_dictionaries=use_dictionaries,
            )
        for row in result.get("inventory", []):
            if not isinstance(row, dict):
                continue
            host = str(row.get("host", "")).strip()
            if host and allowed(host):
                inventory_map[_key(row)] = dict(row)
        hosts.update(str(value) for value in result.get("hosts", []) if value and allowed(str(value)))
        urls.update(str(value) for value in result.get("urls", []) if value and allowed(str(value)))
        endpoints.update(str(value) for value in result.get("endpoints", []) if value)
        completed.add(chunk_text)
        scanned_now += 1
        remaining_host_budget = max(0, max_hosts - len({key[0] for key in inventory_map if key[0]}))
        chunk_outcomes.append(
            {
                "chunk": chunk_text,
                "inventory": len(result.get("inventory", [])),
                "identified": int(result.get("summary", {}).get("device_identified", 0)),
                "unknown": int(result.get("summary", {}).get("device_unknown", 0)),
                "status": "success" if result.get("summary", {}).get("device_scan_complete", True) else "partial",
            }
        )
        inventory_rows = sorted(inventory_map.values(), key=lambda row: _key(row))
        state = {
            "target": target,
            "network": str(network),
            "chunk_prefix": chunk.prefixlen,
            "completed_chunks": sorted(completed),
            "complete": len(completed) == len(all_chunks),
            "contract_sha256": contract_sha256,
            "run_tags": sorted(set(run_tags or [])),
            "egress_label": egress_label,
        }
        _write_state(state_path, state, inventory_rows)

    rows = sorted(
        (
            row
            for row in inventory_map.values()
            if str(row.get("host", "")).strip() and allowed(str(row.get("host", "")).strip())
        ),
        key=lambda row: _key(row),
    )
    if not state_path.is_file():
        _write_state(
            state_path,
            {
                "target": target,
                "network": str(network),
                "chunk_prefix": max(network.prefixlen, chunk_prefix or (24 if network.version == 4 else 120)),
                "completed_chunks": sorted(completed),
                "complete": len(completed) == len(all_chunks),
                "contract_sha256": contract_sha256,
                "run_tags": sorted(set(run_tags or [])),
                "egress_label": egress_label,
            },
            rows,
        )
    _rewrite_inventory(run_root, rows)
    for row in rows:
        host = str(row.get("host", ""))
        port = row.get("port")
        protocol = str(row.get("protocol", "tcp"))
        if host:
            hosts.add(host)
        if host and port:
            endpoints.add(base.normalize_endpoint(host, int(port), protocol))
        evidence_url = str((row.get("evidence") or {}).get("url", "")) if isinstance(row.get("evidence"), dict) else ""
        if evidence_url and allowed(evidence_url):
            urls.add(evidence_url)
    complete = len(completed) == len(all_chunks)
    resumed = bool(read_state_path != state_path or state.get("completed_chunks")) and len(completed) > scanned_now
    summary = {
        "device_network": str(network),
        "device_chunks_total": len(all_chunks),
        "device_chunks_completed": len(completed),
        "device_chunks_scanned_now": scanned_now,
        "device_chunk_limit": max(1, chunk_limit),
        "device_network_complete": complete,
        "device_inventory": len(rows),
        "device_identified": sum(1 for row in rows if row.get("identified")),
        "device_unknown": sum(1 for row in rows if not row.get("identified")),
        "device_resumed": resumed,
        "device_resume_filtered_inventory": resume_filtered_inventory,
        "device_checkpoint": str(state_path.relative_to(run_root)),
        "device_chunks_failed": sum(1 for row in chunk_outcomes if row["status"] != "success"),
        "device_chunk_outcomes": chunk_outcomes,
        "device_run_tags": sorted(set(run_tags or [])),
        "device_egress_label": egress_label,
    }
    progress_path = run_root / "09-camera-surfaces" / "device-chunk-progress.jsonl"
    progress_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in chunk_outcomes),
        encoding="utf-8",
    )
    progress_path.chmod(0o600)
    return {
        "summary": summary,
        "urls": sorted(urls),
        "hosts": sorted(hosts)[:max_hosts],
        "endpoints": sorted(endpoints),
        "inventory": rows,
    }
