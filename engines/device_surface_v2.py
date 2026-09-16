#!/usr/bin/env python3
"""Native device/camera workflow with bounded discovery, resume and inventory."""
from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

try:
    from . import camera_surface as base
    from .dictionary_broker import resolve_info
    from .device_data import fingerprint_rules, load_device_data, path_candidates, service_ports
    from .runner_registry import admitted_path, run_bounded
except ImportError:
    import camera_surface as base
    from dictionary_broker import resolve_info
    from device_data import fingerprint_rules, load_device_data, path_candidates, service_ports
    from runner_registry import admitted_path, run_bounded


def _state_contract(target: str, port_profile: str, custom_ports: str, model_filter: str, vendor_filter: str) -> str:
    material = json.dumps(
        {
            "target": target,
            "port_profile": port_profile,
            "custom_ports": custom_ports,
            "model_filter": model_filter,
            "vendor_filter": vendor_filter,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


def _device_path_dictionary(*, tier: str, enabled: bool, limit: int = 256) -> tuple[list[str], dict[str, Any]]:
    if not enabled:
        return [], {
            "class": "device-path",
            "effective_tier": tier,
            "source": "disabled",
            "path": "",
            "available": False,
            "entries": 0,
        }
    try:
        info = resolve_info("device-path", tier=tier)
    except Exception as exc:
        return [], {
            "class": "device-path",
            "effective_tier": tier,
            "source": "error",
            "path": "",
            "available": False,
            "entries": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }
    path = Path(str(info.get("path", "")))
    values: list[str] = []
    if info.get("available") and path.is_file() and not path.is_symlink():
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                value = raw.strip()
                if not value or value.startswith("#") or "\x00" in value:
                    continue
                values.append(value if value.startswith("/") else f"/{value}")
                if len(values) >= max(0, limit):
                    break
        except OSError as exc:
            info = {**info, "source": "error", "available": False, "error": f"{type(exc).__name__}: {exc}"}
            values = []
    return list(dict.fromkeys(values)), {
        "class": "device-path",
        "effective_tier": info.get("effective_tier") or info.get("requested_tier") or tier,
        "source": info.get("source", ""),
        "path": info.get("path", ""),
        "available": bool(info.get("available")),
        "entries": len(values),
    }


def _load_state(path: Path | None, target: str, expected_contract: str = "") -> dict[str, Any]:
    if not path:
        return {}
    candidate = path
    if candidate.is_dir():
        states = sorted(candidate.rglob("*.device-state.json")) + sorted(candidate.rglob("*.camera-state.json"))
        if not states:
            return {}
        candidate = states[-1]
    try:
        state = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if str(state.get("target", "")) != target:
        return {}
    if expected_contract and str(state.get("contract_sha256", "")) != expected_contract:
        return {}
    processed = state.get("processed", [])
    if not isinstance(processed, list) or any(not isinstance(value, str) for value in processed):
        return {}
    return state


def _probe_with_retries(
    host: str,
    port: int,
    *,
    connect_timeout: float,
    retries: int,
    deadline: float,
    paths: list[str] | None = None,
    probe_mode: str = "all",
) -> dict[str, Any]:
    """Bound a device endpoint retry loop by both attempt and run deadline."""
    last: dict[str, Any] = {"host": host, "port": port, "open": False, "state": "down"}
    attempts = 0
    for _attempt in range(max(0, retries) + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {**last, "state": "unknown", "error": "device session timeout", "attempts": attempts}
        attempts += 1
        try:
            attempt_timeout = max(0.1, min(connect_timeout, remaining))
            kwargs: dict[str, Any] = {}
            if paths:
                kwargs["paths"] = paths
            if probe_mode != "all":
                kwargs["probe_mode"] = probe_mode
            last = base.probe_service(host, port, attempt_timeout, **kwargs)
        except Exception as exc:
            last = {"host": host, "port": port, "open": False, "error": f"{type(exc).__name__}: {exc}"}
        if last.get("open"):
            break
    state = "up" if last.get("open") else ("unknown" if last.get("error") else "down")
    return {**last, "state": state, "attempts": attempts}


_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}
_SENSITIVE_TEXT = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|authorization)\b(\s*[:=]\s*)([^\s&;,\"']+)",
)


def _redact_probe_evidence(row: dict[str, Any], *, omit_content: bool) -> dict[str, Any]:
    value = dict(row)
    headers = value.get("headers")
    if isinstance(headers, dict):
        value["headers"] = {
            str(name): ("[REDACTED]" if str(name).casefold() in _SENSITIVE_HEADERS else str(header_value))
            for name, header_value in headers.items()
        }
    for field in ("body_sample", "_match_text", "banner"):
        if field not in value:
            continue
        if omit_content:
            value.pop(field, None)
        else:
            value[field] = _SENSITIVE_TEXT.sub(r"\1\2[REDACTED]", str(value[field]))
    return value


def _parse_grepable(path: Path, max_hosts: int) -> dict[str, set[int]]:
    services: dict[str, set[int]] = {}
    if not path.is_file():
        return services
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        host = parts[1]
        bucket = services.setdefault(host, set())
        for record in line.split("Ports:", 1)[1].split(","):
            fields = record.strip().split("/")
            if len(fields) >= 2 and fields[1] == "open" and fields[0].isdigit():
                bucket.add(int(fields[0]))
        if len(services) >= max_hosts:
            break
    return {host: ports for host, ports in services.items() if ports}


def _nmap_discover(host: str, ports: set[int], timeout: int, destination: Path) -> set[int]:
    nmap = admitted_path("network_service")
    if not nmap:
        return set()
    family = ["-6"] if ":" in host else []
    if len(ports) >= 60000:
        command = [nmap, *family, "-Pn", "-n", "--open", "-p-", "-oG", str(destination), host]
    else:
        port_text = ",".join(str(value) for value in sorted(ports))
        command = [nmap, *family, "-Pn", "-n", "--open", "-p", port_text, "-oG", str(destination), host]
    result = run_bounded(
        command,
        destination.parent,
        destination.parent / f"{base.slug(host)}.nmap.console.txt",
        destination.parent / f"{base.slug(host)}.nmap.stderr.txt",
        timeout,
    )
    if result["exit_code"] != 0:
        return set()
    return _parse_grepable(destination, 1).get(host.strip("[]"), set())


def _masscan_range(
    network: str,
    ports: set[int],
    *,
    rate: int,
    timeout: int,
    destination: Path,
    max_hosts: int,
) -> tuple[dict[str, set[int]], dict[str, Any]]:
    binary = admitted_path("range_discovery")
    if not binary:
        return {}, {"runner": "masscan", "status": "unavailable"}
    port_text = "1-65535" if len(ports) >= 60000 else ",".join(str(value) for value in sorted(ports))
    raw = destination / "device-range.masscan.json"
    result = run_bounded(
        [binary, network, "-p", port_text, "--max-rate", str(max(1, rate)), "--output-format", "json", "--output-filename", str(raw)],
        destination,
        destination / "device-range.masscan.console.txt",
        destination / "device-range.masscan.stderr.txt",
        timeout,
    )
    services: dict[str, set[int]] = {}
    if raw.is_file():
        text = raw.read_text(encoding="utf-8", errors="replace")
        try:
            parsed = json.loads(text)
            rows = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            rows = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line or line in {"[", "]"}:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rows.extend(row if isinstance(row, list) else [row])
        for row in rows:
            if not isinstance(row, dict):
                continue
            host = str(row.get("ip", "")).strip()
            if not host:
                continue
            bucket = services.setdefault(host, set())
            for entry in row.get("ports", []):
                number = entry.get("port") if isinstance(entry, dict) else entry
                try:
                    number = int(number)
                except (TypeError, ValueError):
                    continue
                if 1 <= number <= 65535:
                    bucket.add(number)
            if len(services) >= max_hosts:
                break
    services = {host: found for host, found in services.items() if found}
    status = "success" if result["exit_code"] == 0 else ("timeout" if result["timed_out"] else "partial")
    return services, {"runner": "masscan", "status": status, **result, "hosts": len(services)}


def _nmap_range(
    network: str,
    ports: set[int],
    *,
    timeout: int,
    destination: Path,
    max_hosts: int,
) -> tuple[dict[str, set[int]], dict[str, Any]]:
    binary = admitted_path("network_service")
    if not binary:
        return {}, {"runner": "nmap", "status": "unavailable"}
    raw = destination / "device-range.nmap.grep.txt"
    port_text = "1-65535" if len(ports) >= 60000 else ",".join(str(value) for value in sorted(ports))
    family = ["-6"] if ipaddress.ip_network(network, strict=False).version == 6 else []
    result = run_bounded(
        [binary, *family, "-Pn", "-n", "--open", "-p", port_text, "-oG", str(raw), network],
        destination,
        destination / "device-range.nmap.console.txt",
        destination / "device-range.nmap.stderr.txt",
        timeout,
    )
    services = _parse_grepable(raw, max_hosts) if result["exit_code"] == 0 else {}
    status = "success" if result["exit_code"] == 0 else ("timeout" if result["timed_out"] else "partial")
    return services, {"runner": "nmap", "status": status, **result, "hosts": len(services)}


def _discover_network_services(
    target: str,
    ports: set[int],
    *,
    rate: int,
    timeout: int,
    destination: Path,
    max_hosts: int,
    allow_target: Callable[[str], bool],
) -> tuple[dict[str, set[int]], dict[str, Any]]:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return {}, {"status": "invalid-network"}
    # The exact CIDR is the target scan unit. Individual discoveries are
    # filtered again before they can enter later Ah-Puch stages.
    if network.version == 4:
        services, evidence = _masscan_range(
            str(network), ports, rate=rate, timeout=timeout, destination=destination, max_hosts=max_hosts
        )
    else:
        services, evidence = {}, {"runner": "masscan", "status": "unsupported-ipv6"}
    if evidence.get("status") in {"unavailable", "unsupported-ipv6", "timeout", "partial"}:
        primary = dict(evidence)
        services, evidence = _nmap_range(
            str(network), ports, timeout=timeout, destination=destination, max_hosts=max_hosts
        )
        evidence["fallback_from"] = primary
    filtered: dict[str, set[int]] = {}
    for host, found in services.items():
        if allow_target(host):
            filtered[host] = found
        if len(filtered) >= max_hosts:
            break
    evidence = dict(evidence)
    evidence["target_hosts"] = len(filtered)
    evidence["network"] = str(network)
    return filtered, evidence


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
    if probe_mode not in {"all", "web", "stream"}:
        raise ValueError(f"unknown device probe mode: {probe_mode}")
    # Base extraction is passive/local: it reads already-produced result files
    # and normalizes candidate endpoints without contacting them.
    base_result = base.analyze(run_root, target, active=False, timeout=timeout, max_hosts=max_hosts)
    destination = run_root / "09-camera-surfaces"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    signatures = base.read_signatures()
    configured_ports = base.ports_for_profile(port_profile, custom_ports)
    imported_paths: list[str] = []
    imported_data_sha256 = ""
    if device_data_path:
        artifact = load_device_data(device_data_path)
        signatures.extend(fingerprint_rules(artifact))
        configured_ports.update(service_ports(artifact))
        imported_paths = path_candidates(artifact)
        imported_data_sha256 = hashlib.sha256(device_data_path.read_bytes()).hexdigest()
    broker_paths, broker_path_info = _device_path_dictionary(
        tier=str(wordlist_tier or "micro"),
        enabled=bool(use_dictionaries),
    )
    imported_paths = list(dict.fromkeys([*imported_paths, *broker_paths]))
    contract_sha256 = _state_contract(target, port_profile, custom_ports, model_filter, vendor_filter)
    state = _load_state(resume_state, target, contract_sha256)
    completed = set(str(value) for value in state.get("processed", []))
    allowed = allow_target or (lambda _value: True)
    hosts = [host for host in dict.fromkeys(base_result.get("hosts", [])) if allowed(str(host))][:max_hosts]
    endpoint_map: dict[str, dict[str, Any]] = {}
    discovery_evidence: dict[str, Any] = {"status": "not-run"}
    deadline = time.monotonic() + max(1, session_timeout)
    probe_timeout = max(0.1, float(connect_timeout if connect_timeout is not None else min(timeout, 5)))

    for raw in base_result.get("endpoints", []):
        try:
            scheme, rest = raw.split("://", 1)
            host_part, port_text = rest.rsplit(":", 1)
            host = host_part.strip("[]")
            port = int(port_text)
        except (ValueError, TypeError):
            continue
        if not allowed(host):
            continue
        endpoint_map[f"{host}:{port}"] = {"host": host, "port": port, "protocol": scheme, "source": "observed"}

    if active and base.is_network_target(target):
        services, discovery_evidence = _discover_network_services(
            target,
            configured_ports,
            rate=max(1, scan_rate),
            timeout=max(1, min(int(deadline - time.monotonic()), max(30, min(timeout * 6, 1800)))),
            destination=destination,
            max_hosts=max(1, max_hosts),
            allow_target=allowed,
        )
        # Re-apply the target filter at the promotion boundary. Discovery
        # backends may be mocked, replaced, or return stale/unfiltered data;
        # no host may enter inventory or active probing unless the caller's
        # allow_target policy accepts it here as well.
        services = {
            str(host): set(found)
            for host, found in services.items()
            if allowed(str(host))
        }
        hosts = sorted(dict.fromkeys(hosts + list(services)))[:max_hosts]
        for host, found_ports in services.items():
            for port in found_ports:
                key = f"{host}:{port}"
                if key not in completed:
                    endpoint_map.setdefault(key, {"host": host, "port": port, "protocol": "tcp", "source": "range-discovery"})
    elif active:
        for host in hosts:
            if not allowed(host):
                continue
            host_ports = set(configured_ports)
            if len(host_ports) > 512:
                discovered = _nmap_discover(
                    host,
                    host_ports,
                    max(30, min(timeout * 4, 900)),
                    destination / f"{base.slug(host)}.nmap.grep.txt",
                )
                host_ports = discovered
            pending = [port for port in sorted(host_ports) if f"{host}:{port}" not in completed]
            with ThreadPoolExecutor(max_workers=max(1, min(workers, 64))) as executor:
                future_map = {
                    executor.submit(
                        _probe_with_retries,
                        host,
                        port,
                        connect_timeout=probe_timeout,
                        retries=max(0, retries),
                        deadline=deadline,
                        paths=imported_paths,
                        probe_mode=probe_mode,
                    ): port
                    for port in pending
                }
                for future in as_completed(future_map):
                    port = future_map[future]
                    key = f"{host}:{port}"
                    completed.add(key)
                    try:
                        result = future.result()
                    except Exception as exc:
                        endpoint_map.setdefault(
                            key,
                            {"host": host, "port": port, "open": False, "error": f"{type(exc).__name__}: {exc}"},
                        )
                        continue
                    endpoint_map[key] = result
        discovery_evidence = {"runner": "direct-bounded", "status": "success", "hosts": len(hosts)}

    # Range discovery first identifies open services; protocol evidence is then
    # collected only for those discovered ports instead of blindly probing the
    # full profile a second time.
    if active and base.is_network_target(target):
        pending_rows = [
            (key, row)
            for key, row in endpoint_map.items()
            if row.get("source") == "range-discovery" and key not in completed
        ]
        with ThreadPoolExecutor(max_workers=max(1, min(workers, 64))) as executor:
            future_map = {
                executor.submit(
                _probe_with_retries,
                    str(row["host"]),
                    int(row["port"]),
                    connect_timeout=probe_timeout,
                    retries=max(0, retries),
                    deadline=deadline,
                paths=imported_paths,
                probe_mode=probe_mode,
                ): (key, row)
                for key, row in pending_rows
            }
            for future in as_completed(future_map):
                key, fallback = future_map[future]
                completed.add(key)
                try:
                    result = future.result()
                except Exception as exc:
                    endpoint_map[key] = {**fallback, "open": True, "error": f"{type(exc).__name__}: {exc}"}
                    continue
                endpoint_map[key] = result if result.get("open") else {**fallback, "open": True}

    inventory: list[dict[str, Any]] = []
    wanted = model_filter.casefold().strip()
    whatweb = admitted_path("technology_fingerprint") if technology_enrichment and active else ""
    tech_budget = 20
    for key, row in sorted(endpoint_map.items()):
        if not allowed(str(row.get("host", ""))):
            continue
        match_text = "\n".join(str(row.get(field, "")) for field in ("server", "title", "body_sample", "banner", "_match_text"))
        response_bytes = int(row.get("response_bytes", 0) or 0)
        matches = (
            base.fingerprint_matches(match_text, signatures, response_bytes=response_bytes)
            if match_text and response_bytes
            else (base.fingerprint_matches(match_text, signatures) if match_text else [])
        )
        models = sorted({str(match.get("model", "")) for match in matches if match.get("model")})
        vendors = sorted({str(match.get("vendor", "")) for match in matches if match.get("vendor")})
        device_types = sorted({str(match.get("device_type", "")) for match in matches if match.get("device_type")})
        identified = bool(models)
        wanted_vendor = vendor_filter.casefold().strip()
        selected = (not wanted or any(wanted in model.casefold() for model in models)) and (
            not wanted_vendor or any(wanted_vendor in vendor.casefold() for vendor in vendors)
        )
        firmware = str(row.get("firmware", ""))
        if not firmware and match_text:
            firmware_match = re.search(r"\b(?:firmware|version|fw)\s*[:=/ -]\s*([A-Za-z0-9][A-Za-z0-9._-]{0,63})", match_text, re.I)
            firmware = firmware_match.group(1) if firmware_match else ""
        record = {
            "host": row.get("host"),
            "port": row.get("port"),
            "protocol": row.get("protocol", row.get("transport", "tcp")),
            "status": row.get("status", 0),
            "server": row.get("server", ""),
            "title": row.get("title", ""),
            "identified": identified,
            "models": models,
            "vendors": vendors,
            "device_types": device_types,
            "selected": selected,
            "source": row.get("source", "active-or-observed"),
            "firmware": firmware,
            "state": row.get("state", "up" if row.get("open", False) or row.get("status") else "down"),
            "online": bool(row.get("open", False) or row.get("status")),
            "attempts": int(row.get("attempts", 0) or 0),
            "evidence": {
                "banner": str(row.get("banner", ""))[:4000],
                "content_type": str(row.get("content_type", ""))[:1000],
                "url": str(row.get("url", "")),
                "title": str(row.get("title", ""))[:1000],
                "server": str(row.get("server", ""))[:1000],
                "response_bytes": int(row.get("response_bytes", 0) or 0),
                "redirect_location": str(row.get("redirect_location", ""))[:2000],
            },
        }
        if whatweb and row.get("url") and tech_budget > 0:
            tech_budget -= 1
            out = destination / f"{base.slug(key)}.technology.json"
            run = run_bounded(
                [whatweb, "--no-errors", "--color=never", f"--log-json={out}", str(row["url"])],
                destination,
                destination / f"{base.slug(key)}.technology.console.txt",
                destination / f"{base.slug(key)}.technology.stderr.txt",
                min(timeout, 90),
            )
            record["technology_enrichment"] = {
                "exit_code": run["exit_code"],
                "artifact": str(out.relative_to(run_root)) if out.exists() else "",
            }
        inventory.append(record)

    raw_evidence = destination / "device-probe-evidence.jsonl"
    evidence_rows = []
    for row in endpoint_map.values():
        evidence_rows.append(_redact_probe_evidence(row, omit_content=export_mode == "redacted"))
    raw_evidence.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in evidence_rows),
        encoding="utf-8",
    )
    raw_evidence.chmod(0o600)

    selected_inventory = [row for row in inventory if row["selected"]]
    identified_rows = [row for row in selected_inventory if row["identified"]]
    unknown_rows = [row for row in selected_inventory if not row["identified"]]
    for name, rows in (
        ("device-inventory.jsonl", selected_inventory),
        ("device-identified.jsonl", identified_rows),
        ("device-unknown.jsonl", unknown_rows),
    ):
        path = destination / name
        path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        path.chmod(0o600)

    scan_complete = not active or discovery_evidence.get("status") in {"success", "not-run"}
    checkpoint = destination / f"{base.slug(target)}.device-state.json"
    checkpoint.write_text(
        json.dumps(
            {
                "target": target,
                "complete": scan_complete,
                "port_profile": port_profile,
                "custom_ports": custom_ports,
                "model_filter": model_filter,
                "vendor_filter": vendor_filter,
                "contract_sha256": contract_sha256,
                "processed": sorted(completed),
                "discovery": discovery_evidence,
                "inventory_count": len(selected_inventory),
                "run_tags": sorted(set(run_tags or [])),
                "egress_label": egress_label,
                "export_mode": export_mode,
                "device_data_sha256": imported_data_sha256,
                "device_path_dictionary": broker_path_info,
                "updated": base.dt.datetime.now(base.dt.timezone.utc).isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    checkpoint.chmod(0o600)

    summary = dict(base_result.get("summary", {}))
    summary.update(
        {
            "device_port_profile": port_profile,
            "device_ports_selected": len(configured_ports),
            "device_inventory": len(selected_inventory),
            "device_identified": len(identified_rows),
            "device_unknown": len(unknown_rows),
            "device_model_filter": model_filter,
            "device_vendor_filter": vendor_filter,
            "device_resumed": bool(state),
            "device_target_filtered_hosts": len(hosts),
            "device_scan_complete": scan_complete,
            "device_discovery_runner": discovery_evidence.get("runner", ""),
            "device_discovery_status": discovery_evidence.get("status", ""),
            "device_endpoints_scanned": len(completed),
            "device_endpoints_found": sum(1 for row in endpoint_map.values() if row.get("open")),
            "device_endpoints_missed": sum(1 for row in endpoint_map.values() if not row.get("open")),
            "device_session_timed_out": time.monotonic() >= deadline,
            "device_export_mode": export_mode,
            "device_run_tags": sorted(set(run_tags or [])),
            "device_egress_label": egress_label,
            "device_raw_evidence": str(raw_evidence.relative_to(run_root)),
            "device_data_sha256": imported_data_sha256,
            "device_path_dictionary_source": broker_path_info.get("source", ""),
            "device_path_dictionary_entries": broker_path_info.get("entries", 0),
            "device_path_dictionary_enabled": bool(use_dictionaries),
            "device_technology_status": (
                "disabled" if not technology_enrichment or not active else ("available" if whatweb else "dependency-unavailable")
            ),
        }
    )
    endpoints = [
        base.normalize_endpoint(str(row["host"]), int(row["port"]), str(row.get("protocol", "tcp")))
        for row in selected_inventory
        if row.get("host") and row.get("port") and row.get("online")
    ]
    urls = sorted(
        {
            str(row.get("url"))
            for row in endpoint_map.values()
            if row.get("url") and allowed(str(row.get("url")))
        }
    )
    fallback_urls = [url for url in base_result.get("urls", []) if allowed(str(url))]
    return {
        "summary": summary,
        "urls": urls or fallback_urls,
        "hosts": hosts,
        "endpoints": endpoints,
        "inventory": selected_inventory,
        "checkpoint": str(checkpoint),
        "discovery": discovery_evidence,
    }
