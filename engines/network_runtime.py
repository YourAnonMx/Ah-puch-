#!/usr/bin/env python3
"""First-class TCP/UDP profile execution with discovery then validation."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Callable

try:
    from .artifact_contract import classify, inspect_artifact
    from .runner_registry import admitted_path, run_bounded
except ImportError:
    from artifact_contract import classify, inspect_artifact
    from runner_registry import admitted_path, run_bounded

_COMPLETED = frozenset({"success", "partial"})


def _clear_terminal_artifacts(paths: list[Path]) -> str | None:
    """Remove previous-run terminal artifacts before dispatch."""
    errors: list[str] = []
    for path in paths:
        try:
            if path.is_symlink() or path.exists():
                path.unlink()
        except OSError as exc:
            errors.append(f"{path}: {type(exc).__name__}: {exc}")
    return "; ".join(errors) if errors else None


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")[:120] or "target"


def _target_kind(target: str) -> str:
    raw = target.strip()
    if raw.startswith(("http://", "https://")):
        from urllib.parse import urlsplit
        raw = urlsplit(raw).hostname or raw
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return "cidr"
        except ValueError:
            pass
    host = raw.strip("[]")
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "host"


def _host_value(target: str) -> str:
    raw = target.strip()
    if raw.startswith(("http://", "https://")):
        from urllib.parse import urlsplit
        return urlsplit(raw).hostname or raw
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")]
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        return raw.rsplit(":", 1)[0]
    return raw


def _parse_masscan_json(path: Path) -> list[tuple[str, int]]:
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    values: list[dict] = []
    try:
        loaded = json.loads(text)
        if isinstance(loaded, list):
            values = [item for item in loaded if isinstance(item, dict)]
        elif isinstance(loaded, dict):
            values = [loaded]
    except json.JSONDecodeError:
        for raw in text.splitlines():
            line = raw.strip().strip(",")
            if line in {"[", "]", ""}:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                values.append(item)
    result: set[tuple[str, int]] = set()
    for item in values:
        ip = str(item.get("ip", "")).strip()
        if not ip:
            continue
        for port in item.get("ports", []):
            if isinstance(port, dict):
                number = port.get("port")
                status = str(port.get("status", "open"))
                if status and status != "open":
                    continue
            else:
                number = port
            try:
                value = int(number)
            except (TypeError, ValueError):
                continue
            if 1 <= value <= 65535:
                result.add((ip, value))
    return sorted(result)


def _parse_gnmap_services(path: Path, fallback_protocol: str) -> list[dict[str, Any]]:
    """Return only explicitly open services from a completed Nmap grep file."""
    if not path.is_file() or path.is_symlink():
        return []
    services: set[tuple[str, int, str]] = set()
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        host = fields[1].strip()
        if not host:
            continue
        for record in line.split("Ports:", 1)[1].split(","):
            parts = record.strip().split("/")
            if len(parts) < 2 or parts[1] != "open":
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            protocol = parts[2].strip().lower() if len(parts) > 2 and parts[2].strip() else fallback_protocol
            if 1 <= port <= 65535 and protocol in {"tcp", "udp"}:
                services.add((host, port, protocol))
    return [
        {"host": host, "port": port, "protocol": protocol}
        for host, port, protocol in sorted(services)
    ]


def _nmap_validate(
    root: Path, host: str, ports: list[int] | str, timeout: int, suffix: str = "tcp",
    options: dict[str, Any] | None = None,
) -> dict:
    nmap = admitted_path("network_service")
    if not nmap:
        return {"host": host, "runner": "network-service", "status": "skipped", "reason": "nmap unavailable", "services": []}
    directory = root / _slug(host)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = directory / suffix
    if isinstance(ports, str):
        port_text = ports.strip()
    else:
        port_text = ",".join(str(value) for value in sorted(set(ports)))
    if not port_text:
        return {"host": host, "runner": "network-service", "status": "skipped", "reason": "no discovered ports", "services": []}
    terminal_paths = [base.with_suffix(".nmap"), base.with_suffix(".xml"), base.with_suffix(".gnmap")]
    cleanup_error = _clear_terminal_artifacts(terminal_paths)
    if cleanup_error:
        return {
            "host": host,
            "runner": "network-service",
            "status": "failed",
            "reason": "terminal artifact cleanup failed",
            "cleanup_error": cleanup_error,
            "services": [],
        }
    options = options or {}
    command = [nmap, "-Pn", "-n", "--open"]
    if int(options.get("service_detection", 1)):
        command.extend(["-sV", "--version-light"])
    if "top_ports" in options:
        command.extend(["--top-ports", str(max(1, int(options["top_ports"])))])
    elif port_text in {"1-65535", "1:65535"}:
        command.append("-p-")
    else:
        command.extend(["-p", port_text])
    if int(options.get("os_detection", 0)):
        command.append("-O")
    if int(options.get("traceroute", 0)):
        command.append("--traceroute")
    if options.get("scripts"):
        command.extend(["--script", str(options["scripts"])])
    if "timing" in options:
        command.append(f"-T{int(options['timing'])}")
    if int(options.get("rate", 0)) > 0:
        command.extend(["--min-rate", str(int(options["rate"]))])
    if int(options.get("timeout", 0)) > 0:
        command.extend(["--host-timeout", f"{int(options['timeout'])}s"])
    if options.get("profile") == "fast":
        command.append("-F")
    elif options.get("profile") == "comprehensive":
        command.append("-A")
    command.extend(["-oA", str(base), host])
    result = run_bounded(command, directory, directory / f"{suffix}.console.txt", directory / f"{suffix}.stderr.txt", timeout)
    artifacts = [
        inspect_artifact(base.with_suffix(".nmap"), required=True),
        inspect_artifact(base.with_suffix(".xml"), required=True),
        inspect_artifact(base.with_suffix(".gnmap"), required=True),
    ]
    status = classify(result, artifacts)
    services = _parse_gnmap_services(base.with_suffix(".gnmap"), "tcp") if status in _COMPLETED else []
    return {"host": host, "runner": "network-service", "status": status, "artifacts": artifacts, "services": services, **result}


def _udp_validate(root: Path, host: str, ports: str, timeout: int, options: dict[str, Any] | None = None) -> dict:
    nmap = admitted_path("network_service")
    if not nmap:
        return {"host": host, "runner": "network-udp", "status": "skipped", "reason": "nmap unavailable", "services": []}
    directory = root / _slug(host)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = directory / "udp"
    terminal_paths = [base.with_suffix(".nmap"), base.with_suffix(".xml"), base.with_suffix(".gnmap")]
    cleanup_error = _clear_terminal_artifacts(terminal_paths)
    if cleanup_error:
        return {
            "host": host,
            "runner": "network-udp",
            "status": "failed",
            "reason": "terminal artifact cleanup failed",
            "cleanup_error": cleanup_error,
            "services": [],
        }
    options = options or {}
    command = [nmap, "-Pn", "-n", "-sU", "--open"]
    if int(options.get("service_detection", 1)):
        command.extend(["-sV", "--version-light"])
    command.extend(["-p", ports])
    if options.get("scripts"):
        command.extend(["--script", str(options["scripts"])])
    if "timing" in options:
        command.append(f"-T{int(options['timing'])}")
    if int(options.get("rate", 0)) > 0:
        command.extend(["--min-rate", str(int(options["rate"]))])
    if int(options.get("timeout", 0)) > 0:
        command.extend(["--host-timeout", f"{int(options['timeout'])}s"])
    command.extend(["-oA", str(base), host])
    result = run_bounded(command, directory, directory / "udp.console.txt", directory / "udp.stderr.txt", timeout)
    artifacts = [inspect_artifact(base.with_suffix(".nmap"), required=True), inspect_artifact(base.with_suffix(".xml"), required=True), inspect_artifact(base.with_suffix(".gnmap"), required=True)]
    status = classify(result, artifacts)
    services = _parse_gnmap_services(base.with_suffix(".gnmap"), "udp") if status in _COMPLETED else []
    return {"host": host, "runner": "network-udp", "status": status, "artifacts": artifacts, "services": services, **result}


def run(
    root: Path,
    target: str,
    profile: dict,
    *,
    active: bool,
    rate: int,
    host_limit: int,
    timeout: int,
    allow_target: Callable[[str], bool] | None = None,
    tool_options: dict[str, dict[str, Any]] | None = None,
) -> dict:
    destination = root / "network-profile-runtime"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    allowed = allow_target or (lambda _value: True)
    rows: list[dict] = []
    overrides = tool_options or {}
    nmap_options = dict(overrides.get("nmap", {}))
    masscan_options = dict(overrides.get("masscan", {}))
    if not active:
        rows.append({"runner": "network-profile", "status": "planned-passive", "mode": profile.get("mode"), "services": []})
    else:
        kind = _target_kind(target)
        tcp_spec = str(nmap_options.get("ports", masscan_options.get("ports", profile.get("tcp_ports", ""))))
        udp_enabled = bool(profile.get("udp_enabled"))
        udp_spec = str(nmap_options.get("udp_ports", profile.get("udp_ports", "")))
        hosts: dict[str, list[int] | str] = {}

        if kind == "cidr":
            if not allowed(target):
                rows.append({"runner": "range-discovery", "status": "quarantined", "target": target, "services": []})
            else:
                masscan = admitted_path("range_discovery")
                if masscan:
                    raw = destination / "masscan.json"
                    cleanup_error = _clear_terminal_artifacts([raw])
                    if cleanup_error:
                        rows.append({
                            "runner": "range-discovery",
                            "status": "failed",
                            "reason": "terminal artifact cleanup failed",
                            "cleanup_error": cleanup_error,
                            "services": [],
                        })
                    else:
                        command = [masscan, target, "-p", tcp_spec, "--max-rate", str(max(1, int(masscan_options.get("rate", rate)))), "--output-format", "json", "--output-filename", str(raw)]
                        result = run_bounded(command, destination, destination / "masscan.console.txt", destination / "masscan.stderr.txt", min(timeout, 43200))
                        artifacts = [inspect_artifact(raw, required=True)]
                        status = classify(result, artifacts)
                        discovered = []
                        if status in _COMPLETED:
                            discovered = [
                                {"host": host, "port": port, "protocol": "tcp"}
                                for host, port in _parse_masscan_json(raw)
                                if allowed(host)
                            ]
                        rows.append({"runner": "range-discovery", "status": status, "artifacts": artifacts, "services": discovered, **result})
                        for service in discovered:
                            host = str(service["host"])
                            current = hosts.setdefault(host, [])
                            if isinstance(current, list):
                                current.append(int(service["port"]))
                else:
                    rows.append({"runner": "range-discovery", "status": "skipped", "reason": "masscan unavailable; full CIDR sweep not replaced with an unbounded nmap fallback", "services": []})
        else:
            host = _host_value(target)
            if allowed(host):
                hosts[host] = tcp_spec
            else:
                rows.append({"runner": "network-service", "status": "quarantined", "target": host, "services": []})

        selected_hosts = sorted(hosts)[: max(1, host_limit)]
        for host in selected_hosts:
            effective_timeout = min(timeout, max(1, int(nmap_options.get("timeout", timeout))), 43200)
            rows.append(_nmap_validate(destination / "validation", host, hosts[host], effective_timeout, "tcp", nmap_options))
            if udp_enabled and udp_spec:
                rows.append(_udp_validate(destination / "validation", host, udp_spec, effective_timeout, nmap_options))

    ledger = destination / "runs.jsonl"
    ledger.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    ledger.chmod(0o600)
    counts: dict[str, int] = {}
    service_count = 0
    for row in rows:
        status = str(row.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
        if status in _COMPLETED and isinstance(row.get("services"), list):
            service_count += len(row["services"])
    return {"runs": len(rows), "statuses": counts, "services": service_count}
