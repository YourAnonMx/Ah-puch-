#!/usr/bin/env python3
"""Normalized Ah-Puch inventory and execution receipt projections."""
from __future__ import annotations

import hashlib
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from .runtime_hardening import atomic_write, evidence_refs, make_evidence_receipt, safe_target
except ImportError:
    from runtime_hardening import atomic_write, evidence_refs, make_evidence_receipt, safe_target

SENSITIVE_NAMES = {
    "password", "passwd", "pass", "token", "secret", "api-key", "api_key",
    "apikey", "api-secret", "api_secret", "client-secret", "client_secret",
    "credential", "credentials", "authorization", "auth-cred", "auth_cred",
    "key", "vt_key",
}


def _jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write(path, "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))


def _write_private(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write(path, value)


def _field(value: Any, maximum: int = 4096) -> str:
    """Render one bounded TSV field without allowing row injection."""
    return " ".join(str(value or "").replace("\x00", "").split())[:maximum]


def _safe_url(value: Any) -> str:
    """Preserve HTTP path/query names while removing credentials and values."""
    try:
        parsed = urlsplit(str(value or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        port = parsed.port
    except ValueError:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    display = f"[{host}]" if ":" in host else host
    default = 443 if parsed.scheme.lower() == "https" else 80
    netloc = display if port in {None, default} else f"{display}:{port}"
    names = sorted({name for name, _item in parse_qsl(parsed.query, keep_blank_values=True) if name})
    query = urlencode([(name, "") for name in names])
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))


def _event_evidence(root: Path, row: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("result_dir", "artifact", "plan", "stdout", "stderr", "console", "source"):
        raw = str(row.get(key, "") or "").strip()
        if not raw:
            continue
        candidate = Path(raw)
        full = candidate if candidate.is_absolute() else root / candidate
        try:
            if full.is_symlink():
                continue
            resolved = full.resolve()
            raw = str(resolved.relative_to(root.resolve()))
        except (OSError, ValueError):
            continue
        if not resolved.exists():
            continue
        values.append(_field(raw, 1024))
    return list(dict.fromkeys(value for value in values if value))


def _line_count(path: Path) -> int | None:
    try:
        count = 0
        last = b""
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                if b"\x00" in block:
                    return None
                count += block.count(b"\n")
                last = block[-1:]
        return count + (1 if path.stat().st_size and last != b"\n" else 0)
    except OSError:
        return None


def build_run_index(root: Path, target: str) -> dict[str, int]:
    """Build the human-facing V9 evidence projection from canonical artifacts.

    This is an index only: it performs no network work, does not reinterpret a
    scanner execution as a finding, and never copies secrets from query values.
    The existing checksum ledger remains the authoritative integrity seal.
    """
    root = Path(root)
    destination = root / "run-index"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)

    events = _jsonl(root / "module_status.jsonl")
    phase_lines = ["sequence\tengine\tcomponent\tstatus\tevidence"]
    coverage: dict[str, dict[str, int]] = {}
    for sequence, row in enumerate(events, 1):
        engine = _field(row.get("engine", "unknown"), 256) or "unknown"
        component = _field(
            row.get("stage") or row.get("capability") or row.get("runner")
            or row.get("module") or row.get("module_id") or "-",
            512,
        )
        status = _field(row.get("status", "unknown"), 64).lower() or "unknown"
        evidence = _event_evidence(root, row)
        phase_lines.append(f"{sequence}\t{engine}\t{component}\t{status}\t{','.join(evidence)}")
        counts = coverage.setdefault(engine, {})
        counts[status] = counts.get(status, 0) + 1
    _write_private(destination / "phase-index.tsv", "\n".join(phase_lines) + "\n")

    coverage_lines = ["engine\tevents\tsuccess\tpartial\tskipped\tplanned\ttimeout\tfailed\tother"]
    for engine, counts in sorted(coverage.items()):
        known = sum(counts.get(key, 0) for key in ("success", "partial", "skipped", "planned", "timeout", "failed"))
        total = sum(counts.values())
        coverage_lines.append("\t".join(str(value) for value in (
            engine,
            total,
            counts.get("success", 0),
            counts.get("partial", 0),
            counts.get("skipped", 0),
            counts.get("planned", 0),
            counts.get("timeout", 0),
            counts.get("failed", 0),
            total - known,
        )))
    _write_private(destination / "coverage-matrix.tsv", "\n".join(coverage_lines) + "\n")

    http_lines = ["status\torigin\tfinal_url\ttitle\tserver\ttechnologies\tsource"]
    status_urls: dict[int, set[str]] = {}
    http_sources: list[tuple[str, dict[str, Any]]] = [
        ("http-inventory/observed.jsonl", row)
        for row in _jsonl(root / "http-inventory" / "observed.jsonl")
    ]
    for phase in ("post-crawl", "post-content"):
        relative = f"http-reverification/{phase}.jsonl"
        http_sources.extend((relative, row) for row in _jsonl(root / relative))
    for source, row in http_sources:
        try:
            status = int(row.get("status", 0) or 0)
        except (TypeError, ValueError):
            status = 0
        status = status if 0 <= status <= 599 else 0
        origin = _safe_url(row.get("origin"))
        final_url = _safe_url(row.get("final_url"))
        technologies = row.get("technologies", [])
        if isinstance(technologies, list):
            technologies = ",".join(sorted({_field(value, 256) for value in technologies if _field(value, 256)}))
        http_lines.append("\t".join((
            str(status), origin, final_url, _field(row.get("title"), 1000),
            _field(row.get("server"), 512), _field(technologies, 2048),
            source,
        )))
        for value in (origin, final_url):
            if value:
                status_urls.setdefault(status, set()).add(value)
    _write_private(destination / "http-status-index.tsv", "\n".join(http_lines) + "\n")
    status_root = destination / "http-status"
    status_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for status, values in sorted(status_urls.items()):
        _write_private(status_root / f"{status}.urls.txt", "\n".join(sorted(values)) + "\n")

    output_lines = ["path\tbytes\tlines\ttype"]
    indexed_outputs = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or destination in path.parents:
            continue
        if path.name in {"checksums.sha256", "storage_inventory.tsv"}:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        lines = _line_count(path)
        kind = "text" if lines is not None else "binary"
        output_lines.append(f"{path.relative_to(root)}\t{size}\t{lines if lines is not None else '-'}\t{kind}")
        indexed_outputs += 1
    _write_private(destination / "output-index.tsv", "\n".join(output_lines) + "\n")

    summary = {
        "schema_version": 1,
        "target": _safe_url(target) or _field(target, 512),
        "events": len(events),
        "engines": len(coverage),
        "http_observations": len(http_sources),
        "http_status_buckets": len(status_urls),
        "indexed_outputs": indexed_outputs,
        "integrity_ledger": "checksums.sha256",
        "storage_inventory": "storage_inventory.tsv",
        "execution_receipts": "receipts/executions.jsonl",
    }
    _write_private(destination / "summary.json", json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    _write_private(
        destination / "README.txt",
        "Ah-Puch run evidence index\n"
        "\n"
        "Read in this order:\n"
        "1. summary.json\n"
        "2. coverage-matrix.tsv\n"
        "3. phase-index.tsv\n"
        "4. http-status-index.tsv and http-status/*.urls.txt\n"
        "5. output-index.tsv\n"
        "6. receipts/executions.jsonl\n"
        "7. checksums.sha256 and storage_inventory.tsv\n"
        "\n"
        "The index reports execution evidence; scanner execution alone is not a confirmed vulnerability.\n",
    )
    return {
        "events": len(events),
        "engines": len(coverage),
        "http_observations": len(http_sources),
        "http_status_buckets": len(status_urls),
        "indexed_outputs": indexed_outputs,
    }


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _nmap_services(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for path in root.rglob("*.xml"):
        # Nmap XML may come from the network profile runtime, the stable core,
        # or module wrappers. Parse files that actually contain an nmaprun root
        # rather than depending only on a historical directory name.
        try:
            tree = ET.parse(path)
        except (ET.ParseError, OSError):
            continue
        if tree.getroot().tag != "nmaprun":
            continue
        for host in tree.findall("host"):
            addresses = [item.attrib.get("addr", "") for item in host.findall("address") if item.attrib.get("addr")]
            names = [item.attrib.get("name", "") for item in host.findall("./hostnames/hostname") if item.attrib.get("name")]
            host_value = (names or addresses or [""])[0]
            if not host_value:
                continue
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                try:
                    number = int(port.attrib.get("portid", "0"))
                except ValueError:
                    continue
                protocol = port.attrib.get("protocol", "tcp")
                service = port.find("service")
                name = service.attrib.get("name", "") if service is not None else ""
                key = (host_value, protocol, number, name)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "host": host_value,
                    "protocol": protocol,
                    "port": number,
                    "service": name,
                    "product": service.attrib.get("product", "") if service is not None else "",
                    "version": service.attrib.get("version", "") if service is not None else "",
                    "source": str(path.relative_to(root)),
                })
    return sorted(rows, key=lambda row: (str(row["host"]), str(row["protocol"]), int(row["port"])))


def build_inventory(root: Path) -> dict[str, int]:
    destination = root / "inventory"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    graph = _jsonl(root / "graph" / "assets.jsonl")
    hosts = [row for row in graph if row.get("kind") in {"domain", "hostname", "ip", "cidr"}]
    urls = [row for row in graph if row.get("kind") in {"url", "origin"}]
    devices = _jsonl(root / "09-camera-surfaces" / "device-inventory.jsonl")
    http_rows = _jsonl(root / "http-inventory" / "observed.jsonl")
    services = _nmap_services(root)
    for device in devices:
        host = str(device.get("host", ""))
        port = device.get("port")
        if host and port:
            services.append({
                "host": host,
                "protocol": device.get("protocol", "tcp"),
                "port": port,
                "service": "device-surface",
                "models": device.get("models", []),
                "source": "09-camera-surfaces/device-inventory.jsonl",
            })
    advanced = _jsonl(root / "advanced-consumers" / "runs.jsonl")
    findings: list[dict[str, Any]] = []
    for row in advanced:
        if row.get("status") in {"success", "partial", "failed", "timeout"}:
            findings.append({
                "type": "consumer-execution",
                "runner": row.get("runner", ""),
                "origin": row.get("origin", ""),
                "status": row.get("status", ""),
                "exit_code": row.get("exit_code"),
                "artifacts": row.get("artifacts", []),
                "source": "advanced-consumers/runs.jsonl",
            })
    for row in http_rows:
        urls.append({
            "kind": "http-observation",
            "value": row.get("origin", ""),
            "status": row.get("status"),
            "final_url": row.get("final_url", ""),
            "server": row.get("server", row.get("httpx_server", "")),
            "title": row.get("title", row.get("httpx_title", "")),
            "technologies": row.get("technologies", []),
            "cdn": row.get("cdn_name", ""),
            "source": "http-inventory/observed.jsonl",
        })
    _write_jsonl(destination / "hosts.jsonl", hosts)
    _write_jsonl(destination / "urls.jsonl", urls)
    _write_jsonl(destination / "services.jsonl", services)
    _write_jsonl(destination / "devices.jsonl", devices)
    _write_jsonl(destination / "findings.jsonl", findings)
    summary = {
        "hosts": len(hosts),
        "urls": len(urls),
        "services": len(services),
        "devices": len(devices),
        "findings": len(findings),
    }
    summary_path = destination / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.chmod(0o600)
    return summary


def _runner_hashes(root: Path) -> dict[str, str]:
    path = root / "runner-registry" / "runners.json"
    if not path.is_file():
        return {}
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    result: dict[str, str] = {}
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict) and row.get("path") and row.get("sha256"):
                result[os.path.realpath(str(row["path"]))] = str(row["sha256"])
                result[Path(str(row["path"])).name] = str(row["sha256"])
    return result


def _hash_if_file(value: str, root: Path) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        return ""
    try:
        return _sha(resolved) if resolved.is_file() else ""
    except OSError:
        return ""


def _name(value: str) -> str:
    return value.strip().lstrip("-").lower().replace("_", "-")


def _redact_command(command: list[Any]) -> list[str]:
    result: list[str] = []
    redact_next = False
    for raw in command:
        token = str(raw)
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        if "=" in token:
            key, _value = token.split("=", 1)
            if _name(key) in {_name(value) for value in SENSITIVE_NAMES}:
                result.append(f"{key}=[REDACTED]")
                continue
        normalized = _name(token)
        if normalized in {_name(value) for value in SENSITIVE_NAMES}:
            result.append(token)
            redact_next = True
            continue
        if token.lower().startswith(("basic ", "bearer ")):
            result.append("[REDACTED-AUTHORIZATION]")
            continue
        result.append(token)
    return result


def build_receipts(root: Path, target: str) -> dict[str, int]:
    destination = root / "receipts"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    runner_hashes = _runner_hashes(root)
    # Preserve the validated configuration that produced the argv, so an
    # execution receipt can prove non-default TOOL.KEY propagation without
    # exposing arbitrary command-line input.  The manifest is local, sealed
    # run state and contains only parsed tool-option values.
    tool_options: dict[str, Any] = {}
    manifest = root / "manifest.json"
    if manifest.is_file():
        try:
            loaded = json.loads(manifest.read_text(encoding="utf-8"))
            if isinstance(loaded.get("tool_options"), dict):
                tool_options = loaded["tool_options"]
        except (OSError, json.JSONDecodeError):
            tool_options = {}
    events = _jsonl(root / "module_status.jsonl")
    extra = _jsonl(root / "advanced-consumers" / "runs.jsonl") + _jsonl(root / "network-profile-runtime" / "runs.jsonl")
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(events + extra, 1):
        command = row.get("command", [])
        if not isinstance(command, list):
            command = []
        redacted_command = _redact_command(command)
        command_text = json.dumps(redacted_command, ensure_ascii=False, separators=(",", ":"))
        executable = str(command[0]) if command else ""
        executable_key = os.path.realpath(executable) if executable else ""
        stdout = str(row.get("stdout", row.get("console", "")) or "")
        stderr = str(row.get("stderr", "") or "")
        artifact_paths: list[Path] = []
        for candidate in (stdout, stderr):
            if candidate:
                artifact_paths.append(Path(candidate) if Path(candidate).is_absolute() else root / candidate)
        result_dir = str(row.get("result_dir", "") or "")
        if result_dir:
            candidate = Path(result_dir) if Path(result_dir).is_absolute() else root / result_dir
            if candidate.is_file():
                artifact_paths.append(candidate)
        quality = make_evidence_receipt(
            root,
            target,
            producer=str(row.get("engine") or row.get("runner") or "runtime-event"),
            status=str(row.get("status", "")),
            artifacts=artifact_paths,
            command=redacted_command,
            metadata={"engine": row.get("engine", ""), "runner": row.get("runner", row.get("module", ""))},
        )
        receipt = {
            "schema_version": 1,
            "receipt_type": quality["receipt_type"],
            "producer": quality["producer"],
            "producer_version": quality["producer_version"],
            "target_ref": quality["target_ref"],
            "target_sha256": quality["target_sha256"],
            "started_at": quality["started_at"],
            "finished_at": quality["finished_at"],
            "scope": quality["scope"],
            "privacy": quality["privacy"],
            "artifacts": quality["artifacts"],
            "artifact_refs": quality["artifacts"],
            "command_sha256": quality["command_sha256"],
            "target": safe_target(target),
            "receipt_id": hashlib.sha256(f"{index}:{safe_target(target)}:{command_text}:{row.get('engine','')}:{row.get('runner','')}".encode()).hexdigest(),
            "engine": row.get("engine", ""),
            "runner": row.get("runner", row.get("module", "")),
            "status": row.get("status", ""),
            "exit_code": row.get("exit_code"),
            "timed_out": bool(row.get("timed_out", False) or row.get("status") == "timeout"),
            "duration": row.get("duration"),
            "command": redacted_command,
            "argv_sha256": hashlib.sha256(command_text.encode()).hexdigest() if redacted_command else "",
            "executable_sha256": runner_hashes.get(executable_key, runner_hashes.get(Path(executable).name if executable else "", "")),
            "stdout_sha256": _hash_if_file(stdout, root),
            "stderr_sha256": _hash_if_file(stderr, root),
            "result_dir": row.get("result_dir", ""),
            "source": row.get("source", "runtime-event"),
            "tool_options": tool_options,
        }
        rows.append(receipt)
    _write_jsonl(destination / "executions.jsonl", rows)
    summary = {"schema_version": 1, "receipt_type": "execution-evidence-index", "receipts": len(rows)}
    path = destination / "summary.json"
    atomic_write(path, json.dumps(summary, indent=2) + "\n")
    return summary
