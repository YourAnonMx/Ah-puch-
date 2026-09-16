#!/usr/bin/env python3
"""Bounded HTTP re-observation for URLs discovered during web fan-out.

Discovery evidence and HTTP response evidence are deliberately separate.  This
module accepts only target-eligible canonical URLs and reuses the canonical
HTTP probe (including its redirect guard), and writes a private phase ledger.
It never treats an HTTP status or a successful request as a vulnerability.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from . import artifact_bus, http_inventory
    from .runner_registry import admitted_path, run_bounded
except ImportError:
    import artifact_bus
    import http_inventory
    from runner_registry import admitted_path, run_bounded

PHASES = frozenset({"initial", "post-crawl", "post-content"})
VERIFIERS = ("native", "wget", "curl", "httpx")
VERIFIER_RUNNERS = {"wget": "wget", "curl": "http_client", "httpx": "http_probe"}
_HTTP_STATUS_RE = re.compile(r"\b(?:HTTP/\S+\s+)?([1-5]\d\d)\b")
_SAFE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "server",
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    }
)


def _write_private(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def _text(value: Any, limit: int = 2048) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _safe_redirects(value: object) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not isinstance(value, list):
        return rows
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            status = int(item.get("status", 0) or 0)
        except (TypeError, ValueError):
            status = 0
        rows.append(
            {
                "status": status if 0 <= status <= 599 else 0,
                "from": artifact_bus.canonical_url(str(item.get("from", ""))),
                "to": artifact_bus.canonical_url(str(item.get("to", ""))),
                "allowed": bool(item.get("allowed", False)),
            }
        )
    return rows


def _safe_probe_row(phase: str, requested: str, value: object, verifier: str = "native") -> dict[str, Any]:
    row = value if isinstance(value, dict) else {}
    try:
        status = int(row.get("status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    status = status if 0 <= status <= 599 else 0
    headers = row.get("headers", {}) if isinstance(row.get("headers"), dict) else {}
    safe_headers = {
        str(key).lower(): _text(item, 2048)
        for key, item in headers.items()
        if str(key).lower() in _SAFE_HEADERS
    }
    server = _text(row.get("server") or safe_headers.get("server", ""), 512)
    technologies = row.get("technologies", [])
    if not isinstance(technologies, list):
        technologies = []
    return {
        "schema_version": 1,
        "phase": phase,
        "verifier": verifier,
        "requested_url": requested,
        "origin": artifact_bus.canonical_url(str(row.get("origin", ""))) or requested,
        "status": status,
        "final_url": artifact_bus.canonical_url(str(row.get("final_url", ""))) or requested,
        "redirects": _safe_redirects(row.get("redirects")),
        "title": _text(row.get("title"), 1000),
        "server": server,
        "content_type": _text(row.get("content_type") or safe_headers.get("content-type", ""), 512),
        "content_length": _text(safe_headers.get("content-length", ""), 64),
        "body_sha256": _text(row.get("body_sha256"), 128),
        "bytes_sampled": int(row.get("bytes_sampled", 0) or 0),
        "elapsed_ms": float(row.get("elapsed_ms", 0) or 0),
        "technologies": sorted({_text(item, 256) for item in technologies if _text(item, 256)}),
        "technology_source": _text(row.get("technology_source"), 256),
        "security_headers": row.get("security_headers", {}) if isinstance(row.get("security_headers"), dict) else {},
        "headers": safe_headers,
        "error": _text(row.get("error"), 2048),
    }


def _selected_verifiers(value: str) -> tuple[str, ...]:
    verifier = str(value or "native").strip().lower()
    if verifier == "all":
        return VERIFIERS
    if verifier not in VERIFIERS:
        raise ValueError(f"unsupported HTTP verifier: {value}")
    return (verifier,)


def _phase_status(
    rows: list[dict[str, Any]],
    expected_observations: int,
    active: bool,
    unavailable_observations: int = 0,
) -> str:
    if not active or expected_observations == 0:
        return "skipped"
    if unavailable_observations >= expected_observations and not rows:
        return "unavailable"
    completed = sum(1 for row in rows if int(row.get("status", 0) or 0) > 0)
    transport_errors = len(rows) - completed
    missing = max(0, expected_observations - len(rows) - unavailable_observations)
    if completed and (transport_errors or unavailable_observations or missing):
        return "partial"
    if completed:
        return "success"
    if rows or unavailable_observations:
        return "failed"
    return "failed"


def _safe_read(path: Path, limit: int = 5_000_000) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _command_error(text: str, receipt: dict[str, Any]) -> str:
    if int(receipt.get("exit_code", 1)) == 0:
        return ""
    sample = _text(text, 512)
    if sample:
        return sample
    return f"exit-code:{receipt.get('exit_code', 1)}"


def _curl_row(phase: str, requested: str, text: str, receipt: dict[str, Any]) -> dict[str, Any]:
    status = 0
    final_url = requested
    for line in text.splitlines():
        fields = line.split("\t")
        if fields and fields[0].isdigit():
            status = int(fields[0])
            if len(fields) > 1:
                final_url = artifact_bus.canonical_url(fields[1]) or requested
    return _safe_probe_row(
        phase,
        requested,
        {
            "origin": requested,
            "status": status,
            "final_url": final_url,
            "headers": {},
            "error": "" if status else _command_error(text, receipt),
        },
        "curl",
    )


def _wget_row(phase: str, requested: str, text: str, receipt: dict[str, Any]) -> dict[str, Any]:
    statuses = [int(value) for value in _HTTP_STATUS_RE.findall(text)]
    status = statuses[-1] if statuses else 0
    return _safe_probe_row(
        phase,
        requested,
        {
            "origin": requested,
            "status": status,
            "final_url": requested,
            "headers": {},
            "error": "" if status else _command_error(text, receipt),
        },
        "wget",
    )


def _httpx_rows(
    root: Path,
    phase: str,
    urls: list[str],
    binary: str,
    timeout: int,
) -> list[dict[str, Any]]:
    destination = Path(root) / "http-reverification" / "raw"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    input_path = destination / f"{phase}.httpx.inputs.txt"
    _write_private(input_path, "\n".join(urls) + ("\n" if urls else ""))
    stdout = destination / f"{phase}.httpx.stdout.txt"
    stderr = destination / f"{phase}.httpx.stderr.txt"
    command = [
        binary, "-silent", "-json", "-status-code", "-title",
        "-server", "-tech-detect", "-l", str(input_path),
    ]
    receipt = run_bounded(command, destination, stdout, stderr, timeout, stdin_path=None)
    text = _safe_read(stdout) + "\n" + _safe_read(stderr)
    rows: list[dict[str, Any]] = []
    observed: set[str] = set()
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        requested = artifact_bus.canonical_url(str(item.get("input") or item.get("url") or ""))
        if not requested:
            continue
        observed.add(requested)
        rows.append(
            _safe_probe_row(
                phase,
                requested,
                {
                    "origin": requested,
                    "status": int(item.get("status_code", item.get("status", 0)) or 0),
                    "final_url": artifact_bus.canonical_url(str(item.get("final_url") or item.get("url") or requested)) or requested,
                    "headers": {},
                    "title": item.get("title", ""),
                    "server": item.get("webserver", item.get("server", "")),
                    "technologies": item.get("tech", []) if isinstance(item.get("tech", []), list) else [],
                    "technology_source": "httpx",
                    "error": "",
                },
                "httpx",
            )
        )
    missing_error = _command_error(text, receipt) or "httpx produced no row for URL"
    for url in urls:
        if url not in observed:
            rows.append(
                _safe_probe_row(
                    phase,
                    url,
                    {"origin": url, "status": 0, "final_url": url, "headers": {}, "error": missing_error},
                    "httpx",
                )
            )
    return rows


def _external_rows(
    root: Path,
    phase: str,
    urls: list[str],
    verifier: str,
    timeout: int,
) -> tuple[list[dict[str, Any]], str]:
    runner_id = VERIFIER_RUNNERS[verifier]
    binary = admitted_path(runner_id)
    if not binary:
        return [], "runner contract unavailable"
    if verifier == "httpx":
        return _httpx_rows(root, phase, urls, binary, timeout), ""
    destination = Path(root) / "http-reverification" / "raw"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows: list[dict[str, Any]] = []
    for index, url in enumerate(urls, start=1):
        stdout = destination / f"{phase}.{verifier}.{index:04d}.stdout.txt"
        stderr = destination / f"{phase}.{verifier}.{index:04d}.stderr.txt"
        if verifier == "wget":
            command = [
                binary, "--server-response", "--spider", "--max-redirect=0",
                f"--timeout={max(1, timeout)}", "--tries=1", "--no-verbose", url,
            ]
        elif verifier == "curl":
            command = [
                binary, "--silent", "--show-error", "--max-redirs", "0",
                "--max-time", str(max(1, timeout)), "--output", "/dev/null",
                "--write-out", "%{http_code}\t%{url_effective}\t%{redirect_url}\n", url,
            ]
        else:  # defensive; caller validates verifier before dispatch.
            raise ValueError(f"unsupported external HTTP verifier: {verifier}")
        receipt = run_bounded(command, destination, stdout, stderr, timeout, stdin_path=None)
        text = _safe_read(stdout) + "\n" + _safe_read(stderr)
        rows.append(_curl_row(phase, url, text, receipt) if verifier == "curl" else _wget_row(phase, url, text, receipt))
    return rows, ""


def _write_status_artifacts(
    root: Path,
    phase: str,
    rows: list[dict[str, Any]],
    rejected_urls: list[str],
) -> dict[str, str]:
    """Write human status queues for one phase plus cumulative HTTP ledgers."""
    destination = Path(root) / "http-reverification"
    verified = [
        str(row.get("final_url") or row.get("requested_url"))
        for row in rows
        if int(row.get("status", 0) or 0) == 200
    ]
    non_200 = [
        f"{int(row.get('status', 0) or 0)}\t{row.get('requested_url', '')}\t{row.get('final_url', '')}\t{row.get('error', '')}"
        for row in rows
        if int(row.get("status", 0) or 0) != 200
    ]
    redirects = ["status\tfrom\tto\tallowed"]
    for row in rows:
        for item in row.get("redirects", []) if isinstance(row.get("redirects"), list) else []:
            redirects.append(
                f"{int(item.get('status', 0) or 0)}\t{item.get('from', '')}\t{item.get('to', '')}\t{str(bool(item.get('allowed', False))).lower()}"
            )
    paths = {
        "verified_200": destination / f"{phase}.verified_200_urls.txt",
        "non_200": destination / f"{phase}.non_200_urls.txt",
        "redirects": destination / f"{phase}.redirects.tsv",
        "rejected": destination / f"{phase}.rejected_urls.txt",
    }
    _write_private(paths["verified_200"], "\n".join(sorted(set(verified))) + ("\n" if verified else ""))
    _write_private(paths["non_200"], "\n".join(non_200) + ("\n" if non_200 else ""))
    _write_private(paths["redirects"], "\n".join(redirects) + "\n")
    _write_private(paths["rejected"], "\n".join(sorted(set(rejected_urls))) + ("\n" if rejected_urls else ""))

    all_rows: list[dict[str, Any]] = []
    for ledger in sorted(destination.glob("*.jsonl")):
        if ledger.name.count(".") != 1:
            continue
        for line in ledger.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                all_rows.append(item)
    cumulative_verified = sorted(
        {
            str(row.get("final_url") or row.get("requested_url"))
            for row in all_rows
            if int(row.get("status", 0) or 0) == 200
        }
    )
    cumulative_non_200 = [
        f"{int(row.get('status', 0) or 0)}\t{row.get('requested_url', '')}\t{row.get('final_url', '')}\t{row.get('phase', '')}\t{row.get('error', '')}"
        for row in sorted(all_rows, key=lambda item: (str(item.get("phase", "")), str(item.get("requested_url", ""))))
        if int(row.get("status", 0) or 0) != 200
    ]
    _write_private(destination / "verified_200_urls.txt", "\n".join(cumulative_verified) + ("\n" if cumulative_verified else ""))
    _write_private(destination / "non_200_urls.txt", "\n".join(cumulative_non_200) + ("\n" if cumulative_non_200 else ""))
    return {key: str(path.relative_to(root)) for key, path in paths.items()}


def run_phase(
    root: Path,
    phase: str,
    candidates: Iterable[str],
    *,
    active: bool,
    timeout: int,
    threads: int,
    limit: int,
    allow_url: Callable[[str], bool],
    verifier: str = "native",
) -> dict[str, Any]:
    """Re-observe one bounded, already-discovered URL queue."""
    if phase not in PHASES:
        raise ValueError(f"unsupported HTTP reverification phase: {phase}")
    selected = _selected_verifiers(verifier)
    accepted: list[str] = []
    rejected_urls: list[str] = []
    seen: set[str] = set()
    for raw in candidates:
        canonical = artifact_bus.canonical_url(str(raw))
        if not canonical or not allow_url(canonical):
            rejected_urls.append(canonical or "[invalid-url]")
            continue
        if canonical not in seen:
            seen.add(canonical)
            accepted.append(canonical)
    accepted.sort()
    bounded = accepted[: max(0, int(limit))]
    rows: list[dict[str, Any]] = []
    technology_by_origin: dict[str, list[str]] = {}
    inventory_path = Path(root) / "http-inventory" / "observed.jsonl"
    if inventory_path.is_file() and not inventory_path.is_symlink():
        for line in inventory_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or not isinstance(item.get("technologies"), list):
                continue
            origin = artifact_bus.canonical_origin(str(item.get("final_url") or item.get("origin") or ""))
            if origin:
                technology_by_origin[origin] = list(item["technologies"])
    unavailable: dict[str, str] = {}
    if active and bounded and "native" in selected:
        workers = max(1, min(int(threads), 16, len(bounded)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    http_inventory._timed_probe,
                    url,
                    url,
                    "authority",
                    max(1, min(int(timeout), 30)),
                    allow_url,
                ): url
                for url in bounded
            }
            for future in as_completed(futures):
                requested = futures[future]
                try:
                    value = future.result()
                except Exception as exc:  # defensive boundary around the canonical probe
                    value = {
                        "origin": requested,
                        "status": 0,
                        "final_url": requested,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                origin = artifact_bus.canonical_origin(requested)
                if origin and technology_by_origin.get(origin):
                    value["technologies"] = technology_by_origin[origin]
                    value["technology_source"] = "http-inventory/observed.jsonl"
                rows.append(_safe_probe_row(phase, requested, value, "native"))
    if active and bounded:
        for selected_verifier in selected:
            if selected_verifier == "native":
                continue
            verifier_rows, reason = _external_rows(Path(root), phase, bounded, selected_verifier, max(1, min(int(timeout), 30)))
            rows.extend(verifier_rows)
            if reason:
                unavailable[selected_verifier] = reason
    rows.sort(key=lambda row: str(row["requested_url"]))
    unavailable_observations = len(bounded) * len(unavailable)
    status = _phase_status(rows, len(bounded) * len(selected), active, unavailable_observations)
    destination = Path(root) / "http-reverification"
    ledger = destination / f"{phase}.jsonl"
    summary_path = destination / f"{phase}.summary.json"
    _write_private(ledger, "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows))
    status_artifacts = _write_status_artifacts(Path(root), phase, rows, rejected_urls)
    status_counts: dict[str, int] = {}
    for row in rows:
        key = str(int(row.get("status", 0) or 0))
        status_counts[key] = status_counts.get(key, 0) + 1
    summary = {
        "schema_version": 1,
        "phase": phase,
        "status": status,
        "active": bool(active),
        "candidates": len(accepted),
        "queued": len(bounded),
        "rejected_out_of_scope_or_invalid": len(rejected_urls),
        "limited_out": max(0, len(accepted) - len(bounded)),
        "observed": len(rows),
        "transport_errors": sum(1 for row in rows if int(row.get("status", 0) or 0) == 0),
        "http_statuses": dict(sorted(status_counts.items(), key=lambda item: int(item[0]))),
        "ledger": str(ledger.relative_to(root)),
        "verifier": str(verifier or "native").strip().lower(),
        "verifiers": list(selected),
        "unavailable_verifiers": unavailable,
        "artifacts": status_artifacts,
    }
    _write_private(summary_path, json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return summary
