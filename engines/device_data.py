#!/usr/bin/env python3
"""Normalize externally supplied device data into a private native artifact.

The importer deliberately records content hashes instead of source file paths.
This keeps exported evidence reproducible without leaking workstation layout.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


FORMAT_VERSION = 1
ARTIFACT_KIND = "ah-puch-device-data"
_KINDS = {"fingerprint", "device", "port", "path"}
_MATCH_ALIASES = {
    "any": "any",
    "single": "single",
    "all": "all",
    "response-length": "response-length",
    "response_length": "response-length",
    "response-lines": "response-lines",
    "response_lines": "response-lines",
}
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")


class DeviceDataError(ValueError):
    """Raised when a source cannot be normalized without ambiguity."""


def _text(value: Any, field: str, *, required: bool = False, limit: int = 512) -> str:
    if value is None:
        value = ""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise DeviceDataError(f"{field} must be text")
    result = str(value).strip()
    if required and not result:
        raise DeviceDataError(f"{field} is required")
    if "\x00" in result or "\r" in result or "\n" in result:
        raise DeviceDataError(f"{field} contains a control character")
    if len(result) > limit:
        raise DeviceDataError(f"{field} exceeds {limit} characters")
    return result


def _provenance_label(value: str) -> str:
    label = _text(value, "provenance_label", required=True, limit=256)
    expanded = os.path.expanduser(label)
    parsed = urlsplit(label)
    if (
        label.startswith(("/", "~/", "./", "../", "\\\\"))
        or _WINDOWS_ABSOLUTE.match(label)
        or parsed.scheme.casefold() == "file"
        or os.path.isabs(expanded)
    ):
        raise DeviceDataError("provenance_label must be a logical label, not a local path")
    return label


def _signals(value: Any) -> list[str]:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise DeviceDataError("signals contains invalid JSON") from exc
        else:
            value = [part.strip() for part in stripped.split("|")]
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        raise DeviceDataError("signals must be a string or list")
    result = [_text(item, "signal", required=True, limit=4096) for item in value]
    result = list(dict.fromkeys(result))
    if not result:
        raise DeviceDataError("fingerprint requires at least one signal")
    return result


def _fingerprint(row: Mapping[str, Any]) -> dict[str, Any]:
    model = _text(row.get("model"), "model", required=True)
    signals = _signals(row.get("signals", row.get("signal", [])))
    requested = _text(row.get("match", "single"), "match", required=True).casefold()
    try:
        match = _MATCH_ALIASES[requested]
    except KeyError as exc:
        raise DeviceDataError(f"unsupported fingerprint match mode: {requested}") from exc
    if requested == "single" and len(signals) != 1:
        raise DeviceDataError("single match mode requires exactly one signal")

    result: dict[str, Any] = {"model": model, "signals": signals, "match": match}
    for field in ("vendor", "type", "version"):
        value = _text(row.get(field, ""), field)
        if value:
            result[field] = value
    if match == "response-lines":
        raw = row.get("response_lines", row.get("lines"))
        if isinstance(raw, bool):
            raise DeviceDataError("response_lines must be a non-negative integer")
        try:
            lines = int(raw)
        except (TypeError, ValueError) as exc:
            raise DeviceDataError("response_lines must be a non-negative integer") from exc
        if lines < 0:
            raise DeviceDataError("response_lines must be a non-negative integer")
        result["response_lines"] = lines
    elif match == "response-length":
        exact = row.get("response_bytes", row.get("response_length"))
        lower = row.get("response_bytes_min", exact)
        upper = row.get("response_bytes_max", exact)
        if isinstance(lower, bool) or isinstance(upper, bool):
            raise DeviceDataError("response length must use non-negative byte counts")
        try:
            minimum, maximum = int(lower), int(upper)
        except (TypeError, ValueError) as exc:
            raise DeviceDataError("response length must use non-negative byte counts") from exc
        if minimum < 0 or maximum < minimum:
            raise DeviceDataError("response length range is invalid")
        result["response_bytes_min"] = minimum
        result["response_bytes_max"] = maximum
    return result


def _device(row: Mapping[str, Any]) -> dict[str, str]:
    result = {
        field: _text(row.get(field, ""), field, required=field == "model")
        for field in ("vendor", "model", "type", "version")
    }
    if not any(result[field] for field in ("vendor", "type", "version")):
        raise DeviceDataError("device metadata requires vendor, type, or version")
    return result


def _port(value: Any) -> int:
    if isinstance(value, Mapping):
        value = value.get("port")
    if isinstance(value, bool):
        raise DeviceDataError("port must be an integer from 1 to 65535")
    if isinstance(value, str):
        value = value.strip()
        if not value.isdigit():
            raise DeviceDataError("port must be an integer from 1 to 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise DeviceDataError("port must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise DeviceDataError("port must be an integer from 1 to 65535")
    return port


def _path_candidate(value: Any) -> str:
    if isinstance(value, Mapping):
        value = value.get("path")
    candidate = _text(value, "path", required=True, limit=2048)
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc or not candidate.startswith("/") or candidate.startswith("//"):
        raise DeviceDataError("path candidate must be an origin-relative URL path")
    if any(part == ".." for part in parsed.path.split("/")):
        raise DeviceDataError("path candidate may not contain parent traversal")
    return candidate


def _records_from_object(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict) and _text(raw.get("kind", ""), "kind") in _KINDS:
        records = [raw]
    elif isinstance(raw, dict):
        records = []
        collections = (
            ("fingerprint", raw.get("fingerprints", raw.get("fingerprint_rules", []))),
            ("device", raw.get("devices", raw.get("device_metadata", []))),
            ("port", raw.get("ports", [])),
            ("path", raw.get("paths", raw.get("path_candidates", []))),
        )
        for kind, values in collections:
            if values is None:
                continue
            if not isinstance(values, list):
                raise DeviceDataError(f"{kind} collection must be a list")
            for value in values:
                record = dict(value) if isinstance(value, Mapping) else {kind: value}
                record["kind"] = kind
                records.append(record)
    else:
        raise DeviceDataError("source root must be an object or list")
    if any(not isinstance(record, Mapping) for record in records):
        raise DeviceDataError("each source record must be an object")
    return [dict(record) for record in records]


def _read_source(path: Path) -> tuple[list[dict[str, Any]], str]:
    suffix = path.suffix.casefold()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DeviceDataError(f"unable to read source: {path.name}") from exc
    if suffix == ".json":
        try:
            return _records_from_object(json.loads(text)), "application/json"
        except json.JSONDecodeError as exc:
            raise DeviceDataError(f"invalid JSON source: {path.name}") from exc
    if suffix == ".jsonl":
        rows: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.extend(_records_from_object(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise DeviceDataError(f"invalid JSONL at line {line_number}") from exc
        return rows, "application/x-ndjson"
    if suffix == ".tsv":
        reader = csv.DictReader(text.splitlines(), delimiter="\t")
        if not reader.fieldnames or "kind" not in reader.fieldnames:
            raise DeviceDataError("TSV source requires a kind header")
        return [dict(row) for row in reader], "text/tab-separated-values"
    raise DeviceDataError("source extension must be .json, .jsonl, or .tsv")


def _normalize_records(records: Iterable[Mapping[str, Any]]) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = {"fingerprints": [], "devices": [], "ports": [], "paths": []}
    for row in records:
        kind = _text(row.get("kind", ""), "kind", required=True).casefold()
        if kind == "fingerprint":
            result["fingerprints"].append(_fingerprint(row))
        elif kind == "device":
            result["devices"].append(_device(row))
        elif kind == "port":
            result["ports"].append(_port(row.get("port")))
        elif kind == "path":
            result["paths"].append(_path_candidate(row.get("path")))
        else:
            raise DeviceDataError(f"unsupported record kind: {kind}")

    for key in ("fingerprints", "devices"):
        unique = {json.dumps(value, ensure_ascii=False, sort_keys=True): value for value in result[key]}
        result[key] = [unique[token] for token in sorted(unique)]
    result["ports"] = sorted(set(result["ports"]))
    result["paths"] = sorted(set(result["paths"]))
    return result


def _artifact_collection(raw: Mapping[str, Any], field: str) -> list[Any]:
    value = raw.get(field, [])
    if not isinstance(value, list):
        raise DeviceDataError(f"artifact {field} must be a list")
    return value


def _validate_artifact(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DeviceDataError("artifact must be an object")
    if raw.get("format") != FORMAT_VERSION or raw.get("kind") != ARTIFACT_KIND:
        raise DeviceDataError("unsupported device data artifact")
    provenance = raw.get("provenance")
    if not isinstance(provenance, dict):
        raise DeviceDataError("artifact provenance is missing")
    label = _provenance_label(provenance.get("label", ""))
    sources = provenance.get("sources")
    if not isinstance(sources, list) or not sources:
        raise DeviceDataError("artifact source hashes are missing")
    clean_sources: list[dict[str, str]] = []
    for source in sources:
        if not isinstance(source, dict):
            raise DeviceDataError("artifact source entry must be an object")
        digest = _text(source.get("sha256", ""), "sha256", required=True).casefold()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise DeviceDataError("artifact source hash must be SHA-256")
        media_type = _text(source.get("media_type", ""), "media_type", required=True)
        clean_sources.append({"sha256": digest, "media_type": media_type})

    fingerprint_values = _artifact_collection(raw, "fingerprints")
    device_values = _artifact_collection(raw, "devices")
    if any(not isinstance(value, Mapping) for value in fingerprint_values + device_values):
        raise DeviceDataError("artifact fingerprint and device entries must be objects")
    normalized = _normalize_records(
        [dict(value, kind="fingerprint") for value in fingerprint_values]
        + [dict(value, kind="device") for value in device_values]
        + [{"kind": "port", "port": value} for value in _artifact_collection(raw, "ports")]
        + [{"kind": "path", "path": value} for value in _artifact_collection(raw, "paths")]
    )
    return {
        "format": FORMAT_VERSION,
        "kind": ARTIFACT_KIND,
        "provenance": {"label": label, "sources": clean_sources},
        **normalized,
    }


def load_device_data(path: Path | str) -> dict[str, Any]:
    """Load and validate a normalized artifact for device-engine consumers."""
    candidate = Path(path)
    try:
        raw = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeviceDataError("unable to read normalized device data") from exc
    return _validate_artifact(raw)


def import_device_data(
    sources: Iterable[Path | str],
    destination: Path | str,
    *,
    provenance_label: str,
) -> dict[str, Any]:
    """Import JSON, JSONL, or TSV sources and atomically write a 0600 artifact."""
    label = _provenance_label(provenance_label)
    paths = [Path(source) for source in sources]
    if not paths:
        raise DeviceDataError("at least one source is required")

    records: list[dict[str, Any]] = []
    source_rows: list[dict[str, str]] = []
    for source in paths:
        parsed, media_type = _read_source(source)
        records.extend(parsed)
        try:
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as exc:
            raise DeviceDataError(f"unable to hash source: {source.name}") from exc
        source_rows.append({"sha256": digest, "media_type": media_type})

    if not records:
        raise DeviceDataError("sources contain no device data records")

    normalized = _normalize_records(records)
    artifact = {
        "format": FORMAT_VERSION,
        "kind": ARTIFACT_KIND,
        "provenance": {
            "label": label,
            "sources": sorted(source_rows, key=lambda row: (row["sha256"], row["media_type"])),
        },
        **normalized,
    }
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=target.parent, prefix=f".{target.name}.", delete=False
        ) as handle:
            temporary_name = handle.name
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        target.chmod(0o600)
    except OSError as exc:
        if temporary_name:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise DeviceDataError("unable to write normalized device data") from exc
    return artifact


def fingerprint_rules(artifact: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return rules in the shape consumed by ``camera_surface``."""
    return [dict(value) for value in artifact.get("fingerprints", [])]


def service_ports(artifact: Mapping[str, Any]) -> set[int]:
    """Return validated ports in the shape consumed by device discovery."""
    return {_port(value) for value in artifact.get("ports", [])}


def path_candidates(artifact: Mapping[str, Any]) -> list[str]:
    """Return validated origin-relative paths for bounded HTTP probes."""
    return [_path_candidate(value) for value in artifact.get("paths", [])]
