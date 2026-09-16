"""Deterministic, offline advisory ingestion and product/version matching.

This module deliberately has no network or command-execution surface. Updating
the store is an explicit local-file operation; looking up an observed product is
a separate read-only operation suitable for use by a live scan path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


SCHEMA_VERSION = 1
MAX_SOURCE_BYTES = 64 * 1024 * 1024
ADVISORY_FIELDS = {
    "id",
    "year",
    "vendor",
    "product",
    "version_constraint",
    "severity",
    "cvss",
    "references",
    "provenance",
    "updated",
}
SEVERITIES = {"unknown", "info", "low", "medium", "high", "critical"}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
CVE_RE = re.compile(r"^CVE-(\d{4})-\d{4,}$", re.IGNORECASE)


@dataclass(frozen=True)
class ImportResult:
    destination: Path
    source_sha256: str
    advisories_sha256: str
    record_count: int


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _single_line(value: Any, field: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > maximum:
        raise ValueError(f"{field} must contain 1-{maximum} printable characters")
    return cleaned


def _timestamp(value: Any) -> str:
    raw = _single_line(value, "updated", maximum=64)
    candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("updated must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("updated must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _constraint(value: Any) -> str:
    raw = _single_line(value, "version_constraint", maximum=512)
    if raw == "*":
        return raw
    try:
        parsed = SpecifierSet(raw)
    except InvalidSpecifier as exc:
        raise ValueError(f"invalid version_constraint: {raw}") from exc
    if not str(parsed):
        raise ValueError("version_constraint must not be empty")
    return str(parsed)


def _references(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("references must be a list")
    result: set[str] = set()
    for item in value:
        reference = _single_line(item, "reference", maximum=2048)
        parsed = urlsplit(reference)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("references must contain credential-free HTTP(S) URLs")
        result.add(reference)
    return sorted(result)


def _provenance(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = {"source": value}
    if not isinstance(value, Mapping):
        raise ValueError("provenance must be a string or object")
    if "source" not in value:
        raise ValueError("provenance.source is required")
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        name = _single_line(key, "provenance key", maximum=64)
        if isinstance(item, str):
            normalized[name] = _single_line(item, f"provenance.{name}", maximum=2048)
        elif isinstance(item, (int, float, bool)) or item is None:
            normalized[name] = item
        else:
            raise ValueError(f"provenance.{name} must be a JSON scalar")
    normalized["source"] = _single_line(normalized["source"], "provenance.source", maximum=256)
    return dict(sorted(normalized.items()))


def _normalize_record(value: Any, source_sha256: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("each advisory must be an object")
    unknown = set(value) - ADVISORY_FIELDS
    missing = ADVISORY_FIELDS - set(value)
    if unknown:
        raise ValueError(f"unknown advisory fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"missing advisory fields: {', '.join(sorted(missing))}")

    advisory_id = _single_line(value["id"], "id", maximum=128).upper()
    if not ID_RE.fullmatch(advisory_id):
        raise ValueError("id contains unsupported characters")
    year = value["year"]
    if type(year) is not int or not 1900 <= year <= 9999:
        raise ValueError("year must be an integer from 1900 through 9999")
    cve = CVE_RE.fullmatch(advisory_id)
    if cve and int(cve.group(1)) != year:
        raise ValueError("CVE id year does not match year")

    severity = _single_line(value["severity"], "severity", maximum=16).lower()
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")
    cvss = value["cvss"]
    if isinstance(cvss, bool) or not isinstance(cvss, (int, float)) or not 0 <= float(cvss) <= 10:
        raise ValueError("cvss must be a number from 0 through 10")

    return {
        "id": advisory_id,
        "year": year,
        "vendor": _single_line(value["vendor"], "vendor"),
        "product": _single_line(value["product"], "product"),
        "version_constraint": _constraint(value["version_constraint"]),
        "severity": severity,
        "cvss": float(cvss),
        "references": _references(value["references"]),
        "provenance": _provenance(value["provenance"]),
        "updated": _timestamp(value["updated"]),
        "source_sha256": source_sha256,
    }


def _parse_source(raw: bytes, suffix: str) -> list[Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("advisory source must be UTF-8") from exc
    try:
        if suffix == ".jsonl":
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid advisory JSON: {exc}") from exc
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and set(value) == {"advisories"} and isinstance(value["advisories"], list):
        return value["advisories"]
    raise ValueError("JSON source must be a list or an object containing only 'advisories'")


def _product_key(vendor: str, product: str) -> tuple[str, str]:
    normalize = lambda item: " ".join(item.casefold().replace("_", " ").replace("-", " ").split())
    return normalize(vendor), normalize(product)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _product_index(rows: Iterable[Mapping[str, Any]], source_sha256: str) -> dict[str, Any]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        grouped.setdefault(_product_key(str(row["vendor"]), str(row["product"])), []).append(str(row["id"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "source_sha256": source_sha256,
        "products": [
            {"vendor": key[0], "product": key[1], "advisory_ids": sorted(ids)}
            for key, ids in sorted(grouped.items())
        ],
    }


def _write_private(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass
        raise


def import_advisory_file(source: str | Path, destination: str | Path) -> ImportResult:
    """Replace an offline store from a local JSON or JSONL file.

    The function never accepts a URL, opens a socket, imports source code, or
    executes data from the source. The source is fully parsed and validated
    before any store file is replaced. ``manifest.json`` is written last and is
    the commit marker for the data/index generation.
    """

    source_path = Path(source).expanduser()
    destination_path = Path(destination).expanduser()
    if "://" in str(source):
        raise ValueError("advisory updates require a local JSON or JSONL file")
    if source_path.suffix.lower() not in {".json", ".jsonl"}:
        raise ValueError("advisory source must use .json or .jsonl")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    source_resolved = source_path.resolve()
    destination_resolved = destination_path.resolve()
    if destination_resolved == source_resolved or destination_resolved in source_resolved.parents:
        raise ValueError("advisory source must be separate from the store directory")
    size = source_path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"advisory source exceeds {MAX_SOURCE_BYTES} bytes")
    raw = source_path.read_bytes()
    source_digest = _sha256(raw)
    records = [_normalize_record(item, source_digest) for item in _parse_source(raw, source_path.suffix.lower())]
    records.sort(key=lambda row: (row["id"], row["vendor"].casefold(), row["product"].casefold()))
    identifiers = [row["id"] for row in records]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("advisory ids must be unique")

    jsonl = b"".join(_canonical_json(row) for row in records)
    index = _product_index(records, source_digest)
    index_bytes = _canonical_json(index)
    data_digest = _sha256(jsonl)
    index_digest = _sha256(index_bytes)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_sha256": source_digest,
        "advisories_sha256": data_digest,
        "index_sha256": index_digest,
        "record_count": len(records),
    }

    destination_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_private(destination_path / "advisories.jsonl", jsonl)
    _write_private(destination_path / "index.json", index_bytes)
    # Commit marker: readers reject any interrupted generation whose old
    # manifest no longer matches the new data or index.
    _write_private(destination_path / "manifest.json", _canonical_json(manifest))
    return ImportResult(destination_path, source_digest, data_digest, len(records))


def load_advisories(destination: str | Path) -> list[dict[str, Any]]:
    """Load and verify a current or legacy schema-v1 store.

    New stores seal both data and index hashes. Earlier schema-v1 stores did not
    include ``index_sha256``; for those, the index is verified semantically by
    reconstructing the deterministic product index from the sealed advisory
    rows. This preserves backward compatibility without trusting an unsealed
    legacy index.
    """

    root = Path(destination).expanduser()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    raw = (root / "advisories.jsonl").read_bytes()
    index_raw = (root / "index.json").read_bytes()
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported advisory store schema")
    if manifest.get("advisories_sha256") != _sha256(raw):
        raise ValueError("advisory store integrity check failed")
    sealed_index = str(manifest.get("index_sha256", "") or "")
    if sealed_index and sealed_index != _sha256(index_raw):
        raise ValueError("advisory store index integrity check failed")
    try:
        index = json.loads(index_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("advisory store index is invalid") from exc
    if not isinstance(index, dict) or index.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("advisory store index schema mismatch")
    if index.get("source_sha256") != manifest.get("source_sha256"):
        raise ValueError("advisory store source lineage mismatch")
    rows = _parse_source(raw, ".jsonl")
    if manifest.get("record_count") != len(rows):
        raise ValueError("advisory store record count mismatch")
    expected_index = _product_index(rows, str(manifest.get("source_sha256", "")))
    if index != expected_index:
        raise ValueError("advisory store index content mismatch")
    return rows


def match_product_version(
    destination: str | Path,
    *,
    vendor: str,
    product: str,
    version: str,
) -> list[dict[str, Any]]:
    """Map one observed product/version to matching advisories, offline."""

    wanted = _product_key(_single_line(vendor, "vendor"), _single_line(product, "product"))
    try:
        observed = Version(_single_line(version, "version", maximum=256))
    except InvalidVersion as exc:
        raise ValueError(f"invalid observed version: {version}") from exc
    matches: list[dict[str, Any]] = []
    for row in load_advisories(destination):
        if _product_key(row["vendor"], row["product"]) != wanted:
            continue
        constraint = row["version_constraint"]
        if constraint == "*" or observed in SpecifierSet(constraint):
            matches.append(row)
    return sorted(matches, key=lambda row: (-row["cvss"], row["id"]))


def map_inventory(
    destination: str | Path,
    products: Iterable[Mapping[str, str]],
) -> list[dict[str, Any]]:
    """Map a finite offline inventory without performing target activity."""

    output: list[dict[str, Any]] = []
    for observed in products:
        if set(observed) != {"vendor", "product", "version"}:
            raise ValueError("inventory rows require exactly vendor, product, and version")
        for advisory in match_product_version(destination, **observed):
            output.append({
                "vendor": observed["vendor"],
                "product": observed["product"],
                "version": observed["version"],
                "advisory": advisory,
            })
    return sorted(output, key=lambda row: (
        _product_key(row["vendor"], row["product"]),
        row["version"],
        row["advisory"]["id"],
    ))
