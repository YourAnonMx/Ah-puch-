#!/usr/bin/env python3
"""Canonical SRC01 projection adapters for the normalized artifact bus.

This module is network-silent. It reads already-produced core projection and
TLS inventory artifacts, preserves producer terminal status/provenance and maps
them into existing bus kinds. Observed contacts/social links are findings, not
new target URLs; certificate subject metadata is fingerprint evidence, while
SAN/peer identities are re-checked against the current target boundary before they
can become promotable host/URL records.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

try:
    from . import artifact_bus
except ImportError:
    import artifact_bus

_INSTALLED = False
_ORIGINAL_SYNC: Callable[..., dict[str, int]] | None = None
_HOST_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


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


def _lines(path: Path, *, max_bytes: int = 20_000_000) -> list[str]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
            return []
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        return []


def _projection_status(root: Path) -> str:
    status = "unknown"
    for row in _jsonl(root / "core" / "module_status.jsonl") + _jsonl(root / "module_status.jsonl"):
        if row.get("engine") != "recon_core" or row.get("stage") != "04-crawl":
            continue
        if not isinstance(row.get("projections"), dict):
            continue
        status = str(row.get("status", "unknown")).strip().lower() or "unknown"
    return status


def _projection_files(root: Path, suffix: str) -> list[Path]:
    result: list[Path] = []
    for base in (root / "core" / "04-crawl", root / "04-crawl"):
        if not base.is_dir():
            continue
        result.extend(path for path in base.glob(f"*.{suffix}.txt") if path.is_file() and not path.is_symlink())
    return sorted(set(result))


def _run_observation_allowed(bus: artifact_bus.ArtifactBus, allow: Callable[[str], bool]) -> bool:
    target = str(bus.target or "").strip()
    return bool(target and allow(target))


def _san_type(value: str) -> str:
    """Normalize common TLS library spellings without guessing targetability."""
    return re.sub(r"[^a-z0-9]+", "", str(value).casefold())


def _targetable_dns_san(value: str) -> str:
    """Return an exact executable DNS identity, never a wildcard/pattern."""
    host = artifact_bus.canonical_host(value)
    if not host or "*" in host or "?" in host or "@" in host or "/" in host or "\\" in host:
        return ""
    if artifact_bus.canonical_ip(host):
        return ""
    if host == "localhost":
        return host
    labels = host.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return ""
    return host


def _observe_san_fingerprint(
    bus: artifact_bus.ArtifactBus,
    *,
    value: str,
    san_type: str,
    status: str,
    origin_allowed: bool,
    cert_id: str,
    origin: str,
) -> None:
    namespace_type = re.sub(r"[^a-z0-9]+", "-", str(san_type).casefold()).strip("-") or "other"
    bus.observe(
        "fingerprint",
        value,
        producer="tls-inventory/san",
        source="tls-inventory/certificates.jsonl",
        status=status,
        within_target=origin_allowed,
        attributes={
            "namespace": f"certificate-san-{namespace_type}",
            "san_type": san_type,
            "certificate": cert_id,
            "origin": origin,
            "targetable": False,
        },
    )


def ingest_core_projections(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow: Callable[[str], bool],
) -> int:
    """Project crawl evidence without turning contact metadata into targets."""
    status = _projection_status(root)
    run_allowed = _run_observation_allowed(bus, allow)
    count = 0

    for path in _projection_files(root, "files"):
        source = str(path.relative_to(root))
        for value in _lines(path):
            if not artifact_bus.canonical_url(value):
                continue
            bus.observe_url_components(
                value,
                producer="recon-core/file-projection",
                source=source,
                status=status,
                within_target=bool(allow(value)),
            )
            count += 1

    for path in _projection_files(root, "domains"):
        source = str(path.relative_to(root))
        for value in _lines(path):
            host = artifact_bus.canonical_host(value)
            if not host or artifact_bus.canonical_ip(host):
                continue
            bus.observe(
                "host",
                host,
                producer="recon-core/domain-projection",
                source=source,
                status=status,
                within_target=bool(allow(host)),
                attributes={"projection_type": "domain"},
            )
            count += 1

    for path in _projection_files(root, "injection.urls"):
        source = str(path.relative_to(root))
        for value in _lines(path):
            if not artifact_bus.canonical_url(value):
                continue
            bus.observe_url_components(
                value,
                producer="recon-core/parameter-projection",
                source=source,
                status=status,
                within_target=bool(allow(value)),
            )
            count += 1

    for suffix, finding_type, producer in (
        ("emails", "contact-email", "recon-core/email-projection"),
        ("social-links", "social-link", "recon-core/social-projection"),
    ):
        for path in _projection_files(root, suffix):
            source = str(path.relative_to(root))
            for value in _lines(path):
                clean = str(value).strip()
                if not clean:
                    continue
                attributes: dict[str, Any] = {"finding_type": finding_type}
                if finding_type == "social-link":
                    attributes["url"] = artifact_bus.canonical_url(clean) or clean
                else:
                    attributes["contact"] = clean
                bus.observe(
                    "finding",
                    f"{finding_type}:{clean}",
                    producer=producer,
                    source=source,
                    status=status,
                    within_target=run_allowed,
                    observed=True,
                    attributes=attributes,
                )
                count += 1

    for suffix, namespace, producer in (
        ("titles", "http-title", "recon-core/title-projection"),
        ("banners", "server-banner", "recon-core/banner-projection"),
    ):
        for path in _projection_files(root, suffix):
            source = str(path.relative_to(root))
            for value in _lines(path):
                bus.observe(
                    "fingerprint",
                    value,
                    producer=producer,
                    source=source,
                    status=status,
                    within_target=run_allowed,
                    attributes={"namespace": namespace},
                )
                count += 1

    return count


def ingest_tls_identity(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow: Callable[[str], bool],
    allow_network: Callable[[str], bool] | None = None,
) -> int:
    """Project verified TLS identity evidence and scope-check targetable peers/SANs.

    Only exact DNS names, IP addresses and HTTP(S) URI SANs are targetable.
    Wildcard DNS patterns and every other SAN type remain certificate evidence
    only, even if their textual suffix resembles the operator target.
    """
    network_allow = allow_network or allow
    path = root / "tls-inventory" / "certificates.jsonl"
    count = 0
    for row in _jsonl(path):
        status = str(row.get("status", "unknown")).strip().lower() or "unknown"
        origin = artifact_bus.canonical_origin(str(row.get("origin", "")))
        origin_allowed = bool(origin and allow(origin))
        cert_sha = str(row.get("certificate_sha256", "")).strip()
        serial = str(row.get("serial_number", "")).strip()
        cert_id = cert_sha or serial
        if cert_id:
            bus.observe(
                "fingerprint",
                cert_id,
                producer="tls-inventory/certificate",
                source="tls-inventory/certificates.jsonl",
                status=status,
                within_target=origin_allowed,
                attributes={
                    "namespace": "certificate-sha256" if cert_sha else "certificate-serial",
                    "origin": origin,
                    "serial_number": serial,
                    "not_before": row.get("not_before", ""),
                    "not_after": row.get("not_after", ""),
                    "subject": row.get("subject", {}) if isinstance(row.get("subject"), dict) else {},
                    "issuer": row.get("issuer", {}) if isinstance(row.get("issuer"), dict) else {},
                },
            )
            count += 1

        subject = row.get("subject", {}) if isinstance(row.get("subject"), dict) else {}
        for key in ("commonName", "organizationName", "organizationalUnitName"):
            value = str(subject.get(key, "")).strip()
            if not value:
                continue
            bus.observe(
                "fingerprint",
                value,
                producer="tls-inventory/subject",
                source="tls-inventory/certificates.jsonl",
                status=status,
                within_target=origin_allowed,
                attributes={"namespace": f"certificate-subject-{key}", "origin": origin},
            )
            count += 1

        issuer = row.get("issuer", {}) if isinstance(row.get("issuer"), dict) else {}
        issuer_cn = str(issuer.get("commonName", "")).strip()
        if issuer_cn:
            bus.observe(
                "fingerprint",
                issuer_cn,
                producer="tls-inventory/issuer",
                source="tls-inventory/certificates.jsonl",
                status=status,
                within_target=origin_allowed,
                attributes={"namespace": "certificate-issuer-commonName", "origin": origin},
            )
            count += 1

        peer = artifact_bus.canonical_host(str(row.get("peer_address", "")))
        if peer:
            kind = "ip" if artifact_bus.canonical_ip(peer) else "host"
            bus.observe(
                kind,
                peer,
                producer="tls-inventory/peer",
                source="tls-inventory/certificates.jsonl",
                status=status,
                within_target=bool(network_allow(peer)),
                attributes={"certificate": cert_id, "origin": origin},
            )
            count += 1

        sans = row.get("subject_alt_name", []) if isinstance(row.get("subject_alt_name"), list) else []
        for san in sans:
            if not isinstance(san, dict):
                continue
            raw_type = str(san.get("type", "")).strip()
            normalized_type = _san_type(raw_type)
            value = str(san.get("value", "")).strip()
            if not value:
                continue

            if normalized_type == "uri" and artifact_bus.canonical_url(value):
                bus.observe_url_components(
                    value,
                    producer="tls-inventory/san",
                    source="tls-inventory/certificates.jsonl",
                    status=status,
                    within_target=bool(allow(value)),
                )
                count += 1
                continue

            if normalized_type in {"dns", "dnsname"}:
                host = _targetable_dns_san(value)
                if host:
                    bus.observe(
                        "host",
                        host,
                        producer="tls-inventory/san",
                        source="tls-inventory/certificates.jsonl",
                        status=status,
                        within_target=bool(network_allow(host)),
                        attributes={"san_type": raw_type, "certificate": cert_id, "origin": origin},
                    )
                else:
                    _observe_san_fingerprint(
                        bus,
                        value=value,
                        san_type=raw_type or "DNS",
                        status=status,
                        origin_allowed=origin_allowed,
                        cert_id=cert_id,
                        origin=origin,
                    )
                count += 1
                continue

            if normalized_type in {"ip", "ipaddress"}:
                ip = artifact_bus.canonical_ip(value)
                if ip:
                    bus.observe(
                        "ip",
                        ip,
                        producer="tls-inventory/san",
                        source="tls-inventory/certificates.jsonl",
                        status=status,
                        within_target=bool(network_allow(ip)),
                        attributes={"san_type": raw_type, "certificate": cert_id, "origin": origin},
                    )
                else:
                    _observe_san_fingerprint(
                        bus,
                        value=value,
                        san_type=raw_type or "IP Address",
                        status=status,
                        origin_allowed=origin_allowed,
                        cert_id=cert_id,
                        origin=origin,
                    )
                count += 1
                continue

            _observe_san_fingerprint(
                bus,
                value=value,
                san_type=raw_type or "other",
                status=status,
                origin_allowed=origin_allowed,
                cert_id=cert_id,
                origin=origin,
            )
            count += 1
    return count


def install() -> Callable[..., dict[str, int]]:
    """Wrap artifact_bus.sync_sources exactly once and return the active wrapper."""
    global _INSTALLED, _ORIGINAL_SYNC
    if _INSTALLED or getattr(artifact_bus.sync_sources, "_ah_puch_src01_projection", False):
        return artifact_bus.sync_sources
    _ORIGINAL_SYNC = artifact_bus.sync_sources

    def sync_sources(
        bus: artifact_bus.ArtifactBus,
        root: Path,
        graph: Any,
        allow: Callable[[str], bool],
        allow_network: Callable[[str], bool] | None = None,
    ) -> dict[str, int]:
        assert _ORIGINAL_SYNC is not None
        counts = _ORIGINAL_SYNC(bus, root, graph, allow, allow_network)
        counts["core_projection"] = ingest_core_projections(bus, root, allow)
        counts["tls_identity"] = ingest_tls_identity(bus, root, allow, allow_network)
        return counts

    sync_sources._ah_puch_src01_projection = True  # type: ignore[attr-defined]
    artifact_bus.sync_sources = sync_sources
    _INSTALLED = True
    return sync_sources
