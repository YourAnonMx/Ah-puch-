#!/usr/bin/env python3
"""Offline adapters for captured evidence and canonical source contracts.

The adapters are intentionally data-only.  They parse operator-supplied
captures, plans, or reference text and return deterministic JSON-compatible
records.  They never open sockets, start subprocesses, resolve names, or turn
an observed value into an executable target by themselves.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from .asset_graph import host_within_target, url_within_target
except ImportError:  # pragma: no cover - direct module execution compatibility
    from asset_graph import host_within_target, url_within_target


ROOT = Path(__file__).resolve().parents[1]
MAX_CAPTURE_BYTES = 20 * 1024 * 1024
MAX_CAPTURE_ITEMS = 4096


@dataclass(frozen=True)
class AdapterDescriptor:
    """Stable public description of one offline adapter."""

    id: str
    category: str
    execution: str
    provenance: str
    live_default: bool = False


ADAPTER_CATALOG: dict[str, AdapterDescriptor] = {
    "knowledge-taxonomy": AdapterDescriptor("knowledge-taxonomy", "knowledge-taxonomy", "registry-only", "knowledge-base"),
    "passive-recon": AdapterDescriptor("passive-recon", "passive-correlation", "offline", "passive-target-mapper"),
    "surface-map": AdapterDescriptor("surface-map", "surface-expansion", "offline-normalizer", "surface-map-contract"),
    "recon": AdapterDescriptor("recon", "recon-catalog", "registry-gated", "reconnaissance-catalog"),
    "phase-catalog": AdapterDescriptor("phase-catalog", "phase-catalog", "none", "assessment-orchestrator"),
    "crawler": AdapterDescriptor("crawler", "crawl-normalizer", "captured-output", "web-surface-crawler"),
    "recon-plan": AdapterDescriptor("recon-plan", "recon-plan", "registry-gated", "passive-target-mapper"),
    "range-plan": AdapterDescriptor("range-plan", "range-path-plan", "registry-gated", "range-path-discovery"),
    "cve-correlation": AdapterDescriptor("cve-correlation", "metadata-correlation", "offline", "vulnerability-reference"),
    "ics-classification": AdapterDescriptor("ics-classification", "ics-classification", "offline", "industrial-protocol-classifier"),
    "ssh-audit-contract": AdapterDescriptor("ssh-audit-contract", "credential-audit-contract", "blocked-contract", "ssh-auth-audit"),
    "credential-audit-contract": AdapterDescriptor("credential-audit-contract", "credential-testing-reference", "blocked-contract", "credential-audit-reference"),
    "wordlist-catalog": AdapterDescriptor("wordlist-catalog", "resource-catalog", "registry-only", "web-content-dictionary"),
    "network-observation": AdapterDescriptor("network-observation", "network-evidence", "offline-normalizer", "network-observation"),
    "web-security-evidence": AdapterDescriptor("web-security-evidence", "web-evidence", "offline-normalizer", "web-security-orchestrator"),
}

OFFLINE_NORMALIZERS = frozenset(
    {
        "passive-recon",
        "surface-map",
        "crawler",
        "recon-plan",
        "range-plan",
        "cve-correlation",
        "ics-classification",
        "network-observation",
        "web-security-evidence",
    }
)
REFERENCE_ONLY = frozenset(
    {
        "knowledge-taxonomy",
        "recon",
        "phase-catalog",
        "ssh-audit-contract",
        "credential-audit-contract",
        "wordlist-catalog",
    }
)

DOMAIN = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)$")
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
URL = re.compile(r"(?i)^https?://[^\s]+$")
EMAIL = re.compile(r"(?i)^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
TOKEN = re.compile(
    r"(?i)https?://[^\s,;]+|(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}"
)


def _asset(value: str) -> dict[str, str] | None:
    value = value.strip().strip('"').strip("'")
    if not value:
        return None
    if URL.match(value):
        return {"kind": "url", "value": value}
    if EMAIL.match(value):
        return {"kind": "email", "value": value.lower()}
    if IPV4.match(value):
        octets = [int(part) for part in value.split(".")]
        if all(0 <= item <= 255 for item in octets):
            return {"kind": "ipv4", "value": value}
    if DOMAIN.match(value) and "." in value:
        return {"kind": "domain", "value": value.lower()}
    return None


def _token_assets(text: str) -> list[dict[str, str]]:
    assets: dict[tuple[str, str], dict[str, str]] = {}
    for token in TOKEN.findall(text):
        item = _asset(token.rstrip(".,);]"))
        if item:
            assets[(item["kind"], item["value"])] = item
    return sorted(assets.values(), key=lambda item: (item["kind"], item["value"]))[:MAX_CAPTURE_ITEMS]


def normalize_surface_map(text: str, *, source: str = "surface-map") -> dict[str, Any]:
    """Normalize CSV/TXT surface evidence without making network calls."""

    assets: dict[tuple[str, str], dict[str, str]] = {}
    for row in csv.reader(io.StringIO(text)):
        for cell in row:
            item = _asset(cell)
            if item:
                key = (item["kind"], item["value"])
                if key in assets or len(assets) < MAX_CAPTURE_ITEMS:
                    assets[key] = item
    return {
        "schema": "ah-puch-surface-map-observations/v1",
        "source": source,
        "execution": "offline-normalizer",
        "assets": sorted(assets.values(), key=lambda item: (item["kind"], item["value"])),
        "observations": [],
    }


def _scope_decisions(
    assets: Iterable[dict[str, str]],
    target: str,
    *,
    producer: str,
    source: str,
    artifact_ref: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    ref = artifact_ref.as_dict() if hasattr(artifact_ref, "as_dict") else artifact_ref
    for item in assets:
        kind = str(item.get("kind", ""))
        value = str(item.get("value", ""))
        if kind == "url":
            within = url_within_target(value, target, "domain")
        elif kind in {"domain", "ipv4"}:
            within = host_within_target(value, target, "domain")
        else:
            within = False
        decision = {
            "candidate_kind": kind,
            "candidate_value": value,
            "decision": "accepted" if within else "rejected",
            "reason": "within_target" if within else "outside_target_or_not_network_identity",
            "producer": producer,
            "source": source,
        }
        if ref is not None:
            decision["artifact_ref"] = ref
        (accepted if within else rejected).append(decision)
    key = lambda row: (row["candidate_kind"], row["candidate_value"], row["reason"])
    accepted.sort(key=key)
    rejected.sort(key=key)
    return accepted, rejected


def _scoped_result(
    target: str,
    accepted: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    *,
    source: str,
    producer: str,
    non_scope_evidence: Iterable[dict[str, str]] = (),
    crawl_actions: Iterable[Any] = (),
) -> dict[str, Any]:
    return {
        "schema": "ah-puch-scoped-observations/v1",
        "source": source,
        "producer": producer,
        "execution": "offline-scope-normalizer",
        "target": target,
        "accepted": accepted,
        "rejected": rejected,
        "counts": {"accepted": len(accepted), "rejected": len(rejected)},
        "non_scope_evidence": sorted(
            (dict(row) for row in non_scope_evidence),
            key=lambda row: (row.get("kind", ""), row.get("value", "")),
        ),
        "crawl_actions": list(crawl_actions),
    }


def normalize_scoped_surface_map(
    text: str,
    target: str,
    *,
    source: str = "surface-map",
    producer: str = "surface-map",
    artifact_ref: Any = None,
) -> dict[str, Any]:
    parsed = normalize_surface_map(text, source=source)
    accepted, rejected = _scope_decisions(
        parsed["assets"], target, producer=producer, source=source, artifact_ref=artifact_ref
    )
    return _scoped_result(target, accepted, rejected, source=source, producer=producer)


def normalize_passive_atlas(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    for record in records:
        if len(observations) >= MAX_CAPTURE_ITEMS:
            break
        if isinstance(record, dict):
            observations.append(
                {
                    "kind": str(record.get("kind", "unknown")),
                    "asset": str(record.get("asset", "")),
                    "evidence_ref": str(record.get("evidence_ref", "")),
                    "provenance": "passive-recon",
                }
            )
    return {
        "schema": "ah-puch-passive-recon-observations/v1",
        "source": "passive-recon",
        "execution": "offline",
        "observations": observations,
    }


def normalize_passive_recon(text: str) -> dict[str, Any]:
    """Normalize passive observations without promoting them to target input.

    Passive tools commonly emit either JSON Lines or human-readable text.  A
    JSON object is retained as a small observation record; plain text is
    reduced to typed assets.  Both forms remain evidence only: no value is
    resolved, contacted, or added to an executable queue here.
    """

    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
        elif isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))
        if len(records) >= MAX_CAPTURE_ITEMS:
            records = records[:MAX_CAPTURE_ITEMS]

    normalized = normalize_passive_atlas(records)
    assets = _token_assets(text)
    if not records:
        normalized["observations"] = [
            {
                "kind": item["kind"],
                "asset": item["value"],
                "evidence_ref": "",
                "provenance": "passive-recon",
            }
            for item in assets
        ]
    normalized["execution"] = "offline-captured-output"
    normalized["assets"] = assets
    normalized["active_actions"] = []
    return normalized


def normalize_crawl_loom(text: str) -> dict[str, Any]:
    return {
        "schema": "ah-puch-crawler-observations/v1",
        "source": "crawler",
        "execution": "offline-captured-output",
        "assets": _token_assets(text),
        "crawl_actions": [],
    }


def normalize_scoped_crawl_loom(
    text: str,
    target: str,
    *,
    source: str = "crawler",
    producer: str = "crawler",
    artifact_ref: Any = None,
) -> dict[str, Any]:
    parsed = normalize_crawl_loom(text)
    url_assets = [item for item in parsed["assets"] if item.get("kind") == "url"]
    non_scope = [item for item in parsed["assets"] if item.get("kind") != "url"]
    accepted, rejected = _scope_decisions(
        url_assets, target, producer=producer, source=source, artifact_ref=artifact_ref
    )
    return _scoped_result(
        target,
        accepted,
        rejected,
        source=source,
        producer=producer,
        non_scope_evidence=non_scope,
        crawl_actions=parsed["crawl_actions"],
    )


def plan_recon_scribe(text: str) -> dict[str, Any]:
    assets = _token_assets(text)
    domains = [item["value"] for item in assets if item["kind"] == "domain"][:32]
    return {
        "schema": "ah-puch-recon-plan/v1",
        "source": "recon-plan",
        "execution": "offline-plan",
        "domains": domains,
        "steps": [
            {"id": "passive-dns-capture", "network": False, "requires_fresh_activation": True},
            {"id": "certificate-metadata-capture", "network": False, "requires_fresh_activation": True},
        ],
    }


def plan_range_forge(text: str) -> dict[str, Any]:
    assets = _token_assets(text)
    paths = sorted({match for match in re.findall(r"/[A-Za-z0-9._-]{1,80}", text) if match != "/"})[:64]
    return {
        "schema": "ah-puch-range-plan/v1",
        "source": "range-plan",
        "execution": "offline-plan",
        "assets": assets[:32],
        "paths": paths,
        "max_candidates": 64,
        "steps": [],
    }


def _advisory_reference(item: str) -> dict[str, Any]:
    year = item.split("-", 2)[1]
    path = ROOT / "data" / "advisories" / "reference-corpus" / year / f"{item}.md"
    available = path.is_file() and not path.is_symlink()
    return {
        "id": item,
        "references": [path.relative_to(ROOT).as_posix()] if available else [],
        "local_reference_available": available,
        "reference_status": "local" if available else "not-found",
        "version_observed": "",
    }


def normalize_cve_metadata(text: str) -> dict[str, Any]:
    ids = sorted({item.upper() for item in CVE.findall(text)})
    return {
        "schema": "ah-puch-cve-correlation/v1",
        "source": "cve-correlation",
        "execution": "offline-correlation",
        "cves": [_advisory_reference(item) for item in ids[:256]],
    }


def normalize_network_observation(text: str) -> dict[str, Any]:
    port_values = re.findall(r"(?i)(?:ports?|tcp|udp)\s*[:=]?\s*(\d{1,5})\b|:(\d{1,5})\b", text)
    ports = {
        int(value)
        for group in port_values
        for value in group
        if value and 1 <= int(value) <= 65535
    }
    return {
        "schema": "ah-puch-network-observation/v1",
        "source": "network-observation",
        "execution": "offline-captured-output",
        "assets": _token_assets(text),
        "ports": sorted(ports)[:256],
        "active_actions": [],
    }


def normalize_web_security_evidence(text: str) -> dict[str, Any]:
    return {
        "schema": "ah-puch-web-security-evidence/v1",
        "source": "web-security-evidence",
        "execution": "offline-captured-output",
        "assets": _token_assets(text),
        "cves": normalize_cve_metadata(text)["cves"],
        "findings": [line.strip() for line in text.splitlines() if line.strip()][:256],
        "active_actions": [],
    }


ICS_SIGNATURES = {
    102: "s7comm",
    502: "modbus",
    2404: "iec-104",
    4840: "opc-ua",
    20000: "dnp3",
    44818: "ethernet-ip",
    47808: "bacnet",
}


def classify_ics(text: str) -> dict[str, Any]:
    lowered = text.lower()
    observations = [
        {"protocol": protocol, "port": port, "confidence": "captured-marker"}
        for port, protocol in ICS_SIGNATURES.items()
        if str(port) in text or protocol in lowered
    ]
    return {
        "schema": "ah-puch-ics-classification/v1",
        "source": "ics-classification",
        "execution": "offline-classification",
        "observations": observations,
        "active_probes": [],
    }


def normalize_captured_output(adapter: str, text: str) -> dict[str, Any]:
    """Dispatch one canonical adapter without executing its historical source."""

    if not isinstance(text, str):
        raise TypeError("captured text must be a string")
    functions = {
        "passive-recon": normalize_passive_recon,
        "surface-map": normalize_surface_map,
        "crawler": normalize_crawl_loom,
        "recon-plan": plan_recon_scribe,
        "range-plan": plan_range_forge,
        "cve-correlation": normalize_cve_metadata,
        "ics-classification": classify_ics,
        "network-observation": normalize_network_observation,
        "web-security-evidence": normalize_web_security_evidence,
    }
    if adapter in functions:
        return functions[adapter](text)
    if adapter in REFERENCE_ONLY:
        descriptor = ADAPTER_CATALOG[adapter]
        return {
            "schema": "ah-puch-reference-adapter/v1",
            "adapter": adapter,
            "execution": descriptor.execution,
            "provenance": descriptor.provenance,
            "actions": [],
        }
    raise ValueError(f"adapter {adapter!r} has no native capture contract")


def normalize_file(adapter: str, input_path: str | Path, output_path: str | Path | None = None) -> dict[str, Any]:
    """Normalize a bounded local capture and optionally write explicit output."""

    source = Path(input_path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise ValueError("capture input must be an owned regular file")
    if source.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError(f"capture input exceeds {MAX_CAPTURE_BYTES} bytes")
    result = normalize_captured_output(adapter, source.read_text(encoding="utf-8", errors="replace"))
    if output_path:
        destination = Path(output_path).expanduser()
        if destination.exists() and destination.is_symlink():
            raise ValueError("capture output must not be a symlink")
        for parent in (destination.parent, *destination.parent.parents):
            if parent.is_symlink():
                raise ValueError("capture output parent must not contain a symlink")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        destination.chmod(0o600)
        result = {**result, "output": str(destination)}
    return result


def adapter_catalog() -> list[dict[str, Any]]:
    return [
        {
            "id": descriptor.id,
            "category": descriptor.category,
            "execution": descriptor.execution,
            "provenance": descriptor.provenance,
            "live_default": descriptor.live_default,
        }
        for descriptor in sorted(ADAPTER_CATALOG.values(), key=lambda item: item.id)
    ]
