#!/usr/bin/env python3
"""Structured catalog-result handoffs into the canonical graph/artifact bus.

Only module-specific structured artifacts are consumed. Arbitrary stdout is
never scraped into positive graph state, preventing help text, provider names or
error messages from masquerading as discovered assets.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

try:
    from .artifact_bus import ArtifactBus
except ImportError:
    from artifact_bus import ArtifactBus

PARTIAL_EXIT_CODE = 3
_PARTIAL_STATUS_MODULES = frozenset({"1", "2", "3", "5", "6", "7"})
_STRUCTURED_RESULT_BY_MODULE = {
    "2": "dns_doh.json",
    "3": "dns_records.json",
    "5": "domain_info.json",
    "6": "domain_reputation.json",
    "7": "http2_http3.json",
}


def _body_json(body: str, filename: str) -> Any:
    """Extract one generated JSON artifact embedded by the catalog runner."""
    lines = str(body).splitlines()
    suffix = filename + "]"
    for index, line in enumerate(lines[:-1]):
        marker = line.strip()
        if not (marker.startswith("[") and marker.endswith(suffix)):
            continue
        try:
            return json.loads(lines[index + 1])
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def _terminal_error_state(value: object) -> bool:
    state = str(value or "").strip().lower()
    return bool(
        state in {"failed", "timeout", "internal-error", "resolver-error", "transport-error", "http-error", "parse-error", "tls-error", "tls-verification-error", "error"}
        or state.endswith("-error")
    )


def _payload_has_terminal_error(value: Any) -> bool:
    if isinstance(value, dict):
        if "state" in value and _terminal_error_state(value.get("state")):
            return True
        return any(_payload_has_terminal_error(item) for item in value.values())
    if isinstance(value, list):
        return any(_payload_has_terminal_error(item) for item in value)
    return False


def catalog_terminal_status(module_id: str, original_status: str, body: str) -> str:
    """Preserve mixed provider/subprobe failures as an explicit partial state.

    Modules 1/2/3/5/6/7 historically returned rc=0 when at least one provider or
    subprobe completed, even if another timed out or failed. The canonical
    runtime reconciles their structured per-source states before the result is
    written so a real error can never be collapsed into ``success``.
    """
    status = str(original_status)
    module_id = str(module_id)
    if status != "success" or module_id not in _PARTIAL_STATUS_MODULES:
        return status
    if module_id == "1":
        # Module 1's legacy JSON artifact contains only host values. Its source
        # ledger is printed in the captured body; provider errors are rendered
        # as ``source: error:<Class>`` while optional no-key is ``skipped``.
        return "partial" if "error:" in str(body).lower() else status
    filename = _STRUCTURED_RESULT_BY_MODULE.get(module_id, "")
    payload = _body_json(body, filename) if filename else None
    return "partial" if payload is not None and _payload_has_terminal_error(payload) else status


def _embedded_json(path: Path, filename: str) -> Any:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not any(line.strip() in {"status=success", "status=partial"} for line in lines[:8]):
        return None
    suffix = filename + "]"
    for index, line in enumerate(lines[:-1]):
        marker = line.strip()
        if not (marker.startswith("[") and marker.endswith(suffix)):
            continue
        try:
            return json.loads(lines[index + 1])
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def _associated_hosts_from_result(path: Path) -> list[str]:
    payload = _embedded_json(path, "associated_hosts.json")
    if not isinstance(payload, list):
        return []
    hosts: set[str] = set()
    for value in payload:
        host = str(value or "").strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        if host and not any(character.isspace() for character in host):
            hosts.add(host)
    return sorted(hosts)


def _doh_addresses_from_result(path: Path) -> list[str]:
    payload = _embedded_json(path, "dns_doh.json")
    if not isinstance(payload, list):
        return []
    addresses: set[str] = set()
    for row in payload:
        if not isinstance(row, dict) or row.get("state") != "success":
            continue
        answers = row.get("answers", [])
        if not isinstance(answers, list):
            continue
        for value in answers:
            try:
                addresses.add(str(ipaddress.ip_address(str(value).strip())))
            except ValueError:
                continue
    return sorted(addresses)


def _dns_assets(rows: dict[str, Any]) -> tuple[list[str], list[str]]:
    addresses: set[str] = set()
    hosts: set[str] = set()
    for record_type, raw in rows.items():
        if not isinstance(raw, dict) or raw.get("state") != "success":
            continue
        values = raw.get("values", [])
        if not isinstance(values, list):
            continue
        record_type = str(record_type).upper()
        if record_type in {"A", "AAAA"}:
            for value in values:
                try:
                    addresses.add(str(ipaddress.ip_address(str(value).strip())))
                except ValueError:
                    continue
            continue
        if record_type in {"CNAME", "NS", "MX"}:
            for value in values:
                text = str(value or "").strip()
                if record_type == "MX":
                    text = text.split()[-1] if text.split() else ""
                host = text.strip('"').lower().rstrip(".")
                if host and not any(character.isspace() for character in host):
                    hosts.add(host)
    return sorted(addresses), sorted(hosts)


def _dns_record_assets_from_result(path: Path) -> tuple[list[str], list[str]]:
    payload = _embedded_json(path, "dns_records.json")
    if not isinstance(payload, list):
        return [], []
    rows = {
        str(row.get("type", "")): row
        for row in payload
        if isinstance(row, dict) and str(row.get("type", ""))
    }
    return _dns_assets(rows)


def _domain_info_from_result(path: Path) -> tuple[dict[str, Any], list[str], list[str], list[dict[str, Any]]]:
    payload = _embedded_json(path, "domain_info.json")
    if not isinstance(payload, dict):
        return {}, [], [], []
    dns_rows = payload.get("dns", {})
    addresses, hosts = _dns_assets(dns_rows if isinstance(dns_rows, dict) else {})
    ip_rows = payload.get("ip_info", [])
    metadata = [row for row in ip_rows if isinstance(row, dict) and row.get("state") == "success"] if isinstance(ip_rows, list) else []
    return payload, addresses, hosts, metadata


def _domain_reputation_from_result(path: Path) -> dict[str, Any]:
    payload = _embedded_json(path, "domain_reputation.json")
    if not isinstance(payload, dict):
        return {}
    verdict_value = str(payload.get("verdict", "")).strip()
    if verdict_value not in {"Low risk", "Medium risk", "High risk"}:
        return {}
    return payload


def _result_path(base: Any, run: Any, item: dict[str, Any], index: int) -> Path:
    module_id = str(item.get("id", ""))
    name = str(item.get("name", item.get("script", "module")))
    destination = run.module_root / f"{module_id}-{base.slug(name)}" / str(index)
    expected = destination / f"{base.slug(run.target)}.{base.slug(name)}.txt"
    if expected.is_file() and not expected.is_symlink():
        return expected

    # Runs created before the canonical slug format used different directory
    # names. Read only a stable TXT whose exact module ID and input index match;
    # stdout/stderr and neighboring module trees are never candidates.
    for module_dir in sorted(run.module_root.glob(f"{module_id}-*")):
        candidate_dir = module_dir / str(index)
        if module_dir.is_symlink() or candidate_dir.is_symlink() or not candidate_dir.is_dir():
            continue
        for candidate in sorted(candidate_dir.glob("*.txt")):
            if candidate.is_symlink() or candidate.name.endswith((".stdout.txt", ".stderr.txt")):
                continue
            try:
                header = candidate.read_text(encoding="utf-8", errors="replace").splitlines()[:8]
            except OSError:
                continue
            if f"module_id={module_id}" in header:
                return candidate
    return expected


def _project_host_assets(
    base: Any,
    run: Any,
    *,
    source_host: str,
    addresses: list[str],
    hosts: list[str],
    producer: str,
) -> tuple[set[str], int]:
    allow_network = getattr(run, "_network_allowed", run._allowed)
    promoted: set[str] = set()
    observed = 0
    graph = getattr(run, "graph", None)

    for address in addresses:
        allowed = bool(allow_network(address))
        if graph is not None and source_host:
            graph.add_edge(
                "hostname",
                source_host,
                "resolves_to",
                "ip",
                address,
                source=producer,
                depth=2,
                within_target=allowed,
            )
        observed += 1
        if allowed:
            promoted.add(address)

    for host in hosts:
        if not base.HOST_RE.fullmatch(host):
            continue
        allowed = bool(allow_network(host))
        if graph is not None:
            graph.add_node("hostname", host, source=producer, depth=2, within_target=allowed)
        observed += 1
        if allowed:
            promoted.add(host)

    if promoted:
        run.seed_hosts = sorted(set(run.seed_hosts) | promoted)[: run.args.range_host_limit]
    return promoted, observed


def _project_module_1(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    del input_value
    hosts = _associated_hosts_from_result(_result_path(base, run, item, index))
    if not hosts:
        return
    promoted, observed = _project_host_assets(base, run, source_host="", addresses=[], hosts=hosts, producer="catalog-module:1-associated-hosts")
    run.event({"engine": "catalog_artifact_handoff", "module_id": "1", "module": str(item.get("name", "Associated Hosts")), "status": "success", "observed_hosts": observed, "promoted_hosts": len(promoted), "quarantined_hosts": observed - len(promoted)})


def _project_module_2(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    addresses = _doh_addresses_from_result(_result_path(base, run, item, index))
    if not addresses:
        return
    promoted, observed = _project_host_assets(base, run, source_host=base.target_host(input_value).lower().rstrip("."), addresses=addresses, hosts=[], producer="catalog-module:2-dns-over-https")
    run.event({"engine": "catalog_artifact_handoff", "module_id": "2", "module": str(item.get("name", "DNS Over HTTPS")), "status": "success", "observed_addresses": observed, "promoted_addresses": len(promoted), "quarantined_addresses": observed - len(promoted)})


def _project_module_3(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    addresses, hosts = _dns_record_assets_from_result(_result_path(base, run, item, index))
    if not addresses and not hosts:
        return
    promoted, observed = _project_host_assets(base, run, source_host=base.target_host(input_value).lower().rstrip("."), addresses=addresses, hosts=hosts, producer="catalog-module:3-dns-records")
    run.event({"engine": "catalog_artifact_handoff", "module_id": "3", "module": str(item.get("name", "DNS Records")), "status": "success", "observed_addresses": len(addresses), "observed_hosts": len(hosts), "promoted_assets": len(promoted), "quarantined_assets": observed - len(promoted)})


def _project_module_4(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    del input_value
    result = _result_path(base, run, item, index)
    payload = _embedded_json(result, "dnssec.json")
    if not isinstance(payload, dict):
        return
    zones = payload.get("zones", {})
    if not isinstance(zones, dict):
        return
    bus = ArtifactBus(run.root, run.target)
    observed = promoted = 0
    for zone, row in sorted(zones.items(), key=lambda value: str(value[0])):
        if not isinstance(row, dict):
            continue
        status_value = str(row.get("status", "")).strip()
        if not status_value or status_value == "Indeterminate":
            continue
        zone_text = str(zone).strip().lower().rstrip(".")
        within_target = bool(zone_text and run._allowed(zone_text))
        if bus.observe("fingerprint", status_value, producer="catalog-module:4-dnssec", source=str(result.relative_to(run.root)), status="success", within_target=within_target, attributes={"namespace": "dnssec-status", "zone": zone_text, "parent_ds_present": payload.get("parent_ds_present") if zone_text == str(payload.get("domain", "")).lower().rstrip(".") else None}):
            observed += 1
            if within_target:
                promoted += 1
    if not observed:
        return
    bus.save()
    run.event({"engine": "catalog_artifact_handoff", "module_id": "4", "module": str(item.get("name", "DNSSEC Check")), "status": "success", "observed_fingerprints": observed, "promoted_fingerprints": promoted, "quarantined_fingerprints": observed - promoted})


def _project_module_5(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    result = _result_path(base, run, item, index)
    payload, addresses, hosts, metadata = _domain_info_from_result(result)
    if not payload:
        return
    source_host = str(payload.get("domain") or base.target_host(input_value)).strip().lower().rstrip(".")
    promoted, observed_assets = _project_host_assets(base, run, source_host=source_host, addresses=addresses, hosts=hosts, producer="catalog-module:5-domain-info")
    allow_network = getattr(run, "_network_allowed", run._allowed)
    bus = ArtifactBus(run.root, run.target)
    metadata_observed = metadata_promoted = 0
    for row in metadata:
        ip = str(row.get("ip", "")).strip()
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        within_target = bool(allow_network(ip))
        org = str(row.get("org", "") or "").strip()
        asn = str(row.get("asn", "") or "").strip()
        country = str(row.get("country", "") or "").strip()
        if not any((org, asn, country)):
            continue
        value = " | ".join(part for part in (asn, org, country) if part)
        if bus.observe("fingerprint", value, producer="catalog-module:5-domain-info", source=str(result.relative_to(run.root)), status="success", within_target=within_target, attributes={"namespace": "ip-network-metadata", "ip": ip}):
            metadata_observed += 1
            if within_target:
                metadata_promoted += 1
    if metadata_observed:
        bus.save()
    run.event({"engine": "catalog_artifact_handoff", "module_id": "5", "module": str(item.get("name", "Domain Info")), "status": "success", "observed_assets": observed_assets, "promoted_assets": len(promoted), "quarantined_assets": observed_assets - len(promoted), "observed_metadata": metadata_observed, "promoted_metadata": metadata_promoted})


def _project_module_6(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    del input_value
    result = _result_path(base, run, item, index)
    payload = _domain_reputation_from_result(result)
    if not payload:
        return
    domain = str(payload.get("domain", "")).strip().lower().rstrip(".")
    within_target = bool(domain and run._allowed(domain))
    verdict_value = str(payload["verdict"])
    bus = ArtifactBus(run.root, run.target)
    observed = bus.observe("fingerprint", verdict_value, producer="catalog-module:6-domain-reputation", source=str(result.relative_to(run.root)), status="success", within_target=within_target, attributes={"namespace": "domain-reputation", "domain": domain, "virustotal_state": str(payload.get("virustotal", {}).get("state", "")) if isinstance(payload.get("virustotal"), dict) else "", "talos_state": str(payload.get("talos", {}).get("state", "")) if isinstance(payload.get("talos"), dict) else "", "urlhaus_state": str(payload.get("urlhaus", {}).get("state", "")) if isinstance(payload.get("urlhaus"), dict) else "", "otx_state": str(payload.get("otx", {}).get("state", "")) if isinstance(payload.get("otx"), dict) else ""})
    ip_row = payload.get("ip", {})
    addresses: list[str] = []
    if isinstance(ip_row, dict) and ip_row.get("state") == "success" and ip_row.get("ip"):
        try:
            addresses = [str(ipaddress.ip_address(str(ip_row["ip"]).strip()))]
        except ValueError:
            addresses = []
    promoted_assets: set[str] = set()
    observed_assets = 0
    if addresses:
        promoted_assets, observed_assets = _project_host_assets(base, run, source_host=domain, addresses=addresses, hosts=[], producer="catalog-module:6-domain-reputation")
    if observed:
        bus.save()
    run.event({"engine": "catalog_artifact_handoff", "module_id": "6", "module": str(item.get("name", "Domain Reputation Check")), "status": "success", "verdict": verdict_value, "reputation_promotable": bool(within_target), "observed_assets": observed_assets, "promoted_assets": len(promoted_assets)})


def _project_module_7(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    result = _result_path(base, run, item, index)
    payload = _embedded_json(result, "http2_http3.json")
    if not isinstance(payload, dict):
        return
    host = str(payload.get("host", "")).strip().lower().rstrip(".")
    origin = str(payload.get("origin", "")).strip()
    within_target = bool(input_value and run._allowed(input_value))

    dns_row = payload.get("dns", {})
    addresses: list[str] = []
    if isinstance(dns_row, dict) and dns_row.get("state") == "success":
        for value in dns_row.get("ips", []) if isinstance(dns_row.get("ips"), list) else []:
            try:
                addresses.append(str(ipaddress.ip_address(str(value).strip())))
            except ValueError:
                continue
    promoted_assets, observed_assets = _project_host_assets(base, run, source_host=host, addresses=sorted(set(addresses)), hosts=[], producer="catalog-module:7-http2-http3") if addresses else (set(), 0)

    bus = ArtifactBus(run.root, run.target)
    observed_technology = promoted_technology = observed_fingerprint = promoted_fingerprint = 0
    for key, label in (("http2", "HTTP/2"), ("http3", "HTTP/3")):
        row = payload.get(key, {})
        if not isinstance(row, dict) or row.get("state") != "success" or row.get("supported") is not True:
            continue
        if bus.observe("technology", label, producer="catalog-module:7-http2-http3", source=str(result.relative_to(run.root)), status="success", within_target=within_target, attributes={"host": host, "origin": origin, "port": payload.get("port")}):
            observed_technology += 1
            if within_target:
                promoted_technology += 1

    http2 = payload.get("http2", {})
    certificate = http2.get("certificate", {}) if isinstance(http2, dict) and isinstance(http2.get("certificate"), dict) else {}
    digest = str(certificate.get("sha256", "")).strip().lower()
    if len(digest) == 64 and all(character in "0123456789abcdef" for character in digest):
        if bus.observe("fingerprint", digest, producer="catalog-module:7-http2-http3", source=str(result.relative_to(run.root)), status="verified", within_target=within_target, attributes={"namespace": "tls-certificate-sha256", "host": host, "origin": origin, "common_name": str(certificate.get("common_name", ""))}):
            observed_fingerprint += 1
            if within_target:
                promoted_fingerprint += 1

    if observed_technology or observed_fingerprint:
        bus.save()
    run.event({"engine": "catalog_artifact_handoff", "module_id": "7", "module": str(item.get("name", "HTTP/2 and HTTP/3 Support Checker")), "status": "success", "observed_assets": observed_assets, "promoted_assets": len(promoted_assets), "observed_technology": observed_technology, "promoted_technology": promoted_technology, "observed_fingerprint": observed_fingerprint, "promoted_fingerprint": promoted_fingerprint})


def install(base: Any) -> Any:
    """Wrap catalog dispatch exactly once and project supported artifacts."""
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_catalog_artifacts", False):
        return base

    class CatalogArtifactUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_catalog_artifacts = True

        def write_module_text(self, destination: Path, event: dict[str, Any], status: str, body: str) -> None:
            reconciled = catalog_terminal_status(str(event.get("module_id", "")), status, body)
            if reconciled != status:
                event = {**event, "terminal_reconciled": True, "raw_exit_status": status}
            super().write_module_text(destination, event, reconciled, body)

        def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
            super().run_catalog_module(item, input_value, index)
            module_id = str(item.get("id", ""))
            if module_id == "1":
                _project_module_1(base, self, item, input_value, index)
            elif module_id == "2":
                _project_module_2(base, self, item, input_value, index)
            elif module_id == "3":
                _project_module_3(base, self, item, input_value, index)
            elif module_id == "4":
                _project_module_4(base, self, item, input_value, index)
            elif module_id == "5":
                _project_module_5(base, self, item, input_value, index)
            elif module_id == "6":
                _project_module_6(base, self, item, input_value, index)
            elif module_id == "7":
                _project_module_7(base, self, item, input_value, index)

        def finish(self) -> int:
            rc = super().finish()
            has_partial = any(
                row.get("engine") == "ahpuch_modules" and row.get("status") == "partial"
                for row in getattr(self, "events", [])
            )
            return PARTIAL_EXIT_CODE if rc == 0 and has_partial else rc

    CatalogArtifactUnifiedRun.__name__ = "CatalogArtifactUnifiedRun"
    CatalogArtifactUnifiedRun.__qualname__ = "CatalogArtifactUnifiedRun"
    base.UnifiedRun = CatalogArtifactUnifiedRun
    return base
