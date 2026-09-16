#!/usr/bin/env python3
"""Machine-readable function registry for the ten legacy capability sources.

The registry is deliberately about operational capability entry points, not
every presentation helper in an old shell script.  It gives the scheduler one
place to answer three questions: what was preserved, which canonical adapter
owns it, and what evidence must exist before it may be dispatched.
"""
from __future__ import annotations

import json
import importlib
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "config" / "legacy_capability_matrix.json"
CORE_SOURCE_COUNT = 10
KNOWN_ADAPTERS = frozenset({
    "catalog", "discovery", "dictionary", "evidence", "industrial", "knowledge",
    "offline-advisory", "device", "range", "ssh", "web-evidence",
})
KNOWN_CAPABILITIES = frozenset({
    "complete-assessment", "complete-web-evidence", "advisory-correlation",
    "device-inventory", "dictionary-corpus", "industrial-protocol-followup",
    "intelligence-catalog", "knowledge-index", "range-http-verification",
    "ssh-credential-audit", "subdomain-infrastructure",
})
KNOWN_EVIDENCE = frozenset({
    "bounded-paths", "camera-fingerprint", "concrete-host",
    "concrete-host-or-service", "concrete-http-service", "concrete-service",
    "crawl-output", "directory-dictionary", "discovered-host", "domain",
    "domain-or-ip", "explicit-credential-audit", "filtered-entries", "host-input",
    "host-or-domain", "http-response", "https-origin", "ics-keyword",
    "in-scope-camera-endpoint", "local-advisory-corpus", "local-artifacts",
    "local-dictionary-source", "local-notebook", "local-path-dictionary",
    "masscan-output", "module-output", "observed-ssh-service", "offline-index",
    "operator-options", "operator-range", "operator-selected-module",
    "operator-selected-profile", "operator-selected-tier", "parameterized-url",
    "target", "target-bound-input", "target-domain", "target-url", "typed-evidence",
    "url-artifact", "verified-fingerprint", "verified-http-origin",
    "verified-https-origin", "verified-parameterized-url",
})

# A matrix row keeps the historical source/function name for provenance.  It
# must not be mistaken for a Python import path: several old scripts exposed
# shell functions or conceptual stages rather than importable symbols.  This
# table is the executable bridge to the canonical implementation.  A
# ``composite`` binding means that the named legacy step is deliberately
# carried out inside one bounded adapter (for example cleaning and
# deduplication inside the dictionary builder), not that the step was dropped.
RUNTIME_BINDINGS: dict[str, dict[str, str]] = {
    # Surface / catalog.
    "surface.catalog_loader": {"entrypoint": "engines.catalog_frontend.load_catalog", "mode": "direct"},
    "surface.execute_script": {"entrypoint": "ahpuch_modules.core.runner.execute_script", "mode": "direct"},
    "surface.run_modules": {"entrypoint": "ahpuch_modules.core.runner.run_modules", "mode": "direct"},
    "surface.parse_output_severity": {"entrypoint": "ahpuch_modules.core.runner.parse_output_severity", "mode": "direct"},
    "surface.module_options": {"entrypoint": "engines.runner.module_options", "mode": "direct"},
    "surface.report_generation": {"entrypoint": "ahpuch_modules.utils.report_generator.generate_report", "mode": "direct"},

    # Discovery and the profile/queue orchestration that owns the external
    # tool gates.
    "discovery.module_recon": {"entrypoint": "engines.recon_core.CoreRun.discover", "mode": "composite"},
    "discovery.module_dns": {"entrypoint": "engines.recon_core.CoreRun.dns", "mode": "composite"},
    "discovery.module_httpx_deep": {"entrypoint": "engines.recon_core.CoreRun.http", "mode": "composite"},
    "discovery.module_dirsearch": {"entrypoint": "engines.recon_core.CoreRun.content", "mode": "composite"},
    "discovery.module_katana": {"entrypoint": "engines.recon_core.CoreRun.content", "mode": "composite"},
    "discovery.module_nikto": {"entrypoint": "engines.recon_core.CoreRun.optional_consumers", "mode": "composite"},
    "discovery.module_tls": {"entrypoint": "engines.recon_core.CoreRun.optional_consumers", "mode": "composite"},
    "discovery.module_nmap": {"entrypoint": "engines.recon_core.CoreRun.consumers", "mode": "composite"},
    "discovery.module_nuclei": {"entrypoint": "engines.recon_core.CoreRun.optional_consumers", "mode": "composite"},
    "discovery.module_wapiti": {"entrypoint": "engines.recon_core.CoreRun.optional_consumers", "mode": "composite"},
    "discovery.module_zap": {"entrypoint": "engines.recon_core.CoreRun.optional_consumers", "mode": "composite"},
    "discovery.module_sqlmap": {"entrypoint": "engines.recon_core.CoreRun.consumers", "mode": "composite"},
    "discovery.profile_sequence": {"entrypoint": "engines.recon_core.CoreRun.run", "mode": "orchestration"},
    "discovery.queue_builders": {"entrypoint": "engines.recon_core.CoreRun.build_queues", "mode": "composite"},

    # Dictionary source preparation is intentionally one bounded local
    # pipeline; the tier resolver remains a separately callable primitive.
    "dictionary.build_all": {"entrypoint": "engines.integrated_capability_runtime.build_dictionary", "mode": "composite"},
    "dictionary.build_short": {"entrypoint": "engines.integrated_capability_runtime.build_dictionary", "mode": "composite"},
    "dictionary.clean_lines": {"entrypoint": "engines.integrated_capability_runtime.build_dictionary", "mode": "composite"},
    "dictionary.deduplicate": {"entrypoint": "engines.integrated_capability_runtime.build_dictionary", "mode": "composite"},
    "dictionary.tier_selection": {"entrypoint": "engines.dictionary_runtime.effective_directory_tier", "mode": "direct"},

    # The knowledge and advisory functions are metadata/indexing stages of
    # their canonical local-only adapters.  No historical executable content
    # is imported or executed.
    "knowledge.technique_index": {"entrypoint": "engines.integrated_capability_runtime._knowledge_index", "mode": "composite"},
    "knowledge.reference_catalog": {"entrypoint": "engines.integrated_capability_runtime._knowledge_index", "mode": "composite"},
    "knowledge.ttp_navigation": {"entrypoint": "engines.integrated_capability_runtime._knowledge_index", "mode": "composite"},
    "knowledge.safe_content_filter": {"entrypoint": "engines.integrated_capability_runtime._knowledge_index", "mode": "composite"},
    "advisory.collect_metadata": {"entrypoint": "engines.integrated_capability_runtime._advisory_correlation", "mode": "composite"},
    "advisory.extract_references": {"entrypoint": "engines.integrated_capability_runtime._advisory_correlation", "mode": "composite"},
    "advisory.hot_list": {"entrypoint": "engines.integrated_capability_runtime._advisory_correlation", "mode": "composite"},
    "advisory.blacklist_filter": {"entrypoint": "engines.integrated_capability_runtime._advisory_correlation", "mode": "composite"},
    "advisory.merge_records": {"entrypoint": "engines.integrated_capability_runtime._advisory_correlation", "mode": "composite"},
    "advisory.render_summary": {"entrypoint": "engines.integrated_capability_runtime._advisory_correlation", "mode": "composite"},

    # Industrial evidence and range verification are bounded adapters.  Their
    # callable is the ordered stage that performs all named substeps.
    "industrial.read_urls": {"entrypoint": "engines.integrated_capability_runtime._industrial_protocol_followup", "mode": "composite"},
    "industrial.keyword_search": {"entrypoint": "engines.integrated_capability_runtime._industrial_protocol_followup", "mode": "composite"},
    "industrial.protocol_followup": {"entrypoint": "engines.integrated_capability_runtime._industrial_protocol_followup", "mode": "composite"},
    "range.range_discovery": {"entrypoint": "engines.integrated_capability_runtime._range_http_verification", "mode": "composite"},
    "range.load_paths": {"entrypoint": "engines.integrated_capability_runtime._range_http_verification", "mode": "composite"},
    "range.verify_paths": {"entrypoint": "engines.integrated_capability_runtime._range_http_verification", "mode": "composite"},
    "range.emit_200": {"entrypoint": "engines.integrated_capability_runtime._range_http_verification", "mode": "composite"},

    # Credential auditing remains opt-in and evidence-gated.  The range
    # adapter owns masscan parsing and the SSH adapter owns candidate bounds
    # and connection attempts; no fallback is made from a bare hostname.
    "credential.run_masscan": {"entrypoint": "engines.recon_core.CoreRun.run_range_surface", "mode": "composite"},
    "credential.parse_masscan_output": {"entrypoint": "engines.recon_core.CoreRun.run_range_surface", "mode": "composite"},
    "credential.is_valid_ip": {"entrypoint": "engines.recon_core.is_ip_literal", "mode": "direct"},
    "credential.attempt_ssh_connection": {"entrypoint": "engines.integrated_capability_runtime._ssh_credential_audit", "mode": "composite"},
    "credential.candidate_bound": {"entrypoint": "engines.integrated_capability_runtime._service_targets", "mode": "direct"},

    # Attribution and web evidence consume the same target-scoped artifacts
    # as the current pipeline, with certificate names coming only from the
    # verified TLS inventory.
    "attribution.collect_subdomains": {"entrypoint": "engines.recon_core.CoreRun.discover", "mode": "composite"},
    "attribution.attribute_ips": {"entrypoint": "engines.recon_core.CoreRun.dns", "mode": "composite"},
    "attribution.nmap_vuln": {"entrypoint": "engines.recon_core.CoreRun.consumers", "mode": "composite"},
    "web.extract_domain": {"entrypoint": "engines.runner.target_host", "mode": "direct"},
    "web.crawl": {"entrypoint": "engines.recon_core.CoreRun.content", "mode": "composite"},
    "web.dedupe_urls": {"entrypoint": "engines.web_chain_runtime._urls_from_text", "mode": "direct"},
    "web.classify_files": {"entrypoint": "engines.recon_core.CoreRun.crawl_projections", "mode": "composite"},
    "web.filter_domains": {"entrypoint": "engines.web_chain_runtime._allowed_origin_set", "mode": "direct"},
    "web.dns_records": {"entrypoint": "engines.recon_core.CoreRun.dns", "mode": "composite"},
    "web.certificate_names": {"entrypoint": "engines.tls_inventory.collect", "mode": "composite"},
    "web.ip_attribution": {"entrypoint": "engines.inventory_runtime.build_inventory", "mode": "composite"},
    "web.linked_crawl": {"entrypoint": "engines.recon_core.CoreRun.crawl_projections", "mode": "composite"},
    "web.contacts": {"entrypoint": "engines.recon_core.CoreRun.crawl_projections", "mode": "composite"},
    "web.injection_queue": {"entrypoint": "engines.recon_core.CoreRun.build_queues", "mode": "composite"},
    "web.followup_menu": {"entrypoint": "engines.runner.UnifiedRun.dispatch_followups", "mode": "composite"},

    # ORC/device follow-up is a companion contract, not one of the ten core
    # legacy source families.  It is still validated here so it cannot drift.
    "device_followup.range_scan": {"entrypoint": "engines.device_followup_runtime.run", "mode": "composite"},
    "device_followup.model_rules": {"entrypoint": "engines.camera_surface.read_signatures", "mode": "direct"},
    "device_followup.port_rules": {"entrypoint": "engines.device_followup_runtime._read_ports", "mode": "direct"},
    "device_followup.fingerprint_probe": {"entrypoint": "engines.camera_surface.fingerprint_matches", "mode": "direct"},
}


@lru_cache(maxsize=None)
def resolve_runtime_binding(entrypoint: str) -> Any:
    """Resolve a dotted module/class/function path and require callability."""
    value = str(entrypoint).strip()
    if not value:
        raise RuntimeError("empty runtime entrypoint")
    # Source checkouts keep the vendored package under ``vendor/`` while an
    # installed wheel exposes it as a top-level ``ahpuch_modules`` package.
    # Make the source layout behave like the installed layout without making
    # callers know which layout they are executing from.
    if value.startswith("ahpuch_modules."):
        vendor = str(ROOT / "vendor")
        if (ROOT / "vendor" / "ahpuch_modules").is_dir() and vendor not in sys.path:
            sys.path.insert(0, vendor)
    parts = value.split(".")
    for module_end in range(len(parts), 0, -1):
        module_name = ".".join(parts[:module_end])
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            # A class/function suffix is not a module.  In that case Python
            # reports the longest importable prefix as ``exc.name``; keep
            # walking backwards.  A genuinely missing dependency does not
            # form a prefix of the requested module and must remain an error.
            if exc.name and module_name.startswith(exc.name):
                continue
            raise RuntimeError(f"runtime entrypoint dependency unavailable: {value}: {exc}") from exc
        current: Any = module
        try:
            for attribute in parts[module_end:]:
                current = getattr(current, attribute)
        except AttributeError as exc:
            raise RuntimeError(f"runtime entrypoint attribute unavailable: {value}") from exc
        if not callable(current):
            raise RuntimeError(f"runtime entrypoint is not callable: {value}")
        return current
    raise RuntimeError(f"runtime entrypoint module unavailable: {value}")


def _runtime_binding(function_id: str) -> dict[str, Any]:
    raw = RUNTIME_BINDINGS.get(str(function_id))
    if not raw:
        return {
            "entrypoint": "",
            "mode": "unbound",
            "callable": False,
            "error": "no runtime binding declared",
        }
    entrypoint = str(raw.get("entrypoint", "")).strip()
    try:
        resolve_runtime_binding(entrypoint)
    except (ImportError, RuntimeError, AttributeError, TypeError) as exc:
        return {
            "entrypoint": entrypoint,
            "mode": str(raw.get("mode", "composite")),
            "callable": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "entrypoint": entrypoint,
        "mode": str(raw.get("mode", "composite")),
        "callable": True,
        "error": "",
    }


def runtime_binding_errors(*, include_companions: bool = True) -> list[dict[str, str]]:
    """Return every matrix row whose executable bridge is absent or invalid."""
    errors: list[dict[str, str]] = []
    payload = load_matrix()
    groups = [payload["sources"]]
    if include_companions:
        groups.append(payload["companions"])
    for group in groups:
        for source_id, source in group.items():
            for row in source["functions"]:
                function_id = str(row["id"])
                binding = _runtime_binding(function_id)
                if not binding["callable"]:
                    errors.append({
                        "function_id": function_id,
                        "source_id": str(source_id),
                        "entrypoint": str(binding["entrypoint"]),
                        "error": str(binding["error"]),
                    })
    return sorted(errors, key=lambda row: row["function_id"])


@lru_cache(maxsize=1)
def load_matrix(path: Path = MATRIX_PATH) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"legacy capability matrix unavailable: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError("legacy capability matrix must use schema_version 1")
    sources = payload.get("sources")
    companions = payload.get("companions")
    if not isinstance(sources, dict) or len(sources) != CORE_SOURCE_COUNT:
        raise RuntimeError(f"legacy capability matrix must contain {CORE_SOURCE_COUNT} core sources")
    if not isinstance(companions, dict):
        raise RuntimeError("legacy capability matrix companions must be an object")
    seen: set[str] = set()
    for group_name, group in (("sources", sources), ("companions", companions)):
        for source_id, source in group.items():
            if not isinstance(source_id, str) or not source_id or not isinstance(source, dict):
                raise RuntimeError(f"invalid {group_name} source row")
            paths = source.get("source_paths")
            functions = source.get("functions")
            if not isinstance(paths, list) or not paths or any(not str(value).strip() for value in paths):
                raise RuntimeError(f"{source_id} has no valid source_paths")
            if not isinstance(functions, list) or not functions:
                raise RuntimeError(f"{source_id} has no function rows")
            for row in functions:
                if not isinstance(row, dict):
                    raise RuntimeError(f"{source_id} contains a non-object function row")
                required = {"id", "source", "adapter", "canonical_capability", "evidence", "contact", "parallel_group", "outputs"}
                missing = required - set(row)
                if missing:
                    raise RuntimeError(f"{source_id} function row missing {sorted(missing)}")
                function_id = str(row["id"])
                if not function_id or function_id in seen:
                    raise RuntimeError(f"duplicate or empty legacy function id: {function_id!r}")
                seen.add(function_id)
                if str(row["adapter"]) not in KNOWN_ADAPTERS:
                    raise RuntimeError(f"unknown legacy adapter for {function_id}: {row['adapter']}")
                if str(row["canonical_capability"]) not in KNOWN_CAPABILITIES:
                    raise RuntimeError(f"unknown canonical capability for {function_id}: {row['canonical_capability']}")
                unknown_evidence = set(str(value) for value in row["evidence"]) - KNOWN_EVIDENCE
                if unknown_evidence:
                    raise RuntimeError(f"unknown evidence flag for {function_id}: {sorted(unknown_evidence)}")
                for key in ("evidence", "outputs"):
                    if not isinstance(row[key], list) or not row[key] or any(not str(value).strip() for value in row[key]):
                        raise RuntimeError(f"{function_id} has invalid {key}")
    return payload


def function_rows(*, include_companions: bool = True) -> list[dict[str, Any]]:
    payload = load_matrix()
    groups = [payload["sources"]]
    if include_companions:
        groups.append(payload["companions"])
    rows: list[dict[str, Any]] = []
    for group in groups:
        for source_id, source in group.items():
            for function in source["functions"]:
                binding = _runtime_binding(str(function["id"]))
                rows.append({
                    **function,
                    "source_id": source_id,
                    "source_label": str(source.get("label", source_id)),
                    "source_root": str(source.get("root", "")),
                    "source_paths": [str(value) for value in source["source_paths"]],
                    "runtime_entrypoint": str(binding["entrypoint"]),
                    "runtime_mode": str(binding["mode"]),
                    "runtime_callable": bool(binding["callable"]),
                    "runtime_error": str(binding["error"]),
                })
    return sorted(rows, key=lambda row: (str(row["source_id"]), str(row["id"])))


def source_rows(*, include_companions: bool = True) -> dict[str, dict[str, Any]]:
    payload = load_matrix()
    result = dict(payload["sources"])
    if include_companions:
        result.update(payload["companions"])
    return result


def capabilities_for_sources(source_ids: Iterable[str], *, include_companions: bool = True) -> set[str]:
    selected = {str(value) for value in source_ids}
    return {
        str(row["canonical_capability"])
        for row in function_rows(include_companions=include_companions)
        if str(row["source_id"]) in selected
    }


def rows_for_capabilities(capabilities: Iterable[str], *, include_companions: bool = True) -> list[dict[str, Any]]:
    selected = {str(value) for value in capabilities}
    return [row for row in function_rows(include_companions=include_companions) if str(row["canonical_capability"]) in selected]


def parallel_batches(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group independent legacy functions without changing dependency order."""
    groups: dict[str, list[str]] = {}
    for row in rows:
        groups.setdefault(str(row["parallel_group"]), []).append(str(row["id"]))
    return [
        {"parallel_group": group, "function_ids": sorted(values), "max_workers": len(values)}
        for group, values in sorted(groups.items())
    ]


def evidence_flags(*, verified_http: int = 0, parameterized_urls: int = 0, services: int = 0,
                   ssh_services: int = 0, industrial_indicators: int = 0,
                   camera_fingerprints: int = 0, local_products: int = 0,
                   range_inputs: int = 0, local_sources: int = 0) -> dict[str, int]:
    values = {name: 0 for name in KNOWN_EVIDENCE}
    values.update({
        "verified-http-origin": max(0, int(verified_http)),
        "verified-parameterized-url": max(0, int(parameterized_urls)),
        "concrete-service": max(0, int(services)),
        "concrete-host-or-service": max(0, int(services)),
        "observed-ssh-service": max(0, int(ssh_services)),
        "ics-keyword": max(0, int(industrial_indicators)),
        "camera-fingerprint": max(0, int(camera_fingerprints)),
        "verified-fingerprint": max(0, int(camera_fingerprints)),
        "in-scope-camera-endpoint": max(0, int(camera_fingerprints)),
        "local-product-version": max(0, int(local_products)),
        "local-cve-corpus": max(0, int(local_sources)),
        "local-notebook": max(0, int(local_sources)),
        "local-dictionary-source": max(0, int(local_sources)),
        "local-path-dictionary": max(0, int(local_sources)),
        "operator-range": max(0, int(range_inputs)),
        "bounded-paths": max(0, int(range_inputs)),
        "target-bound-input": max(0, int(services or verified_http or local_sources)),
        "typed-evidence": max(0, int(verified_http or services or local_sources)),
        "module-output": max(0, int(local_sources)),
        "local-artifacts": max(0, int(local_sources)),
        "offline-index": max(0, int(local_sources)),
    })
    return values


def dispatch_plan(capabilities: Iterable[str], evidence: dict[str, int] | None = None) -> dict[str, Any]:
    """Return an auditable eligibility plan; this function never contacts targets."""
    flags = evidence or {}
    rows = rows_for_capabilities(capabilities, include_companions=True)
    dispatch: list[dict[str, Any]] = []
    for row in rows:
        requirements = [str(value) for value in row["evidence"]]
        missing = [value for value in requirements if int(flags.get(value, 0)) <= 0]
        binding_error = str(row.get("runtime_error", "")).strip()
        eligible = not missing and not binding_error
        if binding_error:
            status = "configuration-error"
            reason = "runtime binding unavailable: " + binding_error
        elif missing:
            status = "not-eligible"
            reason = "missing evidence: " + ", ".join(missing)
        else:
            status = "eligible"
            reason = "all required evidence present"
        dispatch.append({
            "function_id": row["id"],
            "source_id": row["source_id"],
            "canonical_capability": row["canonical_capability"],
            "adapter": row["adapter"],
            "parallel_group": row["parallel_group"],
            "contact": row["contact"],
            "required_evidence": requirements,
            "runtime_entrypoint": row["runtime_entrypoint"],
            "runtime_mode": row["runtime_mode"],
            "runtime_callable": row["runtime_callable"],
            "runtime_error": row["runtime_error"],
            "eligible": eligible,
            "status": status,
            "reason": reason,
        })
    return {
        "schema_version": 1,
        "selected_capabilities": sorted({str(value) for value in capabilities}),
        "evidence": dict(sorted(flags.items())),
        "functions": dispatch,
        "parallel_batches": parallel_batches(rows),
    }


def matrix_summary() -> dict[str, Any]:
    payload = load_matrix()
    rows = function_rows(include_companions=True)
    return {
        "schema_version": int(payload["schema_version"]),
        "core_sources": len(payload["sources"]),
        "companion_sources": len(payload["companions"]),
        "core_functions": sum(len(source["functions"]) for source in payload["sources"].values()),
        "companion_functions": sum(len(source["functions"]) for source in payload["companions"].values()),
        "functions": len(rows),
        "runtime_bindings": sum(bool(row["runtime_callable"]) for row in rows),
        "runtime_binding_errors": runtime_binding_errors(include_companions=True),
        "adapters": sorted({str(row["adapter"]) for row in rows}),
        "canonical_capabilities": sorted({str(row["canonical_capability"]) for row in rows}),
        "parallel_groups": sorted({str(row["parallel_group"]) for row in rows}),
    }
