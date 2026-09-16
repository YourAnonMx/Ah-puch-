#!/usr/bin/env python3
"""Structured handoff for catalog module 8 (IP Info).

This wrapper extends the canonical catalog-artifact chain without scraping
arbitrary stdout. Only the module's structured ``ip_info.json`` success payload
is eligible for current-scope projection.
"""
from __future__ import annotations

import ipaddress
from typing import Any

try:
    from .artifact_bus import ArtifactBus
    from .catalog_artifact_runtime import _embedded_json, _project_host_assets, _result_path
except ImportError:
    from artifact_bus import ArtifactBus
    from catalog_artifact_runtime import _embedded_json, _project_host_assets, _result_path


def _ip_info_from_result(path: Any) -> dict[str, Any]:
    payload = _embedded_json(path, "ip_info.json")
    if not isinstance(payload, dict) or payload.get("state") != "success":
        return {}
    try:
        canonical_ip = str(ipaddress.ip_address(str(payload.get("ip", "")).strip()))
    except ValueError:
        return {}
    data = payload.get("data", {})
    if not isinstance(data, dict):
        return {}
    return {**payload, "ip": canonical_ip, "data": data}


def _project_module_8(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    result = _result_path(base, run, item, index)
    payload = _ip_info_from_result(result)
    if not payload:
        return

    ip = str(payload["ip"])
    source_host = str(payload.get("host", "") or "").strip().lower().rstrip(".")
    promoted, observed_assets = _project_host_assets(
        base,
        run,
        source_host=source_host,
        addresses=[ip],
        hosts=[],
        producer="catalog-module:8-ip-info",
    )

    allow_network = getattr(run, "_network_allowed", run._allowed)
    within_target = bool(allow_network(ip))
    data = payload["data"]
    asn = str(data.get("asn", "") or "").strip()
    org = str(data.get("org", "") or "").strip()
    country = str(data.get("country_name", "") or data.get("country", "") or "").strip()
    metadata_value = " | ".join(part for part in (asn, org, country) if part)

    metadata_observed = metadata_promoted = 0
    if metadata_value:
        bus = ArtifactBus(run.root, run.target)
        if bus.observe(
            "fingerprint",
            metadata_value,
            producer="catalog-module:8-ip-info",
            source=str(result.relative_to(run.root)),
            status="success",
            within_target=within_target,
            attributes={
                "namespace": "ip-network-metadata",
                "ip": ip,
                "provider": str(payload.get("provider", "")),
            },
        ):
            metadata_observed = 1
            metadata_promoted = int(within_target)
            bus.save()

    run.event(
        {
            "engine": "catalog_artifact_handoff",
            "module_id": "8",
            "module": str(item.get("name", "IP Info")),
            "status": "success",
            "observed_assets": observed_assets,
            "promoted_assets": len(promoted),
            "quarantined_assets": observed_assets - len(promoted),
            "observed_metadata": metadata_observed,
            "promoted_metadata": metadata_promoted,
        }
    )


def install(base: Any) -> Any:
    """Wrap catalog dispatch exactly once for module 8 structured projection."""
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_catalog_ip_info", False):
        return base

    class CatalogIPInfoUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_catalog_ip_info = True

        def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
            super().run_catalog_module(item, input_value, index)
            if str(item.get("id", "")) == "8":
                _project_module_8(base, self, item, input_value, index)

    CatalogIPInfoUnifiedRun.__name__ = "CatalogIPInfoUnifiedRun"
    CatalogIPInfoUnifiedRun.__qualname__ = "CatalogIPInfoUnifiedRun"
    base.UnifiedRun = CatalogIPInfoUnifiedRun
    return base
