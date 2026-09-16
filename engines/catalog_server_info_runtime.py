#!/usr/bin/env python3
"""Structured handoff for catalog module 10 (Server Info)."""
from __future__ import annotations

from typing import Any

try:
    from .artifact_bus import ArtifactBus
    from .catalog_artifact_runtime import _embedded_json, _result_path
except ImportError:
    from artifact_bus import ArtifactBus
    from catalog_artifact_runtime import _embedded_json, _result_path


def _server_info_from_result(path: Any) -> dict[str, Any]:
    payload = _embedded_json(path, "server_info.json")
    if not isinstance(payload, dict) or payload.get("state") != "success":
        return {}
    origin = str(payload.get("origin", "") or "").strip()
    host = str(payload.get("host", "") or "").strip().lower().rstrip(".")
    headers = payload.get("headers", {})
    if not origin.startswith(("http://", "https://")) or not host or not isinstance(headers, dict):
        return {}
    return {**payload, "origin": origin, "host": host, "headers": headers}


def _project_module_10(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    del input_value
    result = _result_path(base, run, item, index)
    payload = _server_info_from_result(result)
    if not payload:
        return

    origin = str(payload["origin"])
    host = str(payload["host"])
    within_target = bool(run._allowed(origin))
    bus = ArtifactBus(run.root, run.target)
    observed_origins = promoted_origins = observed_technology = promoted_technology = 0

    if bus.observe(
        "origin",
        origin,
        producer="catalog-module:10-server-info",
        source=str(result.relative_to(run.root)),
        status="verified",
        within_target=within_target,
        attributes={"host": host, "status_code": payload.get("status_code")},
    ):
        observed_origins = 1
        promoted_origins = int(within_target)

    header_map = {
        "server": "server-header",
        "x-powered-by": "x-powered-by",
        "via": "via-header",
    }
    for header, namespace in header_map.items():
        value = str(payload["headers"].get(header, "") or "").strip()
        if not value:
            continue
        if bus.observe(
            "technology",
            value,
            producer="catalog-module:10-server-info",
            source=str(result.relative_to(run.root)),
            status="verified",
            within_target=within_target,
            attributes={"host": host, "origin": origin, "namespace": namespace},
        ):
            observed_technology += 1
            promoted_technology += int(within_target)

    if observed_origins or observed_technology:
        bus.save()
    run.event(
        {
            "engine": "catalog_artifact_handoff",
            "module_id": "10",
            "module": str(item.get("name", "Server Info")),
            "status": "success",
            "observed_origins": observed_origins,
            "promoted_origins": promoted_origins,
            "observed_technology": observed_technology,
            "promoted_technology": promoted_technology,
        }
    )


def install(base: Any) -> Any:
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_catalog_server_info", False):
        return base

    class CatalogServerInfoUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_catalog_server_info = True

        def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
            super().run_catalog_module(item, input_value, index)
            if str(item.get("id", "")) == "10":
                _project_module_10(base, self, item, input_value, index)

    CatalogServerInfoUnifiedRun.__name__ = "CatalogServerInfoUnifiedRun"
    CatalogServerInfoUnifiedRun.__qualname__ = "CatalogServerInfoUnifiedRun"
    base.UnifiedRun = CatalogServerInfoUnifiedRun
    return base
