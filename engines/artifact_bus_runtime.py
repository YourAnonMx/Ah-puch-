#!/usr/bin/env python3
"""Production lifecycle integration for the normalized Ah-Puch artifact bus."""
from __future__ import annotations

import json
from typing import Any

try:
    from .artifact_bus import ArtifactBus, sync_sources
except ImportError:
    from artifact_bus import ArtifactBus, sync_sources


def _dedupe_observations(row: dict[str, Any]) -> None:
    observations = row.get("observations", [])
    if not isinstance(observations, list):
        return
    unique: dict[str, dict[str, Any]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        encoded = json.dumps(observation, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        unique.setdefault(encoded, observation)
    row["observations"] = [unique[key] for key in sorted(unique)]


def normalize_graph_candidate_semantics(bus: ArtifactBus) -> int:
    """Keep topology discovery from masquerading as completed URL evidence.

    AssetGraph is authoritative for relationships and provenance, but a URL node
    being inside the target does not mean an HTTP/crawl observation completed. Explicit
    operator URL input remains promotable; graph-derived URL/path/parameter
    observations wait for their concrete HTTP/crawl producer adapter. Repeated
    lifecycle syncs remain idempotent after status normalization.
    """
    changed = 0
    graph_candidate_kinds = {"url", "origin", "path", "parameter"}
    for (kind, _key), row in bus.rows.items():
        if kind not in graph_candidate_kinds:
            continue
        observations = row.get("observations", [])
        if not isinstance(observations, list):
            continue

        # ``ingest_graph`` records the graph node with its real producer and,
        # for URL nodes, also projects origin/path/parameter components through
        # a synthetic ``asset-graph`` adapter observation.  The synthetic URL
        # observation is redundant once the direct graph-node observation is
        # present.  Remove only that compatibility projection so re-entry does
        # not inflate URL provenance while concrete producer provenance stays
        # intact.  Derived origin/path/parameter rows are intentionally kept.
        if kind == "url":
            has_direct_graph_url = any(
                isinstance(observation, dict)
                and observation.get("source") == "graph/assets.jsonl"
                and isinstance(observation.get("attributes"), dict)
                and observation["attributes"].get("graph_kind") == "url"
                for observation in observations
            )
            if has_direct_graph_url:
                filtered = [
                    observation
                    for observation in observations
                    if not (
                        isinstance(observation, dict)
                        and observation.get("source") == "graph/assets.jsonl"
                        and observation.get("producer") == "asset-graph"
                        and (
                            not isinstance(observation.get("attributes"), dict)
                            or observation["attributes"].get("graph_kind") != "url"
                        )
                    )
                ]
                removed = len(observations) - len(filtered)
                if removed:
                    row["observations"] = filtered
                    observations = filtered
                    changed += removed

        for observation in observations:
            if not isinstance(observation, dict) or observation.get("source") != "graph/assets.jsonl":
                continue
            producer = str(observation.get("producer", ""))
            wanted = "operator" if producer == "operator-target" else "graph-candidate"
            if observation.get("status") != wanted:
                observation["status"] = wanted
                changed += 1
        _dedupe_observations(row)
    return changed


def suppress_execution_pseudo_findings(bus: ArtifactBus) -> int:
    """Keep scanner execution evidence without promoting it as a finding.

    ``advanced-consumers/runs.jsonl`` proves that a runner executed; it does not
    prove that the runner found a vulnerability. Until a structured finding
    parser exists, those observations remain in provenance but are explicitly
    non-promotable. Repeated lifecycle syncs remain idempotent.
    """
    changed = 0
    for (kind, _key), row in bus.rows.items():
        if kind != "finding":
            continue
        observations = row.get("observations", [])
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            attributes = observation.get("attributes", {})
            if not isinstance(attributes, dict) or attributes.get("finding_type") != "consumer-execution":
                continue
            if observation.get("observed") is not False:
                observation["observed"] = False
                changed += 1
            status = str(observation.get("status", "unknown"))
            if not status.startswith("execution-"):
                observation["status"] = f"execution-{status}"
        _dedupe_observations(row)
    return changed


def install(base: Any) -> Any:
    """Wrap the already composed production UnifiedRun exactly once."""
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_artifact_bus", False):
        return base

    class ArtifactBusUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_artifact_bus = True

        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            self._artifact_bus_failed = False

        def _sync_artifact_bus(self, phase: str) -> dict[str, Any]:
            try:
                bus = ArtifactBus(self.root, self.target)
                sources = sync_sources(
                    bus,
                    self.root,
                    getattr(self, "graph", None),
                    self._allowed,
                    getattr(self, "_network_allowed", self._allowed),
                )
                graph_demotions = normalize_graph_candidate_semantics(bus)
                suppressed = suppress_execution_pseudo_findings(bus)
                summary = bus.save()
                self.event({
                    "engine": "artifact_bus",
                    "status": "success",
                    "phase": phase,
                    "records": summary["records"],
                    "observations": summary["observations"],
                    "promotable": sum(summary["promotable"].values()),
                    "graph_candidate_demotions": graph_demotions,
                    "suppressed_execution_pseudo_findings": suppressed,
                    "sources": sources,
                })
                return {
                    "status": "success",
                    **summary,
                    "sources": sources,
                    "graph_candidate_demotions": graph_demotions,
                    "suppressed_execution_pseudo_findings": suppressed,
                }
            except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
                self._artifact_bus_failed = True
                self.event({
                    "engine": "artifact_bus",
                    "status": "failed",
                    "phase": phase,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                return {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}

        def _apply_promoted_handoff(self, phase: str) -> None:
            """Replace discovered fan-out lists with the scope-safe bus queues."""
            bus = ArtifactBus(self.root, self.target)
            network_allowed = getattr(self, "_network_allowed", self._allowed)
            promoted_hosts = {
                str(row["value"])
                for kind in ("host", "ip")
                for row in bus.records(kind, promotable_only=True)
                if network_allowed(str(row["value"]))
            }
            promoted_urls = {
                str(row["value"])
                for kind in ("url", "origin")
                for row in bus.records(kind, promotable_only=True)
                if self._allowed(str(row["value"]))
            }
            old_hosts = set(self.seed_hosts)
            old_urls = set(self.seed_urls)
            self.seed_hosts = sorted(promoted_hosts)[: self.args.range_host_limit]
            self.seed_urls = sorted(promoted_urls)
            self.event({
                "engine": "artifact_bus_handoff",
                "status": "success",
                "phase": phase,
                "hosts": len(self.seed_hosts),
                "urls": len(self.seed_urls),
                "dropped_unpromoted_hosts": len(old_hosts - promoted_hosts),
                "dropped_unpromoted_urls": len(old_urls - promoted_urls),
            })

        def run_native(self) -> None:
            super().run_native()
            result = self._sync_artifact_bus("post-native")
            if result.get("status") == "success":
                self._apply_promoted_handoff("native-to-catalog")

        def run_catalog(self) -> None:
            super().run_catalog()
            result = self._sync_artifact_bus("post-catalog")
            if result.get("status") == "success":
                self._apply_promoted_handoff("catalog-to-device")

        def run_camera_surface(self) -> None:
            super().run_camera_surface()
            self._sync_artifact_bus("post-device")

        def finish(self) -> int:
            # Final pre-seal sync sees graph state plus every producer output.
            self._sync_artifact_bus("pre-finish")
            rc = super().finish()
            if self._artifact_bus_failed:
                rc = max(rc, 1)
            return rc

    ArtifactBusUnifiedRun.__name__ = "ArtifactBusUnifiedRun"
    ArtifactBusUnifiedRun.__qualname__ = "ArtifactBusUnifiedRun"
    base.UnifiedRun = ArtifactBusUnifiedRun
    return base
