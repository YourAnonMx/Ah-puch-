#!/usr/bin/env python3
"""Lifecycle adapter for the typed multi-method recon coordinator."""
from __future__ import annotations

from typing import Any

try:
    from .pipeline_coordinator import PipelineCoordinator
except ImportError:
    from pipeline_coordinator import PipelineCoordinator


def install(base: Any) -> Any:
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_typed_pipeline", False):
        return base

    class TypedPipelineUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_typed_pipeline = True

        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            self._typed_pipeline = PipelineCoordinator(self)

        def run_native(self) -> None:
            super().run_native()
            result = self._typed_pipeline.run_pipeline()
            self.event({
                "engine": "typed_pipeline",
                "status": str(result.get("status", "failed")),
                "profile": str(self.args.profile),
                "mode": str(self.args.pipeline_mode),
                "rounds": int(result.get("rounds", 0) or 0),
                "converged": bool(result.get("converged", False)),
                "records": int(result.get("records", 0) or 0),
                "artifact": "typed-pipeline/summary.json",
            })
            if result.get("status") in {"success", "partial", "planned"}:
                sync = getattr(self, "_sync_artifact_bus", None)
                handoff = getattr(self, "_apply_promoted_handoff", None)
                sync_result = {"status": "skipped"}
                if callable(sync):
                    sync_result = sync("post-typed-pipeline")
                if callable(handoff) and sync_result.get("status") == "success":
                    handoff("typed-pipeline-to-catalog")

    TypedPipelineUnifiedRun.__name__ = "TypedPipelineUnifiedRun"
    TypedPipelineUnifiedRun.__qualname__ = "TypedPipelineUnifiedRun"
    base.UnifiedRun = TypedPipelineUnifiedRun
    return base
