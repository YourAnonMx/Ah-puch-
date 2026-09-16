#!/usr/bin/env python3
"""SRC10 truthful orchestration terminal attribution.

This layer adds no execution capability. It prevents aggregate advanced-
consumer events from being reused as terminal evidence for sibling stages. Each
runner-backed native capability/profile stage is reduced from its own rows in
``advanced-consumers/runs.jsonl``; absence of matching evidence is ``skipped``.
A current native/profile partial also propagates to exit code 3 when no harder
failure already owns the process terminal.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

PARTIAL_EXIT_CODE = 3
RUNNER_BY_STAGE: dict[str, frozenset[str]] = {
    "template-assessment": frozenset({"template-checks"}),
    "web-server-assessment": frozenset({"web-server-check"}),
    "secondary-web-audit": frozenset({"web-audit-secondary"}),
    "proxy-passive": frozenset({"web-proxy-passive"}),
    "proxy-active": frozenset({"web-proxy-active"}),
    "parameter-validation": frozenset({"parameter-validation"}),
}
ENGINE_BY_STAGE: dict[str, frozenset[str]] = {
    "recon-dns": frozenset({"recon_core", "recon_core_v2"}),
    "http-inventory": frozenset({"http_inventory"}),
    "web-fanout": frozenset({"web_fanout"}),
    "tls-inventory": frozenset({"tls_inventory"}),
    "network-profile": frozenset({"network_profile_runtime"}),
    "device": frozenset({"device_surface"}),
}
_PRIORITY = {"failed": 6, "timeout": 5, "partial": 4, "skipped": 3, "planned": 2, "success": 1}
_ALLOWED = frozenset(_PRIORITY)


def _normalize_status(value: object) -> str:
    status = str(value or "").strip().lower()
    # Unknown terminal vocabulary must never become success. Preserve the run
    # as incomplete until a known producer contract is mapped explicitly.
    return status if status in _ALLOWED else "partial"


def reduce_statuses(values: Iterable[object], *, empty: str = "skipped") -> str:
    statuses = [_normalize_status(value) for value in values]
    if not statuses:
        return empty
    return max(statuses, key=lambda value: _PRIORITY[value])


def _runner_rows(root: Path, runner_ids: frozenset[str]) -> list[dict[str, Any]]:
    path = Path(root) / "advanced-consumers" / "runs.jsonl"
    if not path.is_file() or path.is_symlink():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and str(row.get("runner", "")) in runner_ids:
            rows.append(row)
    return rows


def stage_terminal(run: Any, stage: str) -> tuple[str, int, str]:
    """Return terminal status, evidence count and evidence source for one stage."""
    empty = "planned" if bool(getattr(getattr(run, "args", None), "dry_run", False)) else "skipped"
    runner_ids = RUNNER_BY_STAGE.get(str(stage))
    if runner_ids is not None:
        rows = _runner_rows(Path(run.root), runner_ids)
        return reduce_statuses((row.get("status") for row in rows), empty=empty), len(rows), "advanced-consumers/runs.jsonl"
    engines = ENGINE_BY_STAGE.get(str(stage), frozenset())
    statuses = [
        row.get("status")
        for row in getattr(run, "events", [])
        if isinstance(row, dict) and row.get("engine") in engines
    ]
    return reduce_statuses(statuses, empty=empty), len(statuses), "module_status.jsonl"


def _has_current_partial(events: Iterable[dict[str, Any]]) -> bool:
    return any(
        isinstance(row, dict)
        and row.get("engine") in {"native_capability_terminal", "profile_stage_terminal"}
        and str(row.get("status", "")).strip().lower() == "partial"
        for row in events
    )


def _progress_terminal_label(exit_code: int) -> str:
    if int(exit_code) == 0:
        return "run complete"
    if int(exit_code) == PARTIAL_EXIT_CODE:
        return "run completed partially"
    return "run completed with failures"


def install(base: Any) -> Any:
    """Wrap the composed run so terminal evidence is capability-specific."""
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_orchestration_terminal", False):
        return base

    class OrchestrationTerminalUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_orchestration_terminal = True

        def event(self, value: dict[str, Any]) -> None:
            row = dict(value)
            if row.get("engine") == "native_capability_terminal":
                capability = str(row.get("capability", ""))
                if capability in RUNNER_BY_STAGE or capability in ENGINE_BY_STAGE:
                    status, count, source = stage_terminal(self, capability)
                    row["status"] = status
                    row["evidence_events"] = count
                    row["evidence_source"] = source
                    if capability in RUNNER_BY_STAGE:
                        row["evidence_runners"] = sorted(RUNNER_BY_STAGE[capability])
                    else:
                        row["evidence_engines"] = sorted(ENGINE_BY_STAGE[capability])
                    row["terminal_reconciled"] = True
            super().event(row)

        def _emit_profile_stage_terminals(self) -> None:
            profile_capabilities = {"profile-baseline", "profile-full", "profile-deep"}
            for capability in sorted(getattr(self, "native_capabilities", set()) & profile_capabilities):
                stages = base.PROFILE_STAGE_MATRIX.get(capability, frozenset())
                for stage in sorted(stages):
                    status, count, source = stage_terminal(self, stage)
                    row = {
                        "engine": "profile_stage_terminal",
                        "profile": capability,
                        "stage": stage,
                        "status": status,
                        "evidence_events": count,
                        "evidence_source": source,
                    }
                    if stage in RUNNER_BY_STAGE:
                        row["evidence_runners"] = sorted(RUNNER_BY_STAGE[stage])
                    else:
                        row["evidence_engines"] = sorted(ENGINE_BY_STAGE.get(stage, frozenset()))
                    self.event(row)

        def finish(self) -> int:
            rc = int(super().finish())
            if rc == 0 and _has_current_partial(getattr(self, "events", [])):
                return PARTIAL_EXIT_CODE
            return rc

        def execute(self) -> int:
            """Emit one final progress line using the reconciled process terminal."""
            progress = getattr(self, "progress", None)
            original_finish = getattr(progress, "finish", None)
            deferred: list[str] = []
            if callable(original_finish):
                progress.finish = lambda label="complete": deferred.append(str(label))
            try:
                rc = int(super().execute())
            finally:
                if callable(original_finish):
                    progress.finish = original_finish
            if callable(original_finish):
                original_finish(_progress_terminal_label(rc))
            return rc

    OrchestrationTerminalUnifiedRun.__name__ = "OrchestrationTerminalUnifiedRun"
    OrchestrationTerminalUnifiedRun.__qualname__ = "OrchestrationTerminalUnifiedRun"
    base.UnifiedRun = OrchestrationTerminalUnifiedRun
    return base
