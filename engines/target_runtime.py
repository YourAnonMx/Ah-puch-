#!/usr/bin/env python3
"""Per-target isolation and batch-result evidence for the public Ah-Puch entry."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from .target_contract import public_target, target_kind, target_sha256
    from .runtime_hardening import atomic_json
except ImportError:
    from target_contract import public_target, target_kind, target_sha256
    from runtime_hardening import atomic_json

_BATCH_RECORDS: list[dict[str, Any]] = []
PARTIAL_EXIT_CODE = 3


def _status_for_exit_code(value: int) -> str:
    code = int(value)
    if code == 0:
        return "success"
    if code == PARTIAL_EXIT_CODE:
        return "partial"
    return "failed"


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    atomic_json(path, value)


def _artifact_summary(root: Path) -> dict[str, Any]:
    path = root / "artifacts" / "summary.json"
    if not path.is_file():
        return {"records": 0, "observations": 0, "promotable": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"records": 0, "observations": 0, "promotable": {}}
    if not isinstance(value, dict):
        return {"records": 0, "observations": 0, "promotable": {}}
    return {
        "records": int(value.get("records", 0) or 0),
        "observations": int(value.get("observations", 0) or 0),
        "promotable": value.get("promotable", {}) if isinstance(value.get("promotable"), dict) else {},
    }


def begin() -> None:
    _BATCH_RECORDS.clear()


def records() -> list[dict[str, Any]]:
    return [dict(row) for row in _BATCH_RECORDS]


def finish(process_exit_code: int) -> list[Path]:
    """Write one truthful aggregate result per output root used by the invocation."""
    if not _BATCH_RECORDS:
        return []
    by_output: dict[str, list[dict[str, Any]]] = {}
    for source in _BATCH_RECORDS:
        row = dict(source)
        output_root = str(row.pop("_output_root", ""))
        if output_root:
            by_output.setdefault(output_root, []).append(row)
    written: list[Path] = []
    for output, rows in sorted(by_output.items()):
        material = "|".join(str(row.get("target_sha256", "")) + ":" + str(row.get("run_id", "")) for row in rows)
        batch_id = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
        target_statuses = [str(row.get("status", _status_for_exit_code(int(row.get("exit_code", 0))))) for row in rows]
        successes = sum(status == "success" for status in target_statuses)
        partials = sum(status == "partial" for status in target_statuses)
        failures = len(rows) - successes - partials
        process_status = _status_for_exit_code(process_exit_code)
        if failures or process_status == "failed":
            batch_status = "failed"
        elif partials or process_status == "partial":
            batch_status = "partial"
        else:
            batch_status = "success"
        summary = {
            "schema_version": 1,
            "batch_id": batch_id,
            "process_exit_code": int(process_exit_code),
            "status": batch_status,
            "targets_total": len(rows),
            "targets_success": successes,
            "targets_partial": partials,
            "targets_failed": failures,
            "targets": rows,
        }
        path = Path(output) / f"target-batch-{batch_id}.json"
        _atomic_json(path, summary)
        written.append(path)
    return written


def _reconcile_checkpoint(run: Any, rc: int) -> None:
    """Make the final checkpoint agree with the target terminal contract."""
    path = Path(getattr(run, "checkpoint_path", run.root / "checkpoint.json"))
    if not path.is_file():
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    payload["status"] = _status_for_exit_code(rc)
    payload["exit_code"] = int(rc)
    _atomic_json(path, payload)


def install(base: Any) -> Any:
    """Wrap the already composed public UnifiedRun and retain per-target truth."""
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_target_runtime", False):
        return base

    class TargetContractUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_target_runtime = True

        def write_module_text(self, destination: Path, event: dict[str, Any], status: str, body: str) -> None:
            """Honor the shared catalog partial exit code before evidence is written."""
            try:
                exit_code = int(event.get("exit_code", -1))
            except (TypeError, ValueError):
                exit_code = -1
            if event.get("engine") == "ahpuch_modules" and exit_code == PARTIAL_EXIT_CODE:
                status = "partial"
                event = {**event, "status": "partial", "terminal_reconciled": True}
            super().write_module_text(destination, event, status, body)

        def finish(self) -> int:
            rc = super().finish()
            output_root = Path(self.args.output).expanduser().resolve()
            target_public = public_target(self.target)
            bus = _artifact_summary(self.root)
            record = {
                "schema_version": 2,
                "target": target_public,
                "target_sha256": target_sha256(self.target),
                "input_kind": target_kind(self.target),
                "run_id": self.root.name,
                "input_contract": {
                    "required": "one target input",
                    "accepted": "domain, HTTP(S) URL, IP/IPv6, host:port, or CIDR range",
                    "scope_source": "operator target",
                },
                "access_policy": {
                    "interactive_auth_required": False,
                    "credential_input_required": False,
                    "api_keys_required": False,
                    "authorization_manifest_required": False,
                    "optional_auth_flags": ["--credential-audit", "--auth-validate"],
                },
                "profile": str(self.args.profile),
                "target_boundary": {
                    "source": "operator-target",
                    "mode": "automatic",
                    "targets_file_is_complete_input": True,
                },
                "exit_code": int(rc),
                "status": _status_for_exit_code(rc),
                "artifact_bus": bus,
            }
            _atomic_json(self.root / "target-contract.json", record)
            _BATCH_RECORDS.append({**record, "_output_root": str(output_root)})
            return rc

        def execute(self) -> int:
            rc = super().execute()
            _reconcile_checkpoint(self, rc)
            # Base execute writes its final checkpoint after calling finish().
            # Seal only after that last mutation so saved-run integrity describes
            # the actual terminal files rather than the pre-checkpoint snapshot.
            base.reseal_saved_run(self.root)
            return rc

    TargetContractUnifiedRun.__name__ = "TargetContractUnifiedRun"
    TargetContractUnifiedRun.__qualname__ = "TargetContractUnifiedRun"
    base.UnifiedRun = TargetContractUnifiedRun
    return base
