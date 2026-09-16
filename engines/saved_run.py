#!/usr/bin/env python3
"""Network-free inspection helpers for completed Ah-Puch runs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


TEXT_LIMIT = 8_000_000
_DEVICE_STATE_SUFFIXES = (".device-state.json", ".device-network-state.json", ".camera-state.json")


def _regular_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _root(value: Path) -> Path:
    supplied = value.expanduser()
    if supplied.is_symlink():
        raise ValueError("saved run root may not be a symlink")
    root = supplied.resolve()
    manifest = root / "manifest.json"
    if not root.is_dir() or not _regular_file(manifest):
        raise ValueError("saved run must be a directory containing a regular manifest.json")
    return root


def _files(root: Path) -> list[Path]:
    result: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            continue
        result.append(path)
    return result


def _device_contract_ok(state_path: Path) -> bool:
    """Validate the current SRC09 sidecar/snapshot binding without imports or I/O outside the run."""
    sidecar = state_path.with_name(state_path.name + ".src09-contract.json")
    if not _regular_file(state_path) or not _regular_file(sidecar):
        return False
    try:
        metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(metadata, dict):
        return False
    expected_state = str(metadata.get("checkpoint_sha256", ""))
    expected_inventory = str(metadata.get("inventory_sha256", ""))
    inventory_name = str(metadata.get("inventory_file", "")).strip()
    if not expected_state or not expected_inventory or not inventory_name:
        return False
    if _sha256(state_path) != expected_state:
        return False
    inventory = sidecar.parent / inventory_name
    try:
        inventory.resolve().relative_to(sidecar.parent.resolve())
    except (OSError, ValueError):
        return False
    return bool(_regular_file(inventory) and _sha256(inventory) == expected_inventory)


def _resume_state_eligible(path: Path, state: dict[str, Any]) -> bool:
    """Apply the actual terminal shape used by general and device checkpoints."""
    if path.name == "checkpoint.json":
        return str(state.get("stage", "")).strip().lower() not in {"complete", "failed"}
    if path.name.endswith(_DEVICE_STATE_SUFFIXES):
        return state.get("complete") is False and _device_contract_ok(path)
    return False


def inspect_saved_run(path: Path, operation: str, *, query: str = "", compare: Path | None = None) -> dict[str, Any]:
    root = _root(path)
    if operation in {"view", "view-module", "view-runner"}:
        files = _files(root)
        if operation == "view-module":
            files = [item for item in files if "ahpuch_modules" in item.relative_to(root).parts]
        elif operation == "view-runner":
            files = [item for item in files if any(part in {"core", "web-fanout", "advanced-consumers", "network-profile-runtime", "runner-registry"} for part in item.relative_to(root).parts)]
        if query:
            files = [item for item in files if query.casefold() in str(item.relative_to(root)).casefold()]
        samples = {}
        for item in files[:100]:
            if item.stat().st_size <= TEXT_LIMIT:
                samples[str(item.relative_to(root))] = item.read_text(encoding="utf-8", errors="replace")[:4000]
        return {"operation": operation, "files": [str(item.relative_to(root)) for item in files], "samples": samples}
    if operation == "grep":
        if not query:
            raise ValueError("grep operation requires a non-empty query")
        matches = []
        for item in _files(root):
            if item.stat().st_size > TEXT_LIMIT:
                continue
            try:
                lines = item.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                if query.casefold() in line.casefold():
                    matches.append({"path": str(item.relative_to(root)), "line": number, "text": line[:1000]})
                    if len(matches) >= 1000:
                        break
        return {"operation": operation, "query": query, "matches": matches}
    if operation in {"inventory", "receipts"}:
        base = root / ("inventory" if operation == "inventory" else "receipts")
        files = [item for item in _files(root) if item.is_relative_to(base)] if base.is_dir() else []
        return {"operation": operation, "files": [str(item.relative_to(root)) for item in files], "rows": sum(len(item.read_text(encoding="utf-8", errors="replace").splitlines()) for item in files)}
    if operation == "resume":
        candidates: list[Path] = [root / "checkpoint.json"]
        for suffix in _DEVICE_STATE_SUFFIXES:
            candidates.extend(sorted(root.rglob(f"*{suffix}")))
        states = []
        for item in sorted(set(candidates), key=lambda value: str(value)):
            if not _regular_file(item):
                continue
            try:
                state = json.loads(item.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                state = "invalid"
            eligible = bool(isinstance(state, dict) and _resume_state_eligible(item, state))
            states.append({
                "path": str(item.relative_to(root)),
                "state": state,
                "resume_eligible": eligible,
                "src09_contract_ok": bool(
                    isinstance(state, dict)
                    and item.name.endswith(_DEVICE_STATE_SUFFIXES)
                    and _device_contract_ok(item)
                ),
            })
        eligible = [row["path"] for row in states if row.get("resume_eligible")]
        recovery_path = root / "runtime" / "recovery.json"
        recovery: dict[str, Any] | None = None
        if _regular_file(recovery_path):
            try:
                loaded = json.loads(recovery_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    recovery = loaded
            except (OSError, json.JSONDecodeError):
                recovery = {"status": "invalid"}
        return {"operation": operation, "checkpoints": states, "resume_eligible": eligible, "recovery": recovery}
    if operation == "compare":
        other = _root(compare) if compare else None
        if other is None:
            raise ValueError("compare operation requires a second saved run")

        def index(base: Path) -> dict[str, str]:
            return {str(item.relative_to(base)): hashlib.sha256(item.read_bytes()).hexdigest() for item in _files(base)}

        left, right = index(root), index(other)
        return {
            "operation": operation,
            "added": sorted(right.keys() - left.keys()),
            "removed": sorted(left.keys() - right.keys()),
            "changed": sorted(key for key in left.keys() & right.keys() if left[key] != right[key]),
        }
    raise ValueError(f"unknown saved-run operation: {operation}")
