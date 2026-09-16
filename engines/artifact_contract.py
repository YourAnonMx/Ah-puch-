#!/usr/bin/env python3
"""Native-runner artifact validation and honest terminal classification."""
from __future__ import annotations

import stat
from pathlib import Path


def inspect_artifact(path: Path, *, required: bool = True, require_nonempty: bool = False, max_bytes: int = 100_000_000) -> dict:
    row = {"path": str(path), "required": required, "exists": False, "valid": not required}
    try:
        metadata = path.stat()
    except OSError as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
        return row
    row.update({"exists": True, "bytes": metadata.st_size, "mode": oct(metadata.st_mode & 0o777), "regular": stat.S_ISREG(metadata.st_mode)})
    valid = bool(row["regular"]) and metadata.st_size <= max_bytes
    if require_nonempty:
        valid = valid and metadata.st_size > 0
    row["valid"] = valid
    return row


def classify(run: dict, artifacts: list[dict]) -> str:
    if run.get("timed_out") or run.get("exit_code") == 124:
        return "timeout"
    required_bad = [row for row in artifacts if row.get("required") and not row.get("valid")]
    produced = [row for row in artifacts if row.get("exists") and row.get("valid")]
    if run.get("exit_code") == 0 and not required_bad:
        return "success"
    if produced:
        return "partial"
    return "failed"
