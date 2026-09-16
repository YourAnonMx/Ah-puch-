#!/usr/bin/env python3
"""Storage-tree safety checks for result directories."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path


def _mountpoints() -> set[str]:
    result: set[str] = set()
    try:
        with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) > 4:
                    value = fields[4].replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
                    result.add(os.path.realpath(value))
    except OSError:
        pass
    return result


def validate(root: Path) -> list[str]:
    resolved = root.resolve()
    errors: list[str] = []
    mounts = _mountpoints()
    for path in root.rglob("*"):
        try:
            lst = path.lstat()
        except OSError as exc:
            errors.append(f"unreadable:{path}:{exc}")
            continue
        relative = path.relative_to(root)
        if stat.S_ISLNK(lst.st_mode):
            errors.append(f"symlink:{relative}")
            continue
        if path.is_file() and lst.st_nlink != 1:
            errors.append(f"hardlink:{relative}:links={lst.st_nlink}")
        if lst.st_uid != os.getuid():
            errors.append(f"owner:{relative}:uid={lst.st_uid}")
        real = os.path.realpath(path)
        if real in mounts and Path(real) != resolved:
            errors.append(f"mountpoint:{relative}")
    return errors


def write_report(root: Path) -> dict[str, object]:
    errors = validate(root)
    path = root / "storage-guard.json"
    path.write_text(json.dumps({"errors": errors, "ok": not errors}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return {"ok": not errors, "errors": len(errors)}
