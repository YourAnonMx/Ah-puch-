#!/usr/bin/env python3
"""Protected sensitive evidence extraction with redacted normal projection."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("cloud-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("generic-secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|client[_-]?secret)\b\s*[:=]\s*[\"']?([^\"'\s]{8,})")),
]


def collect(root: Path, *, max_file_bytes: int = 8_000_000) -> dict[str, int]:
    dest = root / "sensitive"
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows: list[dict] = []
    seen: set[tuple[str, int, str, str]] = set()
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or dest in path.parents:
            continue
        if path.suffix.lower() not in {".txt", ".log", ".json", ".jsonl", ".tsv", ".csv"}:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(root))
        for line_no, line in enumerate(text.splitlines(), 1):
            for kind, pattern in PATTERNS:
                for match in pattern.finditer(line):
                    raw = match.group(1) if kind == "generic-secret" and match.groups() else match.group(0)
                    if not raw:
                        continue
                    digest = hashlib.sha256(raw.encode()).hexdigest()
                    key = (relative, line_no, kind, digest)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append({
                        "type": kind,
                        "value": raw,
                        "sha256": digest,
                        "source": relative,
                        "line": line_no,
                        "context": line[:1200],
                    })
    raw_path = dest / "findings.jsonl"
    raw_path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    raw_path.chmod(0o600)
    summary_path = dest / "summary.txt"
    summary_path.write_text(
        "type\tsource\tline\tsha256\n" +
        "".join(f"{row['type']}\t{row['source']}\t{row['line']}\t{row['sha256']}\n" for row in rows),
        encoding="utf-8",
    )
    summary_path.chmod(0o600)
    return {"findings": len(rows)}
