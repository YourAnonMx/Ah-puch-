"""Shared progress, alert, and checkpoint helpers for a unified run."""

from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    from .runtime_hardening import atomic_write
except ImportError:
    from runtime_hardening import atomic_write


def write_text(path: Path, value: str) -> None:
    atomic_write(path, value)


class Progress:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self.total = 0
        self.current = 0

    def start(self, total: int) -> None:
        self.total = max(1, total)
        self.current = 0
        self.show("starting")

    def show(self, label: str) -> None:
        if not self.enabled:
            return
        percent = int((self.current / self.total) * 100) if self.total else 0
        print(f"\r[{percent:3d}%] {label:<72}", end="", flush=True)

    def step(self, label: str) -> None:
        self.current = min(self.total, self.current + 1)
        self.show(label)

    def finish(self, label: str = "complete") -> None:
        if not self.enabled:
            return
        self.current = self.total
        self.show(label)
        print()


class AlertSink:
    def __init__(self, root: Path, target: str, console: bool = True, desktop: bool = False) -> None:
        self.root = root
        self.target = target
        self.console = console
        self.desktop = desktop
        self.directory = root / "alerts"
        self.jsonl = self.directory / "findings.jsonl"
        self.text = self.directory / "findings.txt"
        self.rows: list[dict[str, Any]] = []

    def emit(self, category: str, severity: str, confidence: str, evidence: str, source: str, next_action: str = "review") -> dict[str, Any]:
        row = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "target": self.target,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence[:1000],
            "source": source,
            "next_action": next_action,
        }
        fingerprint = json.dumps({key: row[key] for key in ("category", "evidence", "source")}, sort_keys=True)
        if any(json.dumps({key: item[key] for key in ("category", "evidence", "source")}, sort_keys=True) == fingerprint for item in self.rows):
            return row
        self.rows.append(row)
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.jsonl.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        if self.console:
            print(f"\n[alert][{severity}] {category}: {evidence}")
        if self.desktop and shutil.which("notify-send"):
            try:
                subprocess.run(["notify-send", f"Ah Puch: {severity} finding", f"{category}: {evidence[:180]}"], timeout=3, check=False)
            except (OSError, subprocess.SubprocessError):
                pass
        self.flush_text()
        return row

    def flush_text(self) -> None:
        lines = ["severity\tconfidence\tcategory\tsource\tevidence\tnext_action"]
        lines.extend(
            f"{row['severity']}\t{row['confidence']}\t{row['category']}\t{row['source']}\t{row['evidence']}\t{row['next_action']}"
            for row in self.rows
        )
        write_text(self.text, "\n".join(lines) + "\n")

    def finish(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.jsonl.exists():
            write_text(self.jsonl, "")
        self.flush_text()
        write_text(self.directory / "summary.json", json.dumps({"target": self.target, "findings": len(self.rows), "by_severity": {severity: sum(1 for row in self.rows if row["severity"] == severity) for severity in {row["severity"] for row in self.rows}}}, indent=2) + "\n")


def checkpoint(path: Path, stage: str, status: str, **extra: Any) -> None:
    sequence = 1
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
        sequence = int(previous.get("sequence", 0) or 0) + 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    payload = {
        "schema_version": 1,
        "sequence": sequence,
        "stage": stage,
        "status": status,
        "updated": dt.datetime.now(dt.timezone.utc).isoformat(),
        **extra,
    }
    write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
