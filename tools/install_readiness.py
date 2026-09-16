#!/usr/bin/env python3
"""Create a local, targetless all-tools installation readiness report."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "engines"))

from runner_registry import RUNNERS, snapshot  # noqa: E402


def read_actions(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle, delimiter="\t")]


def build_report(rows: list[dict[str, object]], actions: list[dict[str, str]]) -> dict[str, object]:
    dispositions = Counter(str(row.get("disposition", "missing")) for row in rows)
    action_states = Counter(row.get("status", "missing") for row in actions)
    failures = sorted(row.get("tool", "") for row in actions if row.get("status") in {"failed", "unavailable"})
    blocked_runners = sorted(str(row.get("tool_id") or row.get("id") or "") for row in rows if row.get("disposition") != "REACHABLE")
    blocked = sorted(str(row.get("tool_id") or row.get("id") or "") for row in rows if row.get("disposition") == "BLOCKED_CONTRACT")
    return {
        "status": "ready" if not failures and not blocked_runners else "degraded",
        "policy": {
            "missing_external_tools_are_allowed": False,
            "blocked_contracts_are_failures": True,
            "all_registered_runners_must_be_reachable": True,
            "target_contact": False,
        },
        "registered_runners": len(RUNNERS),
        "runner_dispositions": dict(sorted(dispositions.items())),
        "recipe_actions": len(actions),
        "recipe_statuses": dict(sorted(action_states.items())),
        "failed_recipes": failures,
        "blocked_runners": blocked_runners,
        "blocked_contracts": blocked,
    }


def write_report(destination: Path, report: dict[str, object]) -> None:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    json_path = destination / "readiness.json"
    text_path = destination / "readiness.txt"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        f"STATUS\t{report['status']}",
        f"REGISTERED_RUNNERS\t{report['registered_runners']}",
        f"RECIPE_ACTIONS\t{report['recipe_actions']}",
    ]
    lines.extend(f"RUNNER_{key}\t{value}" for key, value in dict(report["runner_dispositions"]).items())
    lines.extend(f"RECIPE_{key}\t{value}" for key, value in dict(report["recipe_statuses"]).items())
    for tool in report["failed_recipes"]:
        lines.append(f"FAILED_RECIPE\t{tool}")
    for tool in report["blocked_runners"]:
        lines.append(f"BLOCKED_RUNNER\t{tool}")
    for tool in report["blocked_contracts"]:
        lines.append(f"BLOCKED_CONTRACT\t{tool}")
    text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json_path.chmod(0o600)
    text_path.chmod(0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--actions", type=Path, required=True)
    args = parser.parse_args(argv)
    actions = read_actions(args.actions)
    rows = snapshot(args.output_dir / "doctor")
    report = build_report(rows, actions)
    write_report(args.output_dir, report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
