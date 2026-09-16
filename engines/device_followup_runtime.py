"""Evidence-gated device fingerprint compatibility layer.

The historical device scripts contained unrelated credential, kill and
masscan paths.  Ah-Puch v10 retains the useful fingerprint-to-endpoint
follow-up contract only: no device follow-up work is eligible until a device fingerprint
has been observed on an in-scope endpoint, and every active probe remains
bounded by the current target policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

try:
    from .camera_surface import probe_service
except ImportError:
    from camera_surface import probe_service


ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = ROOT / "data" / "cameras" / "device-profiles"


def _read_ports() -> list[int]:
    path = ASSET_DIR / "port.rules.small"
    if not path.is_file():
        return [80, 443, 554, 8000, 8080, 8443, 8554]
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    raw = text.removeprefix("-p ").replace(" ", "")
    values: list[int] = []
    for item in raw.split(","):
        try:
            port = int(item)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            values.append(port)
    return sorted(dict.fromkeys(values))[:256]


def run(
    run_root: Path,
    target: str,
    device_result: dict[str, Any],
    *,
    active: bool,
    dry_run: bool,
    timeout: int,
    allow_target: Callable[[str], bool],
    max_targets: int = 64,
) -> dict[str, Any]:
    destination = run_root / "device-followup"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    inventory = device_result.get("inventory", []) if isinstance(device_result, dict) else []
    candidates: list[dict[str, Any]] = []
    for row in inventory:
        if not isinstance(row, dict) or not row.get("identified"):
            continue
        host = str(row.get("host", "")).strip("[]")
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        models = sorted({str(value) for value in row.get("models", []) if str(value).strip()})
        if host and models and 1 <= port <= 65535 and allow_target(host):
            candidates.append({"host": host, "port": port, "models": models, "source": row.get("source", "device-surface")})
    deduplicated = {f"{row['host']}:{row['port']}": row for row in candidates}
    candidates = [deduplicated[key] for key in sorted(deduplicated)][: max(1, min(int(max_targets), 256))]
    fingerprint_count = sum(len(row["models"]) for row in candidates)
    eligible = bool(active and fingerprint_count and candidates)
    if dry_run:
        status = "planned" if fingerprint_count else "not-eligible"
    elif not active:
        status = "skipped"
    elif not fingerprint_count:
        status = "not-eligible"
    else:
        status = "success"

    plan = {
        "status": status,
        "target": target,
        "fingerprint_evidence": fingerprint_count,
        "eligible_endpoints": candidates,
        "port_dictionary": str(ASSET_DIR / "port.rules.small"),
        "historical_authentication_paths": False,
        "historical_kill_paths": False,
        "historical_unbounded_scan_paths": False,
    }
    (destination / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (destination / "plan.json").chmod(0o600)
    results: list[dict[str, Any]] = []
    if eligible and not dry_run:
        probe_timeout = max(0.5, min(int(timeout), 10))
        for row in candidates:
            if not allow_target(row["host"]):
                continue
            result = probe_service(row["host"], row["port"], probe_timeout, probe_mode="all")
            results.append({"host": row["host"], "port": row["port"], "models": row["models"], "probe": result})
    (destination / "results.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in results), encoding="utf-8")
    (destination / "results.jsonl").chmod(0o600)
    summary = {**plan, "probed_endpoints": len(results), "open_endpoints": sum(1 for row in results if row.get("probe", {}).get("open"))}
    (destination / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (destination / "summary.json").chmod(0o600)
    return summary
