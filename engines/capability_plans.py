#!/usr/bin/env python3
"""Single declarative execution-plan contract for integrated capabilities."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "config" / "integrated_capabilities.json"
RUNTIME_BLOCKS = frozenset(
    {
        "00-input-target", "01-discovery", "02-dns", "03-network", "04-http",
        "05-history", "06-crawl", "07-content", "08-js-api-parameters",
        "09-fingerprint-waf-tls", "10-assessment", "11-local-cloud",
        "12-device-ics",
    }
)
NATIVE_STAGES = frozenset(
    {
        "recon-dns", "http-inventory", "web-fanout", "tls-inventory",
        "network-profile", "device", "device-fingerprint", "device-resume",
        "device-web", "device-stream", "device-technology", "device-report",
        "device-auth",
        "template-assessment", "web-server-assessment",
        "secondary-web-audit", "proxy-passive", "proxy-active",
        "parameter-validation",
    }
)


def load_plans(path: Path = PLAN_PATH) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid integrated capability plan {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError("integrated capability plan must be a schema-version 1 object")
    rows = payload.get("integrations")
    if not isinstance(rows, dict) or not rows:
        raise RuntimeError("integrated capability plan has no integrations")
    result: dict[str, dict[str, Any]] = {}
    for name, value in rows.items():
        if not isinstance(name, str) or not name or not isinstance(value, dict):
            raise RuntimeError("invalid integrated capability row")
        required = {
            "profile", "pipeline_mode", "active", "catalog_ids", "blocks",
            "native_stages", "contact", "outputs",
        }
        missing = required - set(value)
        if missing:
            raise RuntimeError(f"integrated capability {name} is missing {sorted(missing)}")
        if value["profile"] not in {"baseline", "full", "deep"} or value["pipeline_mode"] not in {"auto", "all"}:
            raise RuntimeError(f"invalid profile or pipeline mode for {name}")
        if type(value["active"]) is not bool:
            raise RuntimeError(f"integrated capability {name} active field must be boolean")
        catalog_ids = [str(item) for item in value["catalog_ids"]]
        if any(not item.isdigit() or not 1 <= int(item) <= 177 for item in catalog_ids):
            raise RuntimeError(f"invalid catalog selector for {name}")
        blocks = [str(item) for item in value["blocks"]]
        if not blocks or len(blocks) != len(set(blocks)):
            raise RuntimeError(f"invalid or duplicate blocks for {name}")
        native_stages = [str(item) for item in value["native_stages"]]
        if len(native_stages) != len(set(native_stages)) or not set(native_stages) <= NATIVE_STAGES:
            raise RuntimeError(f"invalid or duplicate native stages for {name}")
        result[name] = {
            **value,
            "catalog_ids": catalog_ids,
            "blocks": blocks,
            "native_stages": native_stages,
        }
    return result


CAPABILITY_PLANS = load_plans()
INTEGRATED_CAPABILITY_NAMES = frozenset({*CAPABILITY_PLANS, "complete-recon"})


def selected_capabilities(value: str | Iterable[str] | None) -> list[str]:
    if isinstance(value, str):
        requested = [item.strip().casefold() for item in value.split(",") if item.strip()]
    else:
        requested = [str(item).strip().casefold() for item in (value or ()) if str(item).strip()]
    selected: list[str] = []
    for name in requested:
        if name == "complete-recon":
            selected.extend(CAPABILITY_PLANS)
        elif name in CAPABILITY_PLANS:
            selected.append(name)
        else:
            raise ValueError(f"unknown Ah-Puch integrated capability: {name}")
    return list(dict.fromkeys(selected))


def execution_plan(value: str | Iterable[str] | None) -> dict[str, Any]:
    selected = selected_capabilities(value)
    if not selected:
        return {
            "selected": [], "profile": "", "pipeline_mode": "",
            "active": False, "catalog_ids": [], "blocks": [],
            "runtime_blocks": [], "native_stages": [],
        }
    profiles = {"baseline": 0, "full": 1, "deep": 2}
    profile = max((str(CAPABILITY_PLANS[name]["profile"]) for name in selected), key=profiles.__getitem__)
    catalog_ids = list(
        dict.fromkeys(
            item
            for name in selected
            for item in CAPABILITY_PLANS[name]["catalog_ids"]
        )
    )
    if "138" in catalog_ids:
        catalog_ids = ["138"]
    blocks = list(
        dict.fromkeys(
            block
            for name in selected
            for block in CAPABILITY_PLANS[name]["blocks"]
        )
    )
    native_stages = list(
        dict.fromkeys(
            stage
            for name in selected
            for stage in CAPABILITY_PLANS[name]["native_stages"]
        )
    )
    return {
        "selected": selected,
        "profile": profile,
        "pipeline_mode": "all" if any(CAPABILITY_PLANS[name]["pipeline_mode"] == "all" for name in selected) else "auto",
        "active": any(bool(CAPABILITY_PLANS[name]["active"]) for name in selected),
        "catalog_ids": catalog_ids,
        "blocks": blocks,
        "runtime_blocks": [block for block in blocks if block in RUNTIME_BLOCKS],
        "native_stages": native_stages,
    }


def apply_execution_plan(args: Any) -> dict[str, Any]:
    plan = execution_plan(getattr(args, "integrated_capabilities", ""))
    if not plan["selected"]:
        return plan
    if not hasattr(args, "operator_catalog_modules"):
        args.operator_catalog_modules = str(getattr(args, "catalog_modules", "") or "")
    args.profile = plan["profile"]
    args.run = plan["profile"]
    args.pipeline_mode = plan["pipeline_mode"]
    # This is an internal execution contract, not another public selector.
    # An empty value is meaningful for local-only integrated capabilities.
    args.integrated_native_stages = ",".join(plan["native_stages"])
    existing = [item.strip() for item in str(getattr(args, "catalog_modules", "")).split(",") if item.strip()]
    merged = list(dict.fromkeys([*plan["catalog_ids"], *existing]))
    if "138" in merged:
        merged = ["138"]
    args.catalog_modules = ",".join(merged)
    if plan["active"] and not bool(getattr(args, "passive", False)):
        args.active = True
        args.passive = False
    return plan
