#!/usr/bin/env python3
"""SRC05 family-level dictionary configuration integration.

The legacy FFUF sibling and the canonical directory runners share one effective
directory tier. A dirsearch.tier override therefore changes the family resource
selection instead of silently affecting only one executable.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from .dictionary_broker import VALID_TIERS, explicit_info, receipt_info, resolve_info
except ImportError:
    from dictionary_broker import VALID_TIERS, explicit_info, receipt_info, resolve_info


def effective_directory_tier(tier: str, tool_options: dict[str, dict[str, Any]] | None) -> str:
    requested = str(((tool_options or {}).get("dirsearch", {}) or {}).get("tier", "") or tier).strip().lower()
    if requested not in VALID_TIERS:
        raise ValueError(f"unsupported directory dictionary tier: {requested}")
    return requested


def install(v2_module: Any) -> Any:
    if getattr(v2_module, "_ah_puch_dictionary_runtime", False):
        return v2_module
    original = v2_module.run_all_origins

    def run_all_origins(root: Path, origins: list[str], **kwargs: Any) -> dict[str, Any]:
        selected = effective_directory_tier(str(kwargs.get("tier", "micro")), kwargs.get("tool_options"))
        local = dict(kwargs)
        local["tier"] = selected
        enabled = bool(local.get("use_dictionaries", True))
        result = dict(original(root, origins, **local))
        directory_options = local.get("tool_options", {}).get("dirsearch", {}) if isinstance(local.get("tool_options", {}), dict) else {}
        configured_path = str(directory_options.get("wordlist", "") or "").strip() if isinstance(directory_options, dict) else ""
        resolution = (
            explicit_info("directory", configured_path, tier=selected)
            if enabled and configured_path
            else resolve_info("directory", tier=selected)
            if enabled
            else {
                "class": "directory",
                "requested_tier": selected,
                "effective_tier": selected,
                "tier_exact": False,
                "path": "",
                "available": False,
                "source": "disabled",
                "provenance": "runtime-disabled",
            }
        )
        result["dictionary_enabled"] = enabled
        result["dictionary_tier"] = selected
        result["dictionary_resolution"] = receipt_info(resolution)
        return result

    if getattr(original, "_ah_puch_legacy_web_fanout", False):
        run_all_origins._ah_puch_legacy_web_fanout = True  # type: ignore[attr-defined]

    v2_module.run_all_origins = run_all_origins
    v2_module._ah_puch_dictionary_runtime = True
    return v2_module
