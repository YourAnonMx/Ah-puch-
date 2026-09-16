#!/usr/bin/env python3
"""Declarative legacy-to-canonical catalog compatibility.

``modules.json`` is the historical catalog base. Current corrections live in
one small machine-readable contract so menu, CLI, Gate3 and runtime do not each
carry their own semantic rewrite tables. This module only validates and applies
that contract; it is not a second catalog authority.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG_CONTRACT_PATH = ROOT / "vendor" / "ahpuch_modules" / "config" / "catalog_contract.json"
if not CATALOG_CONTRACT_PATH.is_file():
    CATALOG_CONTRACT_PATH = ROOT / "ahpuch_modules" / "config" / "catalog_contract.json"
_FAMILY_SELECTOR_SECTIONS = {
    "135": "network_infrastructure",
    "136": "web_application_analysis",
    "137": "security_threat_intelligence",
}


@lru_cache(maxsize=1)
def load_contract() -> dict[str, Any]:
    try:
        payload = json.loads(CATALOG_CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"catalog contract unavailable: {exc}") from exc
    if payload.get("schema_version") != 1:
        raise RuntimeError("catalog contract schema_version must be 1")
    required = {
        "legacy_module_parity",
        "native_aliases",
        "option_additions",
        "option_defaults",
        "module_option_defaults",
        "name_overrides",
        "description_overrides",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise RuntimeError("catalog contract missing sections: " + ",".join(missing))
    for key in required:
        if not isinstance(payload.get(key), dict):
            raise RuntimeError(f"catalog contract {key} must be an object")
    return payload


def _section(name: str) -> dict[str, Any]:
    return dict(load_contract()[name])


# Compatibility exports. Their source of truth is catalog_contract.json.
LEGACY_MODULE_PARITY: dict[str, str] = {
    str(key): str(value) for key, value in _section("legacy_module_parity").items()
}
NATIVE_ALIASES: dict[str, dict[str, Any]] = {
    str(key): dict(value) for key, value in _section("native_aliases").items()
}
OPTION_ADDITIONS: dict[str, tuple[str, ...]] = {
    str(key): tuple(str(item) for item in value)
    for key, value in _section("option_additions").items()
}
OPTION_DEFAULTS: dict[str, Any] = _section("option_defaults")
NAME_OVERRIDES: dict[str, str] = {
    str(key): str(value) for key, value in _section("name_overrides").items()
}
DESCRIPTION_OVERRIDES: dict[str, str] = {
    str(key): str(value) for key, value in _section("description_overrides").items()
}


def _module_defaults() -> dict[tuple[str, str], Any]:
    values: dict[tuple[str, str], Any] = {}
    for raw_key, value in _section("module_option_defaults").items():
        owner, separator, option = str(raw_key).partition(".")
        if not separator or not owner or not option:
            raise RuntimeError(f"invalid module option default key: {raw_key!r}")
        values[(owner, option)] = value
    return values


MODULE_OPTION_DEFAULTS: dict[tuple[str, str], Any] = _module_defaults()


def _apply(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(row.get("id", "")): row for row in rows}
    required_ids = (
        set(LEGACY_MODULE_PARITY)
        | set(NATIVE_ALIASES)
        | set(OPTION_ADDITIONS)
        | set(NAME_OVERRIDES)
        | set(DESCRIPTION_OVERRIDES)
    )
    missing = sorted(required_ids - set(by_id), key=lambda value: int(value) if value.isdigit() else value)
    if missing:
        raise ValueError("catalog contract target missing from historical catalog: " + ",".join(missing))

    for module_id, expected_script in LEGACY_MODULE_PARITY.items():
        actual_script = str(by_id[module_id].get("script", ""))
        if actual_script != expected_script:
            raise ValueError(
                f"legacy parity drift for module {module_id}: expected {expected_script}, got {actual_script or '<none>'}"
            )

    for module_id, alias in NATIVE_ALIASES.items():
        row = by_id[module_id]
        expected_script = str(alias.get("expected_script", ""))
        actual_script = str(row.get("script", ""))
        if not expected_script or actual_script != expected_script:
            raise ValueError(
                f"native alias drift for module {module_id}: expected {expected_script or '<missing>'}, "
                f"got {actual_script or '<none>'}"
            )
        capability = str(alias.get("native_capability", "")).strip()
        primary_input = str(alias.get("primary_input", "")).strip()
        execution_kind = str(alias.get("execution_kind", "native-alias")).strip()
        if not capability or not primary_input or execution_kind != "native-alias":
            raise ValueError(f"native alias contract incomplete for module {module_id}")
        row["legacy_script"] = expected_script
        row["script"] = ""
        row["native_capability"] = capability
        row["primary_input"] = primary_input
        row["options"] = [str(value) for value in alias.get("options", [])]
        row["description"] = str(alias.get("description", "")).strip()
        row["execution_kind"] = execution_kind
        # The frontend classified this row before the declarative alias was
        # applied. Correct the effective activity class as part of the same
        # contract so dispatch never treats a native alias as an executable.
        row["activity_class"] = "native-selector"

    for module_id, additions in OPTION_ADDITIONS.items():
        row = by_id[module_id]
        current = [str(value) for value in row.get("options", [])]
        row["options"] = list(dict.fromkeys([*current, *additions]))

    for module_id, name in NAME_OVERRIDES.items():
        if not name.strip():
            raise ValueError(f"empty name override for module {module_id}")
        by_id[module_id]["name"] = name

    for module_id, description in DESCRIPTION_OVERRIDES.items():
        if not description.strip():
            raise ValueError(f"empty description override for module {module_id}")
        by_id[module_id]["description"] = description
    return rows


def _target_runnable(row: dict[str, Any]) -> bool:
    """Return whether a family selector may dispatch this row with a target."""
    if str(row.get("execution_kind", "")) == "family-selector":
        return False
    if str(row.get("primary_input", "")).strip().casefold() == "local":
        return False
    return bool(row.get("script") or row.get("native_capability"))


def install(base: Any, frontend: Any | None = None) -> Any:
    """Install the declarative compatibility contract exactly once."""
    if getattr(base, "_ah_puch_legacy_parity", False):
        return base

    for key, value in OPTION_DEFAULTS.items():
        base.OPTION_DEFAULTS.setdefault(key, value)

    original_load_catalog = base.load_catalog
    original_module_options = base.module_options

    def load_catalog() -> list[dict[str, Any]]:
        return _apply(original_load_catalog())

    def load_modules() -> list[dict[str, Any]]:
        return [row for row in load_catalog() if row.get("execution_kind") != "family-selector"]

    def selector_expansions() -> dict[str, set[str]]:
        """Expand public selectors from the same effective catalog used by dispatch."""
        rows = load_catalog()
        expanded: dict[str, set[str]] = {}
        for selector, section in _FAMILY_SELECTOR_SECTIONS.items():
            expanded[selector] = {
                str(row.get("id"))
                for row in rows
                if str(row.get("section", "")) == section and _target_runnable(row)
            }
        expanded["138"] = set().union(*(expanded[value] for value in ("135", "136", "137")))
        # Explicit native selectors/aliases remain self-selecting. Local-only
        # rows are deliberately absent from runall target families and retain
        # their dedicated local input contract.
        for row in rows:
            if row.get("native_capability"):
                module_id = str(row.get("id", ""))
                if module_id:
                    expanded[module_id] = {module_id}
        return expanded

    def module_options(
        item: dict[str, Any],
        timeout: int,
        threads: int,
        target: str,
        wordlist_tier: str,
        use_dictionaries: bool = True,
    ) -> dict[str, Any]:
        values = original_module_options(item, timeout, threads, target, wordlist_tier, use_dictionaries)
        module_id = str(item.get("id", ""))
        for (owner, option), value in MODULE_OPTION_DEFAULTS.items():
            if owner == module_id and option in item.get("options", []):
                values[option] = value
        return values

    base.load_catalog = load_catalog
    base.load_modules = load_modules
    base.selector_expansions = selector_expansions
    base.module_options = module_options
    base.LEGACY_MODULE_PARITY = dict(LEGACY_MODULE_PARITY)
    base.NATIVE_ALIASES = {key: dict(value) for key, value in NATIVE_ALIASES.items()}
    base.CATALOG_CONTRACT_PATH = CATALOG_CONTRACT_PATH
    base._ah_puch_legacy_parity = True

    if frontend is not None:
        frontend.load_catalog = load_catalog
        frontend.load_modules = load_modules

    return base
