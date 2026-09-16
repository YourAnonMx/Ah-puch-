"""Build the complete, targetless Ah-Puch command surface.

The surface is an audit/planning artifact.  It describes every catalog row,
runner contract, typed tool option and legacy function binding without starting
subprocesses, loading credentials or contacting a target.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Callable


_FIXTURE_TARGET = "https://fixture.test/"
_PATH_RE = re.compile(r"/(?:home|tmp|var|mnt|media|run)/[^\s\"']+")


def _redact(value: Any, *, root: Path) -> Any:
    """Return a JSON-safe display value without workstation paths."""
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            text = value.replace(str(root), "<PROJECT>")
            text = text.replace(_FIXTURE_TARGET, "<TARGET>")
            if text.startswith(("/home/", "/tmp/", "/var/", "/mnt/", "/media/", "/run/")):
                return "<LOCAL_PATH>"
            return text
        return value
    if isinstance(value, (list, tuple)):
        return [_redact(item, root=root) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact(item, root=root) for key, item in value.items()}
    return str(value)


def _sanitize_command(command: list[Any], *, root: Path) -> list[Any]:
    return [_redact(value, root=root) for value in command]


def _argparse_surface(parser: argparse.ArgumentParser, *, root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for action in parser._actions:
        if not action.option_strings:
            continue
        choices = list(action.choices) if action.choices is not None else None
        type_name = getattr(action.type, "__name__", "") if action.type else ""
        rows.append({
            "flags": list(action.option_strings),
            "destination": str(action.dest),
            "action": type(action).__name__,
            "nargs": _redact(action.nargs, root=root),
            "type": type_name,
            "choices": _redact(choices, root=root),
            "default": _redact(action.default, root=root),
        })
    return rows


def _catalog_surface(
    rows: list[dict[str, Any]],
    *,
    root: Path,
    module_command_builder: Callable[..., list[str]],
    module_option_builder: Callable[..., dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: int(str(item.get("id", "0"))) if str(item.get("id", "0")).isdigit() else 10**9):
        item = {
            "id": str(row.get("id", "")),
            "name": str(row.get("name", "")),
            "description": str(row.get("description", "")),
            "section": str(row.get("section", "")),
            "execution_kind": str(row.get("execution_kind", "executable")),
            "activity_class": str(row.get("activity_class", "")),
            "script": str(row.get("script", "")),
            "legacy_script": str(row.get("legacy_script", "")),
            "native_capability": str(row.get("native_capability", "")),
            "primary_input": str(row.get("primary_input", "")),
            "options": [str(value) for value in row.get("options", [])],
            "menu_families": [str(value) for value in row.get("menu_families", [])],
        }
        script = item["script"]
        if script:
            try:
                options = module_option_builder(
                    row, 60, 4, _FIXTURE_TARGET, "micro", False,
                )
                item["command_template"] = _sanitize_command(
                    module_command_builder(script, _FIXTURE_TARGET, 4, options, 60),
                    root=root,
                )
            except (OSError, TypeError, ValueError, RuntimeError) as exc:
                item["command_template_error"] = f"{type(exc).__name__}: {exc}"
        else:
            item["command_template"] = []
        result.append(item)
    return result


def build_command_surface(
    *,
    catalog_rows: list[dict[str, Any]],
    parser: argparse.ArgumentParser,
    module_command_builder: Callable[..., list[str]],
    module_option_builder: Callable[..., dict[str, Any]],
    root: Path,
) -> dict[str, Any]:
    """Build the complete offline command and capability inventory."""
    try:
        from . import legacy_capability_registry, runner_registry, tool_options
    except ImportError:
        import legacy_capability_registry, runner_registry, tool_options

    catalog = _catalog_surface(
        catalog_rows,
        root=root,
        module_command_builder=module_command_builder,
        module_option_builder=module_option_builder,
    )
    tool_rows: list[dict[str, Any]] = []
    for row in runner_registry.TOOL_INVENTORY["tools"]:
        runner_id = str(row.get("runner_id", ""))
        spec = runner_registry.RUNNERS.get(runner_id, {})
        tool_rows.append({
            "id": str(row.get("id", "")),
            "runner_id": runner_id,
            "binary": str(row.get("binary", "")),
            "capability": str(row.get("capability", "")),
            "block": str(row.get("block", "")),
            "adapter": str(row.get("adapter", "")),
            "contact": str(row.get("contact", "")),
            "inputs": _redact(row.get("inputs", []), root=root),
            "outputs": _redact(row.get("outputs", []), root=root),
            "profiles": _redact(row.get("profiles", []), root=root),
            "version": _redact(row.get("version", []), root=root),
            "help": _redact(row.get("help", []), root=root),
            "required_help": _redact(spec.get("required_help", ()), root=root),
            "integration": str(spec.get("integration", "")),
            "native": bool(spec.get("native", not bool(row.get("binary")))),
        })

    option_rows: list[dict[str, Any]] = []
    for tool, options in tool_options.TOOL_OPTION_DEFAULTS.items():
        for option, default in options.items():
            key = (tool, option)
            owner = tool_options.TOOL_OPTION_CONSUMERS.get(tool, {}).get(option, ("", ""))
            rejected = tool_options.REJECTED_OPTIONS.get(key, "")
            option_rows.append({
                "tool": tool,
                "option": option,
                "key": f"{tool}.{option}",
                "default": _redact(default, root=root),
                "status": "rejected" if rejected else "accepted",
                "reason": rejected,
                "owner": owner[0],
                "projection": owner[1],
            })
    for (tool, option), reason in sorted(tool_options.REJECTED_OPTIONS.items()):
        if (tool, option) not in {(row["tool"], row["option"]) for row in option_rows}:
            option_rows.append({
                "tool": tool,
                "option": option,
                "key": f"{tool}.{option}",
                "default": None,
                "status": "rejected",
                "reason": reason,
                "owner": "",
                "projection": "",
            })

    matrix = legacy_capability_registry.load_matrix()
    legacy_rows: list[dict[str, Any]] = []
    for group_name in ("sources", "companions"):
        for source_id, source in matrix[group_name].items():
            for row in source["functions"]:
                function_id = str(row["id"])
                legacy_rows.append({
                    "function_id": function_id,
                    "source_id": str(source_id),
                    "source_group": group_name,
                    "canonical_capability": str(row.get("canonical_capability", "")),
                    "adapter": str(row.get("adapter", "")),
                    "evidence": _redact(row.get("evidence", []), root=root),
                    "contact": str(row.get("contact", "")),
                    "parallel_group": str(row.get("parallel_group", "")),
                    "outputs": _redact(row.get("outputs", []), root=root),
                    "binding": _redact(legacy_capability_registry.RUNTIME_BINDINGS.get(function_id, {}), root=root),
                })

    rejected_count = sum(1 for row in option_rows if row["status"] == "rejected")
    public_count = sum(1 for row in option_rows if row["status"] == "accepted")
    declared_count = sum(len(options) for options in tool_options.TOOL_OPTION_DEFAULTS.values())
    executable = sum(1 for row in catalog if row["execution_kind"] == "executable")
    native = sum(1 for row in catalog if row["execution_kind"] == "native-selector")
    selectors = sum(1 for row in catalog if row["execution_kind"] == "family-selector")
    return {
        "schema_version": 1,
        "policy": {
            "mode": "targetless-command-surface",
            "commands_executed": False,
            "target_contact": "none",
            "target_input": "domain, HTTP(S) URL, IP/IPv6, host:port, CIDR range, or --targets-file",
            "interactive_auth_required": False,
            "credential_input_required": False,
            "api_keys_required": False,
            "authorization_manifest_required": False,
            "external_installation": False,
            "credentials_loaded": False,
            "templates_are_examples": True,
        },
        "summary": {
            "catalog_rows": len(catalog),
            "catalog_executable": executable,
            "catalog_native_selectors": native,
            "catalog_family_selectors": selectors,
            "tool_inventory_rows": len(tool_rows),
            "runner_contracts": len(runner_registry.RUNNERS),
            # ``declared`` is the typed registry count.  The surface also
            # lists rejected aliases which intentionally have no default;
            # keep that larger count explicit instead of conflating the two.
            "tool_options_declared": declared_count,
            "tool_option_surface_rows": len(option_rows),
            "tool_options_accepted": public_count,
            "tool_options_rejected_or_gated": rejected_count,
            "legacy_function_bindings": len(legacy_rows),
        },
        "cli_options": _argparse_surface(parser, root=root),
        "catalog": catalog,
        "tools": sorted(tool_rows, key=lambda row: row["id"]),
        "tool_options": sorted(option_rows, key=lambda row: row["key"]),
        "legacy_functions": sorted(legacy_rows, key=lambda row: row["function_id"]),
    }


def write_command_surface(payload: dict[str, Any], destination: Path) -> Path:
    """Write a private local command-surface artifact without following symlinks."""
    destination = destination.expanduser()
    if destination.is_symlink():
        raise ValueError("command-surface output must not be a symlink")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    destination.chmod(0o600)
    return destination
