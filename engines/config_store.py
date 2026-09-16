"""Persistent, non-secret runner preferences.

Only execution preferences are stored here. API keys remain in the
installer-managed private environment file and are never copied into a saved
runner profile.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PERSISTED_FIELDS = (
    "wordlist_tier", "no_dictionaries", "threads", "max_inputs", "module_timeout", "native_timeout",
    "follow_up", "follow_up_rounds", "range_ports", "range_rate", "range_host_limit",
    "device_port_profile", "device_custom_ports", "device_model", "device_vendor",
    "device_workers", "device_connect_timeout", "device_session_timeout", "device_retries",
    "device_run_tags", "device_export_mode", "device_egress_label", "no_device_tech",
    "module_options", "tool_options", "active", "passive",
    "pipeline_mode", "recon_max_rounds", "phase_barrier", "continue_on_partial",
    "pipeline_workers", "pipeline_input_limit", "http_verifier", "allow_intrusive_validation",
)

SENSITIVE_OPTION_NAMES = {
    "key", "vt_key", "api_key", "api_secret", "client_secret",
    "secret", "token", "password", "credential",
}
BOOLEAN_FIELDS = {"follow_up", "active", "passive", "no_dictionaries", "no_device_tech", "phase_barrier", "continue_on_partial", "allow_intrusive_validation"}
INTEGER_FIELDS = {
    "threads", "max_inputs", "module_timeout", "native_timeout", "follow_up_rounds",
    "range_rate", "range_host_limit", "device_workers", "device_session_timeout", "device_retries",
    "recon_max_rounds", "pipeline_workers", "pipeline_input_limit",
}
LIST_FIELDS = {"module_options", "tool_options"}
FLOAT_FIELDS = {"device_connect_timeout"}


def config_directory() -> Path:
    override = os.environ.get("AH_PUCH_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))).expanduser() / "ah-puch"


def config_path() -> Path:
    return config_directory() / "profiles.json"


def browser_state_path() -> Path:
    return config_directory() / "catalog-state.json"


def validate_name(name: str) -> str:
    value = name.strip()
    if not NAME_RE.fullmatch(value):
        raise ValueError("config name must use 1-64 letters, numbers, dot, underscore, or hyphen")
    return value


def load_all() -> dict[str, dict[str, Any]]:
    path = config_path()
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def load_browser_state() -> dict[str, Any]:
    """Load non-secret catalog history; targets and option values are never stored."""
    path = browser_state_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"favorites": [], "recent": [], "last": []}
    if not isinstance(value, dict):
        return {"favorites": [], "recent": [], "last": []}
    result: dict[str, Any] = {}
    for field in ("favorites", "recent", "last"):
        rows = value.get(field, [])
        result[field] = [item for item in rows if isinstance(item, str) and item.isdigit()][:50] if isinstance(rows, list) else []
    return result


def save_browser_state(*, favorites: list[str], recent: list[str], last: list[str]) -> Path:
    """Persist catalog IDs only, atomically and with private permissions."""
    directory = config_directory()
    directory.mkdir(parents=True, exist_ok=True)
    destination = browser_state_path()
    temporary = destination.with_suffix(".tmp")
    payload = {
        "favorites": list(dict.fromkeys(favorites))[:50],
        "recent": list(dict.fromkeys(recent))[-20:],
        "last": list(dict.fromkeys(last))[:177],
    }
    temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, destination)
    destination.chmod(0o600)
    return destination


def load(name: str) -> dict[str, Any]:
    key = validate_name(name)
    value = load_all().get(key)
    if not isinstance(value, dict):
        raise KeyError(f"saved config not found: {key}")
    validate_profile(value)
    return value


def save(name: str, values: dict[str, Any]) -> Path:
    key = validate_name(name)
    directory = config_directory()
    directory.mkdir(parents=True, exist_ok=True)
    path = config_path()
    data = load_all()
    data[key] = {field: values[field] for field in PERSISTED_FIELDS if field in values}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def delete(name: str) -> bool:
    key = validate_name(name)
    data = load_all()
    existed = key in data
    data.pop(key, None)
    path = config_path()
    if data:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(0o600)
    elif path.exists():
        path.unlink()
    return existed


def snapshot(args: Any) -> dict[str, Any]:
    values = {field: getattr(args, field) for field in PERSISTED_FIELDS if hasattr(args, field)}
    values["module_options"] = sanitize_module_options(values.get("module_options", []))
    return values


def apply_values(args: Any, values: dict[str, Any]) -> None:
    for field in PERSISTED_FIELDS:
        if field in values and hasattr(args, field):
            setattr(args, field, values[field])


def validate_profile(values: dict[str, Any]) -> None:
    """Reject stale/corrupt profiles before safety flags reach argparse state."""
    unknown = set(values) - set(PERSISTED_FIELDS)
    if unknown:
        raise ValueError(f"saved config contains unknown fields: {', '.join(sorted(unknown))}")
    for field in BOOLEAN_FIELDS:
        if field in values and type(values[field]) is not bool:
            raise ValueError(f"saved config field {field!r} must be a boolean")
    for field in INTEGER_FIELDS:
        if field in values and (type(values[field]) is not int or values[field] < 0):
            raise ValueError(f"saved config field {field!r} must be a non-negative integer")
    for field in FLOAT_FIELDS:
        if field in values and (type(values[field]) not in {int, float} or float(values[field]) <= 0):
            raise ValueError(f"saved config field {field!r} must be a positive number")
    for field in LIST_FIELDS:
        if field in values and (not isinstance(values[field], list) or not all(isinstance(item, str) for item in values[field])):
            raise ValueError(f"saved config field {field!r} must be a list of strings")


def sanitize_module_options(options: Any) -> list[str]:
    """Redact credential-like module option values in persisted projections."""
    if not isinstance(options, list):
        return []
    sanitized: list[str] = []
    for raw in options:
        if not isinstance(raw, str) or "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        option_name = name.rsplit(".", 1)[-1].strip().lower().replace("-", "_")
        if option_name in SENSITIVE_OPTION_NAMES:
            sanitized.append(f"{name}=[REDACTED]")
        else:
            sanitized.append(raw)
    return sanitized
