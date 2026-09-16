"""Shared, bounded command policy for dictionary-backed web discovery.

The public TOOL.KEY parser owns syntax and type validation.  This module owns
the final runtime bounds and the small, safe subset of flags projected to each
installed runner.  Keeping the policy here prevents the web fan-out, the
legacy FFUF sibling, and the typed adapter path from silently drifting apart.
"""
from __future__ import annotations

import re
from typing import Any


DEFAULT_EXTENSIONS = "php,aspx,jsp,html,js,json,txt,bak,zip"
DEFAULT_STATUS_CODES = "200,204,301,302,307,401,403"
MAX_THREADS = 64
MAX_TIMEOUT = 300
MAX_MAX_TIME = 3600
MAX_RATE = 10000
MAX_DEPTH = 10
MAX_DELAY = 300
MAX_LIST_ITEMS = 64
MAX_LIST_LENGTH = 512

_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_STATUS_RE = re.compile(r"^(?:[1-5][0-9]{2}|all)$")
_NUMBER_RE = re.compile(r"^[0-9]+$")


def _bounded_int(value: Any, default: int, *, minimum: int, maximum: int) -> int:
    try:
        if isinstance(value, bool):
            raise ValueError
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _bounded_bool(value: Any, default: bool = False) -> bool:
    if value in (True, 1, "1", "true", "True"):
        return True
    if value in (False, 0, "0", "false", "False"):
        return False
    return default


def _csv(value: Any, default: str, pattern: re.Pattern[str], *, allow_empty: bool = True) -> str:
    raw = str(value if value is not None else "").strip()
    if not raw:
        return "" if allow_empty else default
    values = [item.strip() for item in raw.split(",")]
    if (
        len(values) > MAX_LIST_ITEMS
        or len(raw) > MAX_LIST_LENGTH
        or any(not item or not pattern.fullmatch(item) for item in values)
    ):
        return default
    return ",".join(values)


def _extensions(value: Any, default: str = DEFAULT_EXTENSIONS) -> str:
    return _csv(value, default, _TOKEN_RE)


def _statuses(value: Any, default: str = DEFAULT_STATUS_CODES) -> str:
    return _csv(value, default, _STATUS_RE)


def _numbers(value: Any, default: str = "") -> str:
    return _csv(value, default, _NUMBER_RE)


def bounded_options(
    tool: str,
    options: dict[str, Any] | None,
    *,
    timeout: int,
    threads: int,
) -> dict[str, Any]:
    """Return a defensive, bounded projection for one content runner."""
    source = options if isinstance(options, dict) else {}
    inherited_timeout = _bounded_int(timeout, 60, minimum=1, maximum=MAX_TIMEOUT)
    inherited_threads = _bounded_int(threads, 4, minimum=1, maximum=MAX_THREADS)
    name = str(tool).strip().lower()
    if name == "dirsearch":
        return {
            "threads": _bounded_int(source.get("threads", inherited_threads), inherited_threads, minimum=1, maximum=MAX_THREADS),
            "max_time": _bounded_int(source.get("max_time", 60), 60, minimum=1, maximum=MAX_MAX_TIME),
            "extensions": _extensions(source.get("extensions", DEFAULT_EXTENSIONS)),
            "rate": _bounded_int(source.get("rate", 0), 0, minimum=0, maximum=MAX_RATE),
            "recursive": _bounded_bool(source.get("recursive", False)),
            "deep_recursive": _bounded_bool(source.get("deep_recursive", False)),
        }
    if name == "ffuf":
        return {
            "threads": _bounded_int(source.get("threads", inherited_threads), inherited_threads, minimum=1, maximum=MAX_THREADS),
            "timeout": _bounded_int(source.get("timeout", inherited_timeout), inherited_timeout, minimum=1, maximum=MAX_TIMEOUT),
            "max_time": _bounded_int(source.get("max_time", max(60, inherited_timeout * 10)), max(60, inherited_timeout * 10), minimum=1, maximum=MAX_MAX_TIME),
            "rate": _bounded_int(source.get("rate", 0), 0, minimum=0, maximum=MAX_RATE),
            "extensions": _extensions(source.get("extensions", ""), ""),
            "match_status": _statuses(source.get("match_status", DEFAULT_STATUS_CODES), DEFAULT_STATUS_CODES),
            "filter_status": _statuses(source.get("filter_status", ""), ""),
            "filter_size": _numbers(source.get("filter_size", "")),
            "filter_words": _numbers(source.get("filter_words", "")),
            "filter_lines": _numbers(source.get("filter_lines", "")),
        }
    if name == "gobuster":
        return {
            "threads": _bounded_int(source.get("threads", inherited_threads), inherited_threads, minimum=1, maximum=MAX_THREADS),
            "timeout": _bounded_int(source.get("timeout", inherited_timeout), inherited_timeout, minimum=1, maximum=MAX_TIMEOUT),
            "extensions": _extensions(source.get("extensions", ""), ""),
            "status_codes": _statuses(source.get("status_codes", DEFAULT_STATUS_CODES), DEFAULT_STATUS_CODES),
            "exclude_length": _numbers(source.get("exclude_length", "")),
            "follow_redirect": _bounded_bool(source.get("follow_redirect", False)),
            "delay": _bounded_int(source.get("delay", 0), 0, minimum=0, maximum=MAX_DELAY),
        }
    if name == "feroxbuster":
        return {
            "threads": _bounded_int(source.get("threads", inherited_threads), inherited_threads, minimum=1, maximum=MAX_THREADS),
            "timeout": _bounded_int(source.get("timeout", inherited_timeout), inherited_timeout, minimum=1, maximum=MAX_TIMEOUT),
            "time_limit": _bounded_int(source.get("time_limit", max(60, inherited_timeout * 10)), max(60, inherited_timeout * 10), minimum=1, maximum=MAX_MAX_TIME),
            "depth": _bounded_int(source.get("depth", 0), 0, minimum=0, maximum=MAX_DEPTH),
            "extensions": _extensions(source.get("extensions", ""), ""),
            "status_codes": _statuses(source.get("status_codes", DEFAULT_STATUS_CODES), DEFAULT_STATUS_CODES),
            "filter_status": _statuses(source.get("filter_status", ""), ""),
            "filter_size": _numbers(source.get("filter_size", "")),
            "rate_limit": _bounded_int(source.get("rate_limit", 0), 0, minimum=0, maximum=MAX_RATE),
        }
    raise ValueError(f"unsupported content runner: {tool}")


def dirsearch_args(options: dict[str, Any] | None, *, timeout: int, threads: int) -> list[str]:
    values = bounded_options("dirsearch", options, timeout=timeout, threads=threads)
    command = [
        "--threads", str(values["threads"]),
        "--max-time", str(values["max_time"]),
        "-e", str(values["extensions"]),
    ]
    if values["rate"]:
        command.extend(["--max-rate", str(values["rate"])])
    if values["recursive"]:
        command.append("-r")
    if values["deep_recursive"]:
        command.append("--deep-recursive")
    return command


def ffuf_args(options: dict[str, Any] | None, *, timeout: int, threads: int) -> list[str]:
    values = bounded_options("ffuf", options, timeout=timeout, threads=threads)
    command = [
        "-t", str(values["threads"]),
        "-timeout", str(values["timeout"]),
        "-maxtime", str(values["max_time"]),
    ]
    if values["rate"]:
        command.extend(["-rate", str(values["rate"])])
    if values["extensions"]:
        command.extend(["-e", str(values["extensions"])])
    if values["match_status"]:
        command.extend(["-mc", str(values["match_status"])])
    for key, flag in (("filter_status", "-fc"), ("filter_size", "-fs"), ("filter_words", "-fw"), ("filter_lines", "-fl")):
        if values[key]:
            command.extend([flag, str(values[key])])
    return command


def gobuster_args(options: dict[str, Any] | None, *, timeout: int, threads: int) -> list[str]:
    values = bounded_options("gobuster", options, timeout=timeout, threads=threads)
    command = [
        "-t", str(values["threads"]),
        "--timeout", f"{values['timeout']}s",
    ]
    if values["extensions"]:
        command.extend(["-x", str(values["extensions"])])
    if values["status_codes"]:
        command.extend(["-s", str(values["status_codes"])])
    if values["exclude_length"]:
        command.extend(["--exclude-length", str(values["exclude_length"])])
    if values["follow_redirect"]:
        command.append("-r")
    if values["delay"]:
        command.extend(["--delay", f"{values['delay']}s"])
    return command


def feroxbuster_args(options: dict[str, Any] | None, *, timeout: int, threads: int) -> list[str]:
    values = bounded_options("feroxbuster", options, timeout=timeout, threads=threads)
    command = [
        "--threads", str(values["threads"]),
        "--timeout", f"{values['timeout']}s",
        "--time-limit", f"{values['time_limit']}s",
    ]
    if values["depth"]:
        command.extend(["--depth", str(values["depth"])])
    if values["extensions"]:
        command.extend(["--extensions", str(values["extensions"])])
    if values["status_codes"]:
        command.extend(["--status-codes", str(values["status_codes"])])
    if values["filter_status"]:
        command.extend(["--filter-status", str(values["filter_status"])])
    if values["filter_size"]:
        command.extend(["--filter-size", str(values["filter_size"])])
    if values["rate_limit"]:
        command.extend(["--rate-limit", str(values["rate_limit"])])
    return command
