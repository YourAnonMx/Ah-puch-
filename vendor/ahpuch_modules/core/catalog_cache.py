import os, sys, json, re
from typing import Dict, List, Set
from ahpuch_modules.core.catalog_loader import load as _load_raw
from ahpuch_modules.core.catalog_model import (
    normalize_catalog_ids,
    catalog_to_tools,
    compute_tags,
    SECTION_NAMES,
)

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULES_DIR = os.path.join(_BASE, "modules")

_RAW = normalize_catalog_ids(_load_raw())
_tools_obj = catalog_to_tools(_RAW)

tools: List[Dict] = [t.__dict__ for t in _tools_obj]
tools_mapping: Dict[str, Dict] = {t["number"]: t for t in tools}

COMPAT_ALIASES: Dict[str, str] = {}
for t in tools:
    if t["section"] == "Run All Scripts":
        if "Infrastructure" in t["name"]:
            COMPAT_ALIASES["100"] = t["number"]
        elif "Web Intelligence" in t["name"]:
            COMPAT_ALIASES["200"] = t["number"]
        elif "Security" in t["name"]:
            COMPAT_ALIASES["300"] = t["number"]
    if t["section"] == "Special Mode":
        COMPAT_ALIASES["00"] = t["number"]

def resolve_module_number(n: str):
    if n in tools_mapping:
        return n
    if n in COMPAT_ALIASES and COMPAT_ALIASES[n] in tools_mapping:
        return COMPAT_ALIASES[n]
    return None

TOOL_TAGS: Dict[str, Set[str]] = {t.number: compute_tags(t) for t in _tools_obj}


SECTION_TOOL_NUMBERS: Dict[str, List[str]] = {
    section: [t["number"] for t in tools if t["section"] == section and t["script"]]
    for section in (
        "Network & Infrastructure",
        "Web Application Analysis",
        "Security & Threat Intelligence",
    )
}

RUN_ALL_INFRA_ID = next(
    (t["number"] for t in tools if t["section"] == "Run All Scripts" and "Infrastructure" in t["name"]), None
)
RUN_ALL_WEB_ID = next(
    (t["number"] for t in tools if t["section"] == "Run All Scripts" and "Web Intelligence" in t["name"]), None
)
RUN_ALL_SEC_ID = next(
    (t["number"] for t in tools if t["section"] == "Run All Scripts" and "Security" in t["name"]), None
)
ALL_KNOWN_MODULE_OPTIONS: Set[str] = set()
for t in tools:
    for o in t.get("options_meta") or []:
        ALL_KNOWN_MODULE_OPTIONS.add(o.replace("-", "_").lower())

NUMERIC_OPTION_HINTS = {
    "max_pages",
    "count",
    "warn_ms",
    "resume_count",
    "size",
    "timeout",
    "history_days",
    "depth",
    "limit",
    "short_window",
    "long_window",
    "threads",
    "port",
    "ports",
    "retries",
}

number_of_modules = len(
    [t for t in tools if t["script"] and t["section"] not in ("Run All Scripts", "Special Mode")]
)

AUTHOR = "Jason13"
VERSION = "2.0"
