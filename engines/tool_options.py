"""Typed options for native command runners."""

from __future__ import annotations

import json
import re
from typing import Any


# Wapiti's upstream defaults include modules that use external callback
# infrastructure and weak-login checks, and selected modules may try to fetch
# auxiliary data at runtime. Ah-Puch keeps those capabilities operator-
# selectable via ``--tool-option wapiti.modules=all`` or an explicit module
# list, but the release default must avoid runtime downloads, external
# callbacks, and credential-guessing behavior.
WAPITI_DEFAULT_MODULES = (
    "backup,cms,crlf,csrf,exec,htaccess,ldap,methods,"
    "network_device,printer,redirect,shellshock,spring4shell,sql,ssl,"
    "takeover,timesql,upload,wapp,wp_enum"
)


TOOL_OPTION_DEFAULTS: dict[str, dict[str, Any]] = {
    "gau": {"subs": 1, "threads": 30, "timeout": 10},
    "subfinder": {"threads": 10, "sources": "", "recursive": 0},
    # Historical metadata retained so old configurations fail explicitly;
    # parse_assignments rejects this superseded no-op below.
    "getips": {"verbose": 1},
    "httpx": {"status_code": 1, "title": 1, "server": 1, "ip": 1, "cname": 1, "tech_detect": 1, "threads": 50, "timeout": 10, "rate_limit": 0, "deep": 0, "max_live_urls": 1000},
    "katana": {"depth": 3, "threads": 10, "concurrency": 10, "js_crawl": 1, "rate": 0, "duration": 240, "headless": 0, "max_urls": 1000},
    "gospider": {"threads": 5, "concurrency": 10, "depth": 5, "other_source": 1},
    "dirsearch": {"threads": 4, "max_time": 60, "extensions": "php,aspx,jsp,html,js,json,txt,bak,zip", "wordlist": "", "rate": 0, "recursive": 0, "deep_recursive": 0, "tier": ""},
    # The directory corpus is family-level: dirsearch.wordlist/tier selects
    # the same local resource for every content-discovery sibling. Per-runner
    # options below tune only the executable's bounded request/response
    # policy; they cannot add proxy, replay, credential, or arbitrary-header
    # capabilities.
    "ffuf": {"threads": 4, "timeout": 60, "max_time": 600, "rate": 0, "extensions": "", "match_status": "200,204,301,302,307,401,403", "filter_status": "", "filter_size": "", "filter_words": "", "filter_lines": ""},
    "gobuster": {"threads": 4, "timeout": 60, "extensions": "", "status_codes": "200,204,301,302,307,401,403", "exclude_length": "", "follow_redirect": 0, "delay": 0},
    "feroxbuster": {"threads": 4, "timeout": 60, "time_limit": 600, "depth": 0, "extensions": "", "status_codes": "200,204,301,302,307,401,403", "filter_status": "", "filter_size": "", "rate_limit": 0},
    "nmap": {"top_ports": 100, "service_detection": 1, "os_detection": 0, "scripts": "", "ports": "80,443,8080,8000", "udp_ports": "", "traceroute": 0, "timing": 3, "rate": 0, "timeout": 3600, "profile": "standard"},
    "masscan": {"ports": "80,443,554,8000,8080,8554,502,102,20000,47808", "rate": 500},
    "nikto": {"mutate": "12345", "cgi_dirs": "all"},
    "testssl": {"warnings": "batch", "color": 0},
    "nuclei": {"severity": "", "rate_limit": 0, "threads": 0, "templates": "", "profile": "", "oast": 0, "code": 0, "unsigned": 0, "dast": 0, "timeout": 15},
    "wapiti": {"format": "json", "no_bugreport": 1, "modules": WAPITI_DEFAULT_MODULES, "tasks": 1, "timeout": 15, "wait": 0, "verify_ssl": 1, "headless": 0, "max_scan_time": 3600, "max_attack_time": 600},
    "zap": {"passive_minutes": 10, "active_minutes": 5, "ajax": 0, "memory_mb": 1024, "cpus": 1, "pids": 512, "max_urls": 1000},
    "sqlmap": {"level": 1, "risk": 1, "batch": 1, "skip_static": 1, "max_targets": 50, "timeout": 15, "retries": 2, "output": ""},
    "arachni": {"audit_links": 1, "audit_forms": 1, "audit_headers": 0, "checks": ""},
}

# Canonical owner and concrete projection for every declared TOOL.KEY option.
# Keeping this beside the parser prevents accepted options from drifting into
# silent no-ops and makes the ownership contract available without audit state.
TOOL_OPTION_CONSUMERS: dict[str, dict[str, tuple[str, str]]] = {
    "gau": {
        key: ("engines/recon_core.py:CoreRun.discover", f"gau:{flag}")
        for key, flag in {"subs": "--subs", "threads": "--threads", "timeout": "--timeout"}.items()
    },
    "subfinder": {
        key: ("engines/recon_core.py:CoreRun.discover", f"subfinder:{flag}")
        for key, flag in {"threads": "-t", "sources": "-s", "recursive": "-recursive"}.items()
    },
    "getips": {"verbose": ("engines/recon_core.py:CoreRun.discover", "getips:-v")},
    "httpx": {
        **{
            key: ("engines/http_inventory.py:_httpx_enrichment", f"httpx:{flag}")
            for key, flag in {
                "status_code": "-sc",
                "title": "-title",
                "server": "-server",
                "ip": "-ip",
                "cname": "-cname",
                "tech_detect": "-td",
                "threads": "-threads",
                "timeout": "-timeout",
                "rate_limit": "-rate-limit",
                "deep": "-favicon",
            }.items()
        },
        "max_live_urls": ("engines/http_inventory.py:build_inventory", "origin input bound"),
    },
    "katana": {
        **{
            key: ("engines/web_fanout.py:run_all_origins", f"katana:{flag}")
            for key, flag in {
                "depth": "-d",
                "concurrency": "-c",
                "js_crawl": "-jc",
                "rate": "-rl",
                "headless": "-headless",
                "duration": "-ct",
            }.items()
        },
        "threads": ("engines/web_fanout.py:run_all_origins", "katana:-c"),
        "max_urls": ("engines/web_fanout.py:run_all_origins", "bounded crawl output"),
    },
    "gospider": {
        key: ("engines/web_fanout.py:run_all_origins", f"gospider:{flag}")
        for key, flag in {
            "threads": "-t",
            "concurrency": "-c",
            "depth": "-d",
            "other_source": "--other-source",
        }.items()
    },
    "dirsearch": {
        **{
            key: ("engines/web_fanout.py:run_all_origins", f"dirsearch:{flag}")
            for key, flag in {
                "threads": "--threads",
                "max_time": "--max-time",
                "extensions": "-e",
                "wordlist": "-w",
            }.items()
        },
        **{
            key: ("engines/web_fanout.py:run_all_origins", f"dirsearch:{flag}")
            for key, flag in {
                "rate": "--max-rate",
                "recursive": "-r",
                "deep_recursive": "--deep-recursive",
            }.items()
        },
        "tier": ("engines/web_fanout.py:run_all_origins", "dictionary tier"),
    },
    "ffuf": {
        key: ("engines/legacy_runner_runtime.py:_augment_web_fanout", f"ffuf:{flag}")
        for key, flag in {
            "threads": "-t",
            "timeout": "-timeout",
            "max_time": "-maxtime",
            "rate": "-rate",
            "extensions": "-e",
            "match_status": "-mc",
            "filter_status": "-fc",
            "filter_size": "-fs",
            "filter_words": "-fw",
            "filter_lines": "-fl",
        }.items()
    },
    "gobuster": {
        key: ("engines/web_fanout.py:run_all_origins", f"gobuster:{flag}")
        for key, flag in {
            "threads": "-t",
            "timeout": "--timeout",
            "extensions": "-x",
            "status_codes": "-s",
            "exclude_length": "--exclude-length",
            "follow_redirect": "-r",
            "delay": "--delay",
        }.items()
    },
    "feroxbuster": {
        key: ("engines/tool_adapters.py:_per_url", f"feroxbuster:{flag}")
        for key, flag in {
            "threads": "--threads",
            "timeout": "--timeout",
            "time_limit": "--time-limit",
            "depth": "--depth",
            "extensions": "--extensions",
            "status_codes": "--status-codes",
            "filter_status": "--filter-status",
            "filter_size": "--filter-size",
            "rate_limit": "--rate-limit",
        }.items()
    },
    "nmap": {
        key: ("engines/network_runtime.py:_nmap_validate", f"nmap:{flag}")
        for key, flag in {
            "top_ports": "--top-ports",
            "service_detection": "-sV",
            "os_detection": "-O",
            "scripts": "--script",
            "ports": "-p",
            "udp_ports": "-sU -p",
            "traceroute": "--traceroute",
            "timing": "-T",
            "rate": "--min-rate",
            "timeout": "--host-timeout",
            "profile": "-F|-A",
        }.items()
    },
    "masscan": {
        "ports": ("engines/recon_core.py:CoreRun.run_range_surface", "masscan:--ports"),
        "rate": ("engines/recon_core.py:CoreRun.run_range_surface", "masscan:--max-rate"),
    },
    "nikto": {
        "mutate": ("engines/advanced_consumers.py:_nikto", "nikto:-mutate"),
        "cgi_dirs": ("engines/advanced_consumers.py:_nikto", "nikto:-Cgidirs"),
    },
    "testssl": {
        "warnings": ("engines/advanced_consumers.py:_tls", "testssl:--warnings"),
        "color": ("engines/advanced_consumers.py:_tls", "testssl:--color"),
    },
    "nuclei": {
        key: ("engines/advanced_consumers.py:_nuclei", f"nuclei:{flag}")
        for key, flag in {
            "severity": "-severity",
            "rate_limit": "-rl",
            "threads": "-c",
            "templates": "-t",
            "profile": "-profile",
            "dast": "-dast",
            "timeout": "-timeout",
            "oast": "-ni policy",
            "code": "-code",
            "unsigned": "-dut policy",
        }.items()
    },
    "wapiti": {
        key: ("engines/advanced_consumers.py:_wapiti", f"wapiti:{flag}")
        for key, flag in {
            "format": "-f",
            "modules": "-m",
            "tasks": "--tasks",
            "timeout": "--timeout",
            "wait": "--wait",
            "verify_ssl": "--verify-ssl",
            "headless": "--headless",
            "max_scan_time": "--max-scan-time",
            "max_attack_time": "--max-attack-time",
            "no_bugreport": "--no-bugreport",
        }.items()
    },
    "zap": {
        "passive_minutes": ("engines/advanced_consumers.py:_zap", "zap-baseline:-m"),
        "active_minutes": ("engines/advanced_consumers.py:_zap", "zap-full-scan:-m"),
        "ajax": ("engines/advanced_consumers.py:_zap", "zap:-j"),
        "memory_mb": ("engines/advanced_consumers.py:_zap", "docker:--memory"),
        "cpus": ("engines/advanced_consumers.py:_zap", "docker:--cpus"),
        "pids": ("engines/advanced_consumers.py:_zap", "docker:--pids-limit"),
        "max_urls": ("engines/advanced_consumers.py:_zap", "spider.maxChildren"),
    },
    "sqlmap": {
        "level": ("engines/advanced_consumers.py:_sqlmap", "sqlmap:--level"),
        "risk": ("engines/advanced_consumers.py:_sqlmap", "sqlmap:--risk"),
        "max_targets": ("engines/advanced_consumers.py:run", "parameter queue bound"),
        "timeout": ("engines/advanced_consumers.py:_sqlmap", "sqlmap:--timeout"),
        "retries": ("engines/advanced_consumers.py:_sqlmap", "sqlmap:--retries"),
        "batch": ("engines/advanced_consumers.py:_sqlmap", "sqlmap:--batch"),
        "skip_static": ("engines/advanced_consumers.py:_sqlmap", "sqlmap:--skip-static"),
        "output": ("engines/advanced_consumers.py:_sqlmap", "bounded output directory"),
    },
    "arachni": {
        "audit_links": ("engines/legacy_runner_runtime.py:_arachni", "arachni:--audit-links"),
        "audit_forms": ("engines/legacy_runner_runtime.py:_arachni", "arachni:--audit-forms"),
        "audit_headers": ("engines/legacy_runner_runtime.py:_arachni", "arachni:--audit-headers"),
        "checks": ("engines/legacy_runner_runtime.py:_arachni", "arachni:--checks"),
    },
}

# Options whose historical owner no longer exists in the canonical execution
# surface are rejected explicitly instead of being silently accepted as no-ops.
REJECTED_OPTIONS: dict[tuple[str, str], str] = {
    ("getips", "verbose"): "getips is superseded by scope-bound built-in DNS attribution",
}

REJECTED_OPTIONS.update({
    ("zap", "active"): "active selection is controlled by --zap-active",
    ("zap", "pull"): "image pulls are prohibited during target execution: --pull never",
})

BOOLEAN_OPTIONS = {"subs", "recursive", "verbose", "status_code", "title", "server", "ip", "cname", "tech_detect", "deep", "js_crawl", "headless", "other_source", "deep_recursive", "follow_redirect", "service_detection", "os_detection", "traceroute", "audit_links", "audit_forms", "audit_headers", "color", "no_bugreport", "oast", "code", "unsigned", "dast", "verify_ssl", "active", "ajax", "pull", "batch", "skip_static"}
POSITIVE_OPTIONS = {"threads", "timeout", "depth", "concurrency", "duration", "max_urls", "max_live_urls", "max_time", "time_limit", "rate", "rate_limit", "delay", "top_ports", "passive_minutes", "active_minutes", "memory_mb", "pids", "tasks", "max_scan_time", "max_attack_time", "max_targets", "retries"}


def _validate(tool: str, option: str, value: Any) -> Any:
    if option in BOOLEAN_OPTIONS:
        if value not in (0, 1, False, True):
            raise ValueError(f"{tool}.{option} must be 0 or 1")
        return int(bool(value))
    if option in POSITIVE_OPTIONS:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{tool}.{option} must be a non-negative integer")
    if option == "level" and value not in range(1, 6):
        raise ValueError("sqlmap.level must be 1..5")
    if option == "risk" and value not in range(1, 4):
        raise ValueError("sqlmap.risk must be 1..3")
    if option == "timing" and value not in range(0, 6):
        raise ValueError("nmap.timing must be 0..5")
    if tool == "nmap" and option == "profile" and value not in {"standard", "fast", "comprehensive"}:
        raise ValueError("nmap.profile must be standard, fast, or comprehensive")
    if tool == "dirsearch" and option == "tier" and value not in {"", "micro", "short", "long"}:
        raise ValueError("dirsearch.tier must be micro, short, or long")
    if option in {"extensions", "match_status", "filter_status", "status_codes", "filter_size", "filter_words", "filter_lines", "exclude_length"}:
        if not isinstance(value, str) or len(value) > 512:
            raise ValueError(f"{tool}.{option} must be a short comma-separated string")
        tokens = [token.strip() for token in value.split(",") if token.strip()]
        if len(tokens) > 64:
            raise ValueError(f"{tool}.{option} has too many entries")
        if option == "extensions":
            valid = all(re.fullmatch(r"[A-Za-z0-9._-]+", token) for token in tokens)
        elif option in {"match_status", "filter_status", "status_codes"}:
            valid = all(token == "all" or re.fullmatch(r"[1-5][0-9]{2}", token) for token in tokens)
        else:
            valid = all(re.fullmatch(r"[0-9]+", token) for token in tokens)
        if value and not valid:
            raise ValueError(f"{tool}.{option} contains an invalid value")
    if option == "cpus" and (not isinstance(value, (int, float)) or isinstance(value, bool) or not 0.1 <= value <= 16):
        raise ValueError("zap.cpus must be between 0.1 and 16")
    if option == "checks":
        if not isinstance(value, str) or len(value) > 256:
            raise ValueError("arachni.checks must be a bounded check expression")
        if value and not re.fullmatch(r"[A-Za-z0-9_*,!?+./:-]+", value):
            raise ValueError("arachni.checks contains an invalid character")
    return value


def parse_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def parse_assignments(values: list[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for assignment in values:
        key, separator, raw = assignment.partition("=")
        tool, dot, option = key.partition(".")
        if not separator or not dot or (tool, option) in REJECTED_OPTIONS or tool not in TOOL_OPTION_DEFAULTS or option not in TOOL_OPTION_DEFAULTS[tool]:
            known = ", ".join(
                f"{known_tool}.{known_option}"
                for known_tool, options in TOOL_OPTION_DEFAULTS.items()
                for known_option in options
                if (known_tool, known_option) not in REJECTED_OPTIONS
            )
            if (tool, option) in REJECTED_OPTIONS:
                raise ValueError(f"unsupported tool option {key!r}: {REJECTED_OPTIONS[(tool, option)]}")
            raise ValueError(f"unknown tool option {key!r}; use one of: {known}")
        default = TOOL_OPTION_DEFAULTS[tool][option]
        parsed = parse_value(raw)
        # Unquoted numeric-looking strings such as Nikto's mutation set must
        # retain the type declared by the registry instead of becoming ints.
        if isinstance(default, str) and not isinstance(parsed, str):
            parsed = raw
        result.setdefault(tool, {})[option] = _validate(tool, option, parsed)
    return result


def flatten(values: dict[str, dict[str, Any]]) -> list[str]:
    return [f"{tool}.{key}={json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value}" for tool, options in values.items() for key, value in options.items()]
