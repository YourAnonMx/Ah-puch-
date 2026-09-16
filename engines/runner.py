#!/usr/bin/env python3
"""Unified target runner for the Python core and module catalog."""

from __future__ import annotations

import argparse
import builtins
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

try:
    from .wordlists import build_wordlist
    from .camera_surface import analyze as analyze_camera_surface
    from .profiles import PRESETS, apply_preset, get_preset, preset_choices, preset_help
    from .feedback import AlertSink, Progress, checkpoint
    from .config_store import PERSISTED_FIELDS, apply_values as apply_saved_values, delete as delete_saved_config, load as load_saved_config, load_all as load_saved_configs, load_browser_state, save as save_saved_config, save_browser_state, sanitize_module_options, snapshot as config_snapshot
    from .tool_options import TOOL_OPTION_DEFAULTS, flatten as flatten_tool_options, parse_assignments as parse_tool_assignments
    from .saved_run import inspect_saved_run
    from .device_data import import_device_data
    from .advisory_store import import_advisory_file
    from .run_export import export_saved_run
    from .capability_plans import INTEGRATED_CAPABILITY_NAMES, apply_execution_plan, selected_capabilities
    from .integrated_capability_runtime import build_dictionary, index_advisory_corpus
    from .offline_adapters import ADAPTER_CATALOG, REFERENCE_ONLY, normalize_captured_output, normalize_file
    from .runtime_hardening import ExecutionBudget, activate_budget, atomic_write, cap_file, current_budget, safe_target, utc_now, validate_namespace_limits, write_budget_artifact, write_recovery_artifact
except ImportError:
    from wordlists import build_wordlist
    from camera_surface import analyze as analyze_camera_surface
    from profiles import PRESETS, apply_preset, get_preset, preset_choices, preset_help
    from feedback import AlertSink, Progress, checkpoint
    from config_store import PERSISTED_FIELDS, apply_values as apply_saved_values, delete as delete_saved_config, load as load_saved_config, load_all as load_saved_configs, load_browser_state, save as save_saved_config, save_browser_state, sanitize_module_options, snapshot as config_snapshot
    from tool_options import TOOL_OPTION_DEFAULTS, flatten as flatten_tool_options, parse_assignments as parse_tool_assignments
    from saved_run import inspect_saved_run
    from device_data import import_device_data
    from advisory_store import import_advisory_file
    from run_export import export_saved_run
    from capability_plans import INTEGRATED_CAPABILITY_NAMES, apply_execution_plan, selected_capabilities
    from integrated_capability_runtime import build_dictionary, index_advisory_corpus
    from offline_adapters import ADAPTER_CATALOG, REFERENCE_ONLY, normalize_captured_output, normalize_file
    from runtime_hardening import ExecutionBudget, activate_budget, atomic_write, cap_file, current_budget, safe_target, utc_now, validate_namespace_limits, write_budget_artifact, write_recovery_artifact


VERSION = "2.0.0"
PROGRAM = "ah-puch"
ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor" / "ahpuch_modules"
if not VENDOR.is_dir():
    # Setuptools installs the vendored package as ``ahpuch_modules``. Keep
    # source-checkout and installed-wheel layouts equivalent for the dynamic
    # module loader and its import path.
    VENDOR = ROOT / "ahpuch_modules"
CORE_ENGINE = ROOT / "engines" / "recon_core.py"
CATALOG = VENDOR / "config" / "modules.json"
if str(VENDOR.parent) not in sys.path:
    sys.path.insert(0, str(VENDOR.parent))
from ahpuch_modules.core.invocation import build_module_command
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)


def input(prompt: str = "") -> str:
    """Read one menu answer and exit cleanly when stdin is closed."""
    try:
        return builtins.input(prompt)
    except EOFError:
        print()
        raise SystemExit(0) from None

ACTIVE_NAMES = {
    "api_schema_grabber.py",
    "cors_misconfiguration_scanner.py",
    "file_upload_surface_finder.py",
    "graphql_introspection_probe.py",
    "hidden_parameter_discovery.py",
    "http_method_enumerator.py",
    "firewall_detection.py",
    "open_redirect_finder.py",
    "snmp_bulk_walk.py",
    "virtual_host_fuzzer.py",
    "open_ports.py",
    "ip_range_scanner.py",
    "snmp_public_community_checker.py",
    "udp_service_sampler.py",
    "ntp_info_leak_checker.py",
}
EXPLICIT_ONLY_NAMES = {
    "email_harvester.py",
    "pastebin_monitoring.py",
    "rate_limit_waf_bypass_test.py",
}
# Compatibility export for integrations that still inspect this symbol. These
# modules are supported, but require explicit selection and active mode.
DISABLED_NAMES: set[str] = set()
API_ENV_BY_SCRIPT = {
    "censys.py": ("CENSYS_API_ID", "CENSYS_API_SECRET"),
    "shodan.py": ("SHODAN_API_KEY",),
    "virustotal_scan.py": ("VIRUSTOTAL_API_KEY",),
}
API_KEY_NAMES = (
    "VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "GOOGLE_API_KEY", "CENSYS_API_ID",
    "CENSYS_API_SECRET", "SSL_LABS_API_KEY", "ABUSEIPDB_API_KEY",
    "OTX_API_KEY", "IPQUALITYSCORE_API_KEY", "IPINFO_API_KEY", "SECURITYTRAILS_API_KEY",
    "GITHUB_TOKEN", "HIBP_API_KEY", "WEBSITE_CARBON_API_KEY", "CHAOS_KEY", "GREYNOISE_API_KEY",
    "VT_API_KEY", "HUNTER_API_KEY", "FOFA_EMAIL", "FOFA_KEY",
)
URL_INPUT_HINTS = ("url", "web", "http", "domain/url", "domain/ url")
AUTHORITY_INPUT_HINTS = ("host:port", "domain/host:port")
TARGET_INPUT_CONTRACT = (
    "domain, HTTP(S) URL, IP/IPv6, host:port, CIDR range, or --targets-file"
)
TARGET_INPUT_PROMPT = (
    "Target domain, HTTP(S) URL, IP/IPv6, host:port, CIDR range, or @targets-file: "
)

OPTION_DEFAULTS: dict[str, Any] = {
    "sources": "",
    "timeout": 60,
    "providers": {"Cloudflare": "https://cloudflare-dns.com/dns-query", "Google": "https://dns.google/resolve"},
    "qtype": "A",
    "types": "A,AAAA,CNAME,MX,NS,TXT",
    "check_subdomains": 0,
    "vt_key": "",
    "ips_file": "",
    "provider": "bgpview",
    "max_hosts": 10,
    "workers": 4,
    "resolvers": {"Cloudflare": "1.1.1.1", "Google": "8.8.8.8"},
    "samples": 2,
    "limit": 25,
    "paths": "/,/robots.txt,/sitemap.xml",
    "collapse_digest": 1,
    "status_filter": "200",
    "max_pages": 10,
    "sample_ratio": 1,
    "follow": 0,
    "include_subdomains": 0,
    "include_subs": 0,
    "threads": 4,
    "depth": 2,
    "rate_limit": 1,
    "start_url": "",
    "status_keep": "200,301,302,403",
    "wordlist": "",
    "key": "",
    "strategies": "default",
    "verify_ssl": 0,
    "follow_redirects": 0,
    "paths_file": "",
    "max_params": 24,
    "params_file": "",
    "test_values": "",
    "threshold": 1,
    "max_scripts": 20,
    "export_txt": 1,
    "graphql_paths": "/graphql,/api/graphql",
    "delay": 0,
    "concurrency": 2,
    "json": 0,
    "log": 0,
    "include_wildcard": 0,
    "batch_size": 1,
    "session_hints": "",
    "ports_top": 20,
    "days": 30,
    "short_window": 7,
    "long_window": 30,
    "count": 5,
    "verify": 0,
    "dns_server": "",
    "community": "public",
    "port": 443,
    "selectors": "default,google,selector1,selector2,mail,k1",
}

CAPABILITY_GROUPS: dict[str, dict[str, Any]] = {
    "recon": {"label": "Recon and asset discovery", "description": "associated assets, domain intelligence, certificates, reputation, and passive discovery", "ids": [1, 5, 6, 8, 11, 18, 20, 23, 27, 30, 31, 32, 34, 38, 39, 41, 93, 94, 108, 111, 123, 126, 127, 128, 131, 132, 133]},
    "dns": {"label": "DNS and infrastructure", "description": "DNS records, routing, ASN, resolution, network identity, and infrastructure posture", "ids": [2, 3, 4, 5, 8, 11, 17, 18, 19, 20, 21, 23, 26, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41]},
    "http": {"label": "HTTP and TLS", "description": "HTTP versions, headers, server identity, redirects, certificates, TLS, and security policy", "ids": [7, 10, 12, 13, 14, 15, 25, 27, 29, 36, 40, 41, 97, 99, 100, 104, 106, 107, 121, 122]},
    "crawling": {"label": "Website crawling", "description": "live pages, historical URLs, robots, sitemaps, JavaScript, forms, assets, and endpoint discovery", "ids": [45, 46, 50, 51, 52, 54, 57, 58, 59, 61, 62, 67, 68, 69, 70, 76, 77, 78, 79, 81, 83, 86, 91, 92]},
    "content": {"label": "Content and directories", "description": "paths, extensions, logins, uploads, embedded objects, backups, APIs, and static assets", "ids": [50, 53, 64, 66, 68, 70, 72, 75, 76, 80, 82, 83, 86, 89, 90, 92, 96, 113, 115, 116]},
    "endpoints": {"label": "Endpoints and APIs", "description": "parameters, forms, API schemas, GraphQL, methods, WebSockets, caches, CORS, and redirects", "ids": [62, 65, 67, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 99, 100, 114, 115, 119, 120, 122]},
    "secrets": {"label": "Secrets and JavaScript", "description": "JavaScript, obfuscation, DOM sinks, dependencies, comments, tokens, and exposed configuration", "ids": [54, 62, 65, 69, 71, 80, 81, 87, 91, 92, 96, 99, 100, 114, 124, 131]},
    "network": {"label": "Network, range, and ICS", "description": "ports, ranges, services, routing, industrial indicators, and protocol candidates", "ids": [8, 9, 16, 21, 22, 24, 28, 37, 42, 43, 44, 139, 140, 141, 142, 143, 144, 145, 146, 147]},
    "web": {"label": "Web analysis", "description": "application behavior, cookies, CMS, forms, security controls, performance, and content findings", "ids": list(range(45, 93))},
    "threat": {"label": "Threat intelligence", "description": "reputation, certificates, cloud exposure, CVE, takeover, feeds, and public-contact intelligence", "ids": list(range(93, 135)) + [148, 149, 150, 151]},
    "advisories": {"label": "CVE and version intelligence", "description": "local vulnerability references plus passive product/version mapping", "ids": [131, 177]},
    "device": {"label": "Device and camera workflows", "description": "bounded discovery, fingerprint enrichment, inventory, checkpoint resume and exact authentication validation", "ids": [152, 153, 154, 172, 173, 174, 175, 176]},
    "orchestration": {"label": "Native orchestration adapters", "description": "doctor, graph/runtime stages, target consumers, profiles, reporting and integrity", "ids": list(range(155, 172))},
}

# Named composites preserve the old standalone workflows while dispatching
# through the single Ah-Puch lifecycle. They are deliberately separate from
# numeric catalog IDs so existing public IDs remain stable.
# Exact production-stage contracts for every native selector.  Display names
# never participate in dispatch, and profile selectors enumerate their stages
# explicitly instead of enabling every stage through a broad condition.
PROFILE_STAGE_MATRIX: dict[str, frozenset[str]] = {
    "profile-baseline": frozenset({"recon-dns", "http-inventory", "web-fanout", "tls-inventory"}),
    "profile-full": frozenset({
        "recon-dns", "http-inventory", "web-fanout", "tls-inventory", "network-profile",
        "device", "template-assessment", "web-server-assessment", "secondary-web-audit",
        "proxy-passive", "proxy-active", "parameter-validation",
    }),
    "profile-deep": frozenset({
        "recon-dns", "http-inventory", "web-fanout", "tls-inventory", "network-profile",
        "device", "template-assessment", "web-server-assessment", "secondary-web-audit",
        "proxy-passive", "proxy-active", "parameter-validation",
    }),
}

NATIVE_SELECTOR_CONTRACTS: dict[str, dict[str, Any]] = {
    "device": {"stages": {"device"}, "input": "network", "component": "device_surface"},
    "device-fingerprint": {"stages": {"device-fingerprint"}, "input": "network", "component": "device_surface"},
    "device-resume": {"stages": {"device-resume"}, "input": "network", "component": "device_surface"},
    "runner-doctor": {"stages": set(), "input": "local", "component": "runner_registry"},
    "recon-dns": {"stages": {"recon-dns"}, "input": "network", "component": "recon_core"},
    "http-inventory": {"stages": {"http-inventory"}, "input": "network", "component": "http_inventory"},
    "web-fanout": {"stages": {"http-inventory", "web-fanout"}, "input": "network", "component": "web_fanout"},
    "network-profile": {"stages": {"network-profile"}, "input": "network", "component": "network_profile_runtime"},
    "tls-inventory": {"stages": {"http-inventory", "tls-inventory"}, "input": "network", "component": "tls_inventory"},
    "template-assessment": {"stages": {"http-inventory", "template-assessment"}, "input": "network", "component": "advanced_consumers"},
    "web-server-assessment": {"stages": {"http-inventory", "web-server-assessment"}, "input": "network", "component": "advanced_consumers"},
    "secondary-web-audit": {"stages": {"http-inventory", "secondary-web-audit"}, "input": "network", "component": "advanced_consumers"},
    "proxy-passive": {"stages": {"http-inventory", "proxy-passive"}, "input": "network", "component": "advanced_consumers"},
    "proxy-active": {"stages": {"http-inventory", "proxy-active"}, "input": "network", "component": "advanced_consumers"},
    "parameter-validation": {"stages": {"http-inventory", "parameter-validation"}, "input": "network", "component": "advanced_consumers"},
    "profile-baseline": {"stages": set(PROFILE_STAGE_MATRIX["profile-baseline"]), "input": "network", "component": "runtime"},
    "profile-full": {"stages": set(PROFILE_STAGE_MATRIX["profile-full"]), "input": "network", "component": "runtime"},
    "profile-deep": {"stages": set(PROFILE_STAGE_MATRIX["profile-deep"]), "input": "network", "component": "runtime"},
    "normalize-report": {"stages": set(), "input": "local", "component": "normalized_inventory"},
    "integrity": {"stages": set(), "input": "local", "component": "storage_guard"},
    "device-web": {"stages": {"device-web"}, "input": "network", "component": "device_surface"},
    "device-stream": {"stages": {"device-stream"}, "input": "network", "component": "device_surface"},
    "device-technology": {"stages": {"device-technology"}, "input": "network", "component": "device_surface"},
    "device-report": {"stages": {"device-report"}, "input": "network", "component": "device_surface"},
    "device-auth": {"stages": {"device-auth"}, "input": "network", "component": "auth_validation"},
    "advisory-mapping": {"stages": set(), "input": "local", "component": "advisory_store"},
}


def slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (value or "target")[:120]


def now_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_run_root(output: Path, target: str) -> Path:
    """Create a collision-free per-target run directory atomically."""
    parent = Path(output).expanduser().resolve() / slug(target)
    identifier = now_id()
    for index in range(1000):
        suffix = "" if index == 0 else f"-{index:03d}"
        candidate = parent / f"{identifier}{suffix}"
        try:
            candidate.mkdir(parents=True, mode=0o700)
        except FileExistsError:
            continue
        return candidate
    raise RuntimeError(f"could not allocate a unique run directory under {parent}")


def clean_target(value: str) -> str:
    value = value.strip().strip("'\";,()")
    if re.fullmatch(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
        return value
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    if value.startswith(("http://", "https://")):
        parsed = urlsplit(value)
        if not parsed.hostname:
            raise ValueError("target has no hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("target URL must not contain embedded credentials")
        host = parsed.hostname.lower().rstrip(".")
        display = f"[{host}]" if ":" in host else host
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), display + port, parsed.path or "/", parsed.query, ""))
    if "://" in value:
        raise ValueError("only HTTP(S) URLs are accepted")
    host = value.split()[0]
    if host.startswith("[") and "]" in host:
        end = host.index("]")
        bare = host[1:end]
        suffix = host[end + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit() or not 1 <= int(suffix[1:]) <= 65535):
            raise ValueError("invalid IPv6 port")
        host = f"[{bare}]{suffix}"
    elif host.count(":") == 1:
        name, port = host.rsplit(":", 1)
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("invalid port")
        host = f"{name}:{port}"
        bare = name
    else:
        bare = host.strip("[]").rstrip(".")
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        labels = bare.split(".")
        if len(labels) < 2 or any(not re.fullmatch(r"[A-Za-z0-9-]{1,63}", x) for x in labels):
            raise ValueError("target is not a hostname or IPv4 address")
    return host.lower()


def read_raw_targets(path: Path) -> list[str]:
    if not path.is_file():
        raise ValueError(f"target file does not exist: {path}")
    seen: set[str] = set()
    result: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            target = clean_target(line.split()[0])
        except ValueError:
            continue
        if target not in seen:
            seen.add(target)
            result.append(target)
    return result


def write_text(path: Path, text: str) -> None:
    atomic_write(path, text)


def run_process(cmd: list[str], cwd: Path, stdout_path: Path, stderr_path: Path, timeout: int) -> tuple[int, bool, float]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    timed_out = False
    budget = current_budget()
    if budget is not None and not budget.reserve_execution("subprocess"):
        write_text(stderr_path, "budget-exhausted: max_executions\n")
        return 125, False, 0.0
    with stdout_path.open("w", encoding="utf-8", errors="replace") as out, stderr_path.open("w", encoding="utf-8", errors="replace") as err:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(cwd),
                env={**os.environ, "PYTHONPATH": str(ROOT / "vendor")},
                stdout=out,
                stderr=err,
                text=True,
                start_new_session=True,
            )
            try:
                rc = proc.wait(timeout=max(1, timeout))
            except subprocess.TimeoutExpired:
                timed_out = True
                rc = 124
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        pass
        except OSError as exc:
            err.write(f"process-start-error: {exc}\n")
            rc = 127
    if budget is not None:
        cap_file(stdout_path, budget.limits["max_output_bytes"])
        cap_file(stderr_path, budget.limits["max_output_bytes"])
    return rc, timed_out, time.monotonic() - started


def load_modules() -> list[dict[str, Any]]:
    raw = json.loads(CATALOG.read_text(encoding="utf-8"))
    modules: list[dict[str, Any]] = []
    for section, records in raw.items():
        if section in {"run_all", "special"}:
            continue
        for record in records:
            item = dict(record)
            item["section"] = section
            modules.append(item)
    return modules


def selector_expansions() -> dict[str, set[str]]:
    """Return catalog family selectors as runnable module-ID sets."""
    raw = json.loads(CATALOG.read_text(encoding="utf-8"))
    sections = {
        "135": "network_infrastructure",
        "136": "web_application_analysis",
        "137": "security_threat_intelligence",
    }
    expanded = {
        selector: {str(item.get("id")) for item in raw.get(section, []) if item.get("script")}
        for selector, section in sections.items()
    }
    expanded["138"] = set().union(*expanded.values())
    for item in raw.get("native_capabilities", []):
        expanded[str(item.get("id"))] = {str(item.get("id"))}
    return expanded


def catalog_selection(value: str) -> tuple[set[str], set[str]]:
    """Return expanded catalog IDs plus literal script tokens for a selection."""
    tokens = {item.strip() for item in str(value or "").split(",") if item.strip()}
    selectors = selector_expansions()
    expanded: set[str] = set()
    for token in tokens:
        expanded.update(selectors.get(token, {token}))
    scripts = {token for token in tokens if token.endswith(".py")}
    return expanded, scripts


def module_class(item: dict[str, Any]) -> str:
    if item.get("native_capability"):
        return "native-selector"
    script = item.get("script", "")
    name = item.get("name", "").lower()
    if script in EXPLICIT_ONLY_NAMES:
        return "explicit-only"
    if script in ACTIVE_NAMES:
        return "active-explicit"
    if script in API_ENV_BY_SCRIPT:
        return "optional-api"
    if any(x in name for x in ("analyzer", "checker", "check", "inventory", "records", "info", "history", "fingerprint")):
        return "automatic-passive"
    if item.get("section") == "web_application_analysis":
        return "automatic-surface"
    return "automatic-passive"


def native_capability_component(capability: str) -> str:
    """Return the production component selected by a native catalog adapter."""
    return str(NATIVE_SELECTOR_CONTRACTS.get(capability, {}).get("component", ""))


def has_api_key(script: str) -> bool:
    names = API_ENV_BY_SCRIPT.get(script, ())
    return not names or all(os.environ.get(name) for name in names)


def load_saved_api_env() -> None:
    """Load installer-managed API values without sourcing arbitrary shell code."""
    locations = []
    explicit = os.environ.get("AH_PUCH_API_FILE")
    if explicit:
        locations.append(Path(explicit).expanduser())
    data_dir = (os.environ.get("AH_PUCH_DATA_DIR") or os.environ.get("AH_PUCH_DATA_DIR") or
                os.path.join(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")), "ah-puch"))
    locations.append(Path(data_dir).expanduser() / "api.env")
    config_dir = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    locations.append(Path(config_dir).expanduser() / "ah-puch" / "api.env")
    for path in locations:
        if not path.is_file():
            continue
        allow_plain = bool(explicit and path.expanduser().resolve() == Path(explicit).expanduser().resolve())
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                key, separator, encoded = raw.partition("=")
                if not separator:
                    continue
                if key.endswith("_B64") and key[:-4] in API_KEY_NAMES and not os.environ.get(key[:-4]):
                    import base64
                    os.environ[key[:-4]] = base64.b64decode(encoded.strip()).decode("utf-8")
                elif allow_plain and key in API_KEY_NAMES and not os.environ.get(key):
                    # Compatibility with old installer files. Values are read
                    # only from an explicitly selected file and as data from
                    # an exact allow-list; the file is never sourced or
                    # interpreted as shell syntax.
                    os.environ[key] = encoded.strip()
            return
        except (OSError, ValueError):
            continue


def extract_urls(paths: list[Path]) -> list[str]:
    found: set[str] = set()
    for path in paths:
        if not path.is_file() or path.stat().st_size > 20_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for value in URL_RE.findall(text):
            found.add(value.rstrip(".,;:)]}"))
    return sorted(found)


def in_target_scope(value: str, target: str) -> bool:
    """Keep queue URLs on the supplied host, subdomains, or CIDR range."""
    try:
        host = (urlsplit(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not host:
        return False
    if "/" in target and not target.startswith(("http://", "https://")):
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
    base = target_host(target).lower().rstrip(".")
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(base)
    except ValueError:
        return host == base or host.endswith("." + base)


def scoped_urls(values: list[str], target: str) -> list[str]:
    return [value for value in values if in_target_scope(value, target)]


def merge_ordered(existing: list[str], additions: list[str]) -> list[str]:
    seen = set(existing)
    result = list(existing)
    for value in additions:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def origins(urls: list[str], fallback: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for value in urls:
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            host = parsed.hostname.lower().rstrip(".")
            display_host = f"[{host}]" if ":" in host else host
            netloc = display_host + (f":{parsed.port}" if parsed.port else "")
            origin = urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))
        except Exception:
            continue
        if origin not in seen:
            seen.add(origin)
            values.append(origin)
    if not values:
        if fallback.startswith(("http://", "https://")):
            values.append(fallback)
        elif "/" in fallback:
            try:
                ipaddress.ip_network(fallback, strict=False)
            except ValueError:
                pass
        elif fallback.count(":") > 1 and not fallback.startswith("["):
            values.append(f"https://[{fallback}]/")
        else:
            values.append(f"https://{fallback}/")
    return values


def target_host(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return urlsplit(target).hostname or target
    if target.startswith("[") and "]" in target:
        return target[1 : target.index("]")]
    return target.strip("[]").rsplit(":", 1)[0] if target.count(":") == 1 else target.strip("[]")


def target_authority(target: str) -> str:
    """Return host plus explicit port, preserving IPv6 brackets."""
    if target.startswith(("http://", "https://")):
        parsed = urlsplit(target)
        if parsed.netloc:
            return parsed.netloc.rsplit("@", 1)[-1]
    return target.strip().split("/", 1)[0]


def _directory_dictionary_path(wordlist_tier: str) -> str:
    try:
        from .dictionary_broker import resolve  # type: ignore
    except ImportError:
        try:
            from dictionary_broker import resolve  # type: ignore
        except ImportError:
            resolve = None  # type: ignore[assignment]
    if resolve:
        resolved = resolve("directory", tier=wordlist_tier)
        if resolved:
            return str(resolved)
    value = ROOT / "data" / "wordlists" / f"web-{wordlist_tier}.txt"
    if wordlist_tier == "long" and not value.is_file():
        value = ROOT / "data" / "wordlists" / "web-short.txt"
    return str(value)


def module_options(
    item: dict[str, Any],
    timeout: int,
    threads: int,
    target: str,
    wordlist_tier: str,
    use_dictionaries: bool = True,
) -> dict[str, Any]:
    """Populate every catalog option with bounded, deterministic defaults."""
    values: dict[str, Any] = {}
    for option in item.get("options", []):
        value = OPTION_DEFAULTS.get(option, "")
        if option == "timeout":
            value = timeout
        elif option in {"threads", "workers", "concurrency"}:
            value = threads if option != "concurrency" else min(threads, 4)
        elif option == "max_pages":
            value = 10
        elif option == "start_url":
            value = target if target.startswith(("http://", "https://")) else f"https://{target}/"
        elif option == "wordlist":
            value = _directory_dictionary_path(wordlist_tier) if use_dictionaries else ""
        values[option] = value
    return values


def parse_option_assignments(values: list[str]) -> dict[str, Any]:
    """Parse global KEY=VALUE and scoped ID.KEY=VALUE overrides."""
    result: dict[str, Any] = {}
    known = set(OPTION_DEFAULTS)
    catalog = {str(item["id"]): item for item in load_modules()}
    for raw in values:
        if "=" not in raw:
            raise ValueError(f"module option must use KEY=VALUE: {raw}")
        assignment, value = raw.split("=", 1)
        assignment = assignment.strip()
        module_id = ""
        key = assignment
        if "." in assignment:
            module_id, key = (part.strip() for part in assignment.split(".", 1))
            if not module_id.isdigit() or str(int(module_id)) not in catalog:
                raise ValueError(f"unknown scoped module option owner: {module_id}")
            module_id = str(int(module_id))
        if key not in known:
            raise ValueError(f"unknown module option: {key}")
        if module_id and key not in catalog[module_id].get("options", []):
            raise ValueError(f"module {module_id} does not declare option: {key}")
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = value
        result[f"{module_id}.{key}" if module_id else key] = parsed
    return result


def partition_option_assignments(values: list[str]) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Separate global overrides from per-module overrides after validation."""
    global_options: dict[str, Any] = {}
    module_options_by_id: dict[str, dict[str, Any]] = {}
    for assignment, value in parse_option_assignments(values).items():
        if "." not in assignment:
            global_options[assignment] = value
            continue
        module_id, key = assignment.split(".", 1)
        module_options_by_id.setdefault(module_id, {})[key] = value
    return global_options, module_options_by_id


def apply_module_option_overrides(
    item: dict[str, Any],
    options: dict[str, Any],
    global_options: dict[str, Any],
    module_options_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Apply global then per-module values; the narrowest scope wins."""
    declared = set(item.get("options", []))
    for key, value in global_options.items():
        if key in declared:
            options[key] = value
    for key, value in module_options_by_id.get(str(item.get("id", "")), {}).items():
        options[key] = value
    return options


def apply_common_customizations(args: argparse.Namespace) -> None:
    """Translate friendly depth controls into the canonical module options."""
    pairs = (
        ("depth", "depth"),
        ("max_pages", "max_pages"),
        ("max_scripts", "max_scripts"),
        ("max_params", "max_params"),
        ("samples", "samples"),
        ("max_hosts", "max_hosts"),
        ("workers", "workers"),
        ("rate_limit", "rate_limit"),
    )
    args.module_options = list(getattr(args, "module_options", []))
    for attribute, option in pairs:
        value = getattr(args, attribute, None)
        if value is not None:
            args.module_options.append(f"{option}={value}")


def explicit_cli_fields(raw_argv: list[str], parser_instance: argparse.ArgumentParser) -> set[str]:
    """Return destinations explicitly supplied by the caller.

    Saved profiles provide defaults, but an option present on the command line
    must win even when its parsed value is otherwise indistinguishable from an
    argparse default (notably ``--active``/``--passive``).
    """
    fields: set[str] = set()
    for action in parser_instance._actions:
        if not action.dest or action.dest == argparse.SUPPRESS:
            continue
        for option in action.option_strings:
            if any(token == option or token.startswith(f"{option}=") for token in raw_argv):
                fields.add(action.dest)
                break
    return fields


def print_saved_config(name: str | None = None) -> None:
    values = load_saved_configs() if not name else {name: load_saved_config(name)}
    print(json.dumps(values, ensure_ascii=False, indent=2, sort_keys=True))


def tool_option_help() -> str:
    lines = ["Native tool options (use --tool-option TOOL.KEY=VALUE):"]
    for tool, options in TOOL_OPTION_DEFAULTS.items():
        lines.append(f"  {tool:<10} {','.join(options)}")
    return "\n".join(lines)


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def write_integrity_artifacts(root: Path) -> None:
    """Seal regular result files and record their modes and sizes."""
    inventory = ["path\ttype\tmode\tbytes\tsha256"]
    checksums: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.name in {"checksums.sha256", "storage_inventory.tsv"} or not path.is_file() or path.is_symlink():
            continue
        try:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                continue
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
            relative = str(path.relative_to(root))
            checksum = digest.hexdigest()
            inventory.append(f"{relative}\tfile\t{metadata.st_mode & 0o777:o}\t{metadata.st_size}\t{checksum}")
            checksums.append(f"{checksum}  {relative}")
        except OSError:
            continue
    write_text(root / "storage_inventory.tsv", "\n".join(inventory) + "\n")
    inventory_digest = hashlib.sha256((root / "storage_inventory.tsv").read_bytes()).hexdigest()
    checksums.append(f"{inventory_digest}  storage_inventory.tsv")
    write_text(root / "checksums.sha256", "\n".join(sorted(checksums)) + "\n")


def verify_integrity_artifacts(root: Path) -> int:
    """Verify a saved run's checksum ledger without contacting its target."""
    checksum_path = root / "checksums.sha256"
    if not root.is_dir() or not checksum_path.is_file():
        print(f"integrity: missing run or checksum ledger: {root}", file=sys.stderr)
        return 2
    failures: list[str] = []
    listed: set[str] = set()
    try:
        rows = checksum_path.read_text(encoding="utf-8", errors="strict").splitlines()
    except OSError as exc:
        print(f"integrity: cannot read checksum ledger: {exc}", file=sys.stderr)
        return 2
    for row in rows:
        if not row.strip():
            continue
        digest, separator, relative = row.partition("  ")
        relative_path = Path(relative)
        if relative_path.is_absolute() or relative_path.anchor or ".." in relative_path.parts:
            failures.append(relative or "invalid checksum row")
            continue
        candidate = (root / relative_path).resolve()
        try:
            candidate.relative_to(root.resolve())
            inside_root = True
        except ValueError:
            inside_root = False
        if not separator or len(digest) != 64 or not inside_root:
            failures.append(relative or "invalid checksum row")
            continue
        listed.add(relative)
        if not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            failures.append(relative)
    inventory = root / "storage_inventory.tsv"
    if inventory.is_file():
        try:
            inventory_rows = inventory.read_text(encoding="utf-8", errors="strict").splitlines()[1:]
        except OSError:
            inventory_rows = []
        for row in inventory_rows:
            fields = row.split("\t")
            if len(fields) != 5:
                failures.append("storage_inventory.tsv")
                continue
            relative, file_type, mode_text, size_text, _digest = fields
            candidate = (root / relative).resolve()
            try:
                candidate.relative_to(root.resolve())
                metadata = candidate.stat()
                expected_mode = int(mode_text, 8)
                expected_size = int(size_text)
            except (OSError, ValueError):
                failures.append(relative or "storage_inventory.tsv")
                continue
            if file_type != "file" or not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected_size or (metadata.st_mode & 0o777) != expected_mode:
                failures.append(relative or "storage_inventory.tsv")
    if failures:
        print(f"integrity: FAILED ({len(failures)} files)", file=sys.stderr)
        for item in failures[:20]:
            print(f"  {item}", file=sys.stderr)
        return 10
    for candidate in root.rglob("*"):
        if not candidate.is_file() or candidate.is_symlink() or candidate.name == "checksums.sha256":
            continue
        relative = str(candidate.relative_to(root))
        if relative not in listed:
            failures.append(relative)
    if failures:
        print(f"integrity: FAILED ({len(failures)} files)", file=sys.stderr)
        for item in failures[:20]:
            print(f"  {item}", file=sys.stderr)
        return 10
    print(f"integrity: OK ({len(listed)} files) {root}")
    return 0


def reseal_saved_run(root: Path) -> None:
    """Refresh status projections and integrity after local queue rebuilds."""
    status_path = root / "module_status.jsonl"
    status_rows: list[dict[str, Any]] = []
    if status_path.is_file():
        for raw in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                status_rows.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
    write_json(root / "module_status.json", status_rows)
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {}
    manifest["integrity"] = {"status": "sealed", "algorithm": "sha256", "checksums": "checksums.sha256", "inventory": "storage_inventory.tsv"}
    write_json(manifest_path, manifest)
    write_integrity_artifacts(root)


def rebuild_saved_run(saved: Path, target: str, timeout: int) -> int:
    """Rebuild a saved run with the same bounded process lifecycle as normal runs."""
    cmd = [sys.executable, str(CORE_ENGINE), "--target", target, "--output", str(saved), "--profile", "baseline", "--timeout", "1", "--rebuild-saved"]
    rc, _timed_out, _duration = run_process(
        cmd,
        saved,
        saved / "rebuild.core.console.txt",
        saved / "rebuild.core.error.txt",
        timeout,
    )
    reseal_saved_run(saved)
    return rc


def print_tool_info() -> None:
    print("Core pipeline")
    for name, description in (
        ("discovery", "subdomains, historical URLs, and address attribution"),
        ("dns", "record types and resolved addresses"),
        ("http", "live services and HTTP metadata"),
        ("crawl", "bounded crawling and directory discovery"),
        ("endpoints", "parameters, APIs, forms, and consumer queues"),
        ("analysis", "secrets, technologies, assets, and ICS indicators"),
        ("network", "range, ports, services, TLS, and web checks"),
        ("camera", "camera, video, recorder, RTSP, ONVIF, and device surface detection"),
        ("consumers", "SQLMap, Nmap, Nikto, Arachni, Wapiti, ZAP, and Nuclei"),
    ):
        print(f"  {name:<12} {description}")
    modules = load_modules()
    print(f"\nSurface catalog: {len(modules)} modules")
    for item in modules:
        options = ",".join(item.get("options", [])) or "-"
        print(f"  {item['id']:>3}  {item.get('name', item.get('script', ''))}")
        print(f"       input={item.get('primary_input', '-')}  options={options}")
    print("\nFamily selectors: 135=network, 136=web, 137=security, 138=all runnable modules")
    print(f"\n{tool_option_help()}")
    print(f"\n{preset_help()}")


def explain_plan(args: argparse.Namespace) -> dict[str, Any]:
    """Return the resolved, non-contact execution plan for operator review."""
    budget = ExecutionBudget.from_namespace(args)
    target = getattr(args, "target_opt", "") or getattr(args, "target", "") or ""
    return {
        "schema_version": 1,
        "program": PROGRAM,
        "version": VERSION,
        "target_ref": safe_target(target),
        "profile": str(getattr(args, "profile", "")),
        "run": str(getattr(args, "run", "")),
        "active": bool(getattr(args, "active", False)),
        "passive": bool(getattr(args, "passive", False)),
        "dry_run": bool(getattr(args, "dry_run", False)),
        "no_dictionaries": bool(getattr(args, "no_dictionaries", False)),
        "catalog_modules": str(getattr(args, "catalog_modules", "")),
        "integrated_capabilities": str(getattr(args, "integrated_capabilities", "")),
        "pipeline_mode": str(getattr(args, "pipeline_mode", "")),
        "limits": budget.limits,
        "tool_options": parse_tool_assignments(getattr(args, "tool_options", [])),
        "input_contract": {
            "required": "one target input",
            "accepted": TARGET_INPUT_CONTRACT,
            "scope_source": "operator target",
        },
        "guarantees": {
            "target_contact": "only after normal target and scope validation",
            "interactive_auth_required": False,
            "credential_input_required": False,
            "api_keys_required": False,
            "authorization_manifest_required": False,
            "optional_auth_modes": ["--credential-audit", "--auth-validate"],
            "external_installation": False,
            "private_artifacts": "0600",
            "run_directory": "0700",
            "recovery": "checkpoint.json plus runtime/recovery.json",
        },
    }


def print_dictionary_info() -> None:
    root = ROOT / "data"
    print("Bundled wordlist tiers")
    for tier, name in (("micro", "web-micro.txt"), ("short", "web-short.txt"), ("long", "web-long.txt")):
        path = root / "wordlists" / name
        print(f"  {tier:<6} {path}  {'available' if path.is_file() else 'import locally'}")
    print(f"  categories {len(list((root / 'wordlists' / 'categories').glob('*_short.txt')))} technology/type short lists")
    print(f"  patterns   {len(list((root / 'payloads').glob('*.txt')))} typed protocol/test-pattern corpora")
    print("  Range paths " + str(root / "wordlists" / "range.paths.txt"))


def _print_catalog_rows(rows: list[dict[str, Any]], *, detailed: bool = False) -> None:
    for item in sorted(rows, key=lambda value: int(value["id"])):
        marker = "selector" if item.get("native_capability") or not item.get("script") else "module"
        print(f"{str(item['id']):>3}  {item.get('name', '')}  [{marker}]")
        if detailed:
            options = ",".join(item.get("options", [])) or "-"
            print(f"     input={item.get('primary_input', '-')} options={options} status={module_class(item)}")


def catalog_browser(args: argparse.Namespace) -> bool:
    """Interactive catalog browser that returns selection to the unified runner."""
    modules = {str(item["id"]): item for item in load_modules()}
    state = load_browser_state()
    favorites = [value for value in state.get("favorites", []) if value in modules]
    recent = [value for value in state.get("recent", []) if value in modules]
    last = [value for value in state.get("last", []) if value in modules]
    selected: list[str] = []

    def persist() -> None:
        save_browser_state(favorites=favorites, recent=recent, last=last)

    def select(values: list[str]) -> bool:
        nonlocal selected
        selected = list(dict.fromkeys(value for value in values if value in modules))
        if not selected:
            print("No valid module IDs selected.")
            return False
        print("selected: " + ",".join(selected))
        return True

    def prepare_run(values: list[str], target: str = "") -> bool:
        nonlocal last, recent
        if not select(values):
            return False
        value = target.strip() or input(TARGET_INPUT_PROMPT).strip()
        if not value:
            print("A target/input is required.")
            return False
        args.target = value
        args.catalog_modules = ",".join(selected)
        recent = (recent + selected)[-20:]
        last = list(selected)
        persist()
        return True

    print("Native catalog browser. Type 'help' for commands; execution returns through the unified runner.")
    while True:
        try:
            words = shlex.split(input("catalog> ").strip())
        except ValueError as exc:
            print(f"invalid command: {exc}")
            continue
        if not words:
            continue
        command, tail = words[0].casefold(), words[1:]
        if command in {"back", "quit", "exit"}:
            persist()
            return False
        if command == "help":
            if tail and tail[0] in modules:
                _print_catalog_rows([modules[tail[0]]], detailed=True)
            else:
                print("list [detail] | search TEXT | use ID[,ID] | help ID | options [full]")
                print("set [ID.]KEY=VALUE | set ID KEY=VALUE | unset [ID.]KEY | run [TARGET]")
                print("runall infra|web|security|all [TARGET]")
                print("fav add|del|list|run [IDs] | recent | rerun [TARGET] | view RUN [module|runner]")
                print("grep RUN QUERY | doctor | api | back")
            continue
        if command == "list":
            _print_catalog_rows(list(modules.values()), detailed=bool(tail and tail[0] == "detail"))
            continue
        if command == "search":
            query = " ".join(tail).casefold()
            _print_catalog_rows([
                item for item in modules.values()
                if query in " ".join((str(item.get("id", "")), str(item.get("name", "")), str(item.get("description", "")), str(item.get("script", "")))).casefold()
            ], detailed=True)
            continue
        if command == "use":
            select([value for token in tail for value in token.split(",")])
            continue
        if command == "options":
            rows = [modules[value] for value in selected]
            if not rows:
                print("Select modules first with 'use'.")
                continue
            for item in rows:
                options = item.get("options", [])
                print(f"{item['id']} {item.get('name')}: {', '.join(options) if options else 'no module options'}")
            if tail and tail[0] == "full":
                print(tool_option_help())
            continue
        if command == "set":
            if len(tail) >= 2 and tail[0].isdigit() and "=" in tail[1]:
                assignment = f"{tail[0]}.{tail[1]}"
            else:
                assignment = tail[0] if tail else ""
            if not selected or "=" not in assignment:
                print("usage: set [ID.]KEY=VALUE (or set ID KEY=VALUE) after selecting modules")
                continue
            owner_and_key = assignment.split("=", 1)[0]
            owner, key = owner_and_key.split(".", 1) if "." in owner_and_key else ("", owner_and_key)
            if owner and owner not in selected:
                print(f"module {owner!r} is not selected.")
                continue
            allowed = {option for value in selected for option in modules[value].get("options", [])}
            if key not in allowed:
                print(f"{key!r} is not declared by the selected modules.")
                continue
            if key in {"advisory_store", "device_data"}:
                value = assignment.split("=", 1)[1].strip()
                if not value or any(character in value for character in ("\x00", "\r", "\n")):
                    print("local artifact path is invalid")
                    continue
                setattr(args, key, value)
                print(f"accepted: {key}=<local-artifact>")
                continue
            try:
                parse_option_assignments([assignment])
            except ValueError as exc:
                print(exc)
                continue
            args.module_options = [value for value in args.module_options if value.split("=", 1)[0] != owner_and_key]
            args.module_options.append(assignment)
            print(f"accepted: {owner_and_key}")
            continue
        if command == "unset":
            if not tail:
                print("usage: unset KEY")
                continue
            key = tail[0]
            args.module_options = [value for value in args.module_options if value.split("=", 1)[0] != key]
            if key in {"advisory_store", "device_data"}:
                setattr(args, key, "")
            print(f"unset: {key}")
            continue
        if command == "run":
            if prepare_run(selected, " ".join(tail)):
                return True
            continue
        if command == "runall":
            family = tail[0].casefold() if tail else ""
            selector = {"infra": "135", "infrastructure": "135", "web": "136", "security": "137", "all": "138"}.get(family)
            if not selector:
                print("usage: runall infra|web|security|all [TARGET]")
                continue
            if prepare_run([selector], " ".join(tail[1:])):
                return True
            continue
        if command == "fav":
            action = tail[0].casefold() if tail else "list"
            values = [value for token in tail[1:] for value in token.split(",") if value in modules]
            if action == "add":
                favorites = list(dict.fromkeys(favorites + (values or selected)))
                persist()
            elif action in {"del", "remove"}:
                favorites = [value for value in favorites if value not in set(values or selected)]
                persist()
            elif action == "run":
                if prepare_run(favorites, ""):
                    return True
            elif action != "list":
                print("usage: fav add|del|list|run [IDs]")
                continue
            print("favorites: " + (",".join(favorites) if favorites else "none"))
            continue
        if command == "recent":
            print("recent: " + (",".join(recent) if recent else "none"))
            continue
        if command in {"rerun", "last"}:
            if prepare_run(last, " ".join(tail)):
                return True
            continue
        if command == "view":
            if not tail:
                print("usage: view RUN [module|runner]")
                continue
            operation = {"module": "view-module", "runner": "view-runner"}.get(tail[1].casefold(), "view") if len(tail) > 1 else "view"
            try:
                print(json.dumps(inspect_saved_run(Path(tail[0]), operation), ensure_ascii=False, indent=2))
            except (OSError, ValueError) as exc:
                print(exc)
            continue
        if command == "grep":
            if len(tail) < 2:
                print("usage: grep RUN QUERY")
                continue
            try:
                print(json.dumps(inspect_saved_run(Path(tail[0]), "grep", query=" ".join(tail[1:])), ensure_ascii=False, indent=2))
            except (OSError, ValueError) as exc:
                print(exc)
            continue
        if command == "doctor":
            try:
                from .runner_registry import RUNNERS, inspect_runner
            except ImportError:
                from runner_registry import RUNNERS, inspect_runner
            for name in sorted(RUNNERS):
                row = inspect_runner(name)
                print(f"{name}: {'available' if row.get('available') else 'dependency unavailable'} contract={'ok' if row.get('contract_ok') else 'unverified'}")
            continue
        if command == "api":
            for name in API_KEY_NAMES:
                print(f"{name}: {'configured' if os.environ.get(name) else 'not configured'}")
            continue
        print("Unknown catalog command. Type 'help'.")


class UnifiedRun:
    def __init__(self, target: str, args: argparse.Namespace):
        self.target = clean_target(target)
        self.args = args
        self.root = create_run_root(Path(args.output), self.target)
        self.execution_budget = ExecutionBudget.from_namespace(args)
        self._budget_context = activate_budget(self.execution_budget)
        self.current_stage = "initialized"
        # Every worker pool is subordinate to the invocation-wide cap.  The
        # specialized adapters retain their own stricter defaults, while a
        # command-line override cannot accidentally create an unbounded fanout.
        for attribute in (
            "threads", "pipeline_workers", "device_workers", "integrated_workers",
            "integrated_http_workers", "integrated_probe_workers", "saw_workers",
        ):
            if hasattr(self.args, attribute):
                setattr(self.args, attribute, max(1, min(int(getattr(self.args, attribute)), self.execution_budget.limits["max_concurrency"])))
        self.core_root = self.root / "core"
        self.module_root = self.root / "ahpuch_modules"
        self.queue_root = self.root / "queues"
        self.queue_root.mkdir(mode=0o700)
        self.events: list[dict[str, Any]] = []
        self.seed_urls: list[str] = [self.target] if self.target.startswith(("http://", "https://")) else []
        self.seed_hosts: list[str] = [] if "/" in self.target else [target_host(self.target)]
        self.option_overrides, self.module_option_overrides = partition_option_assignments(self.args.module_options)
        self.tool_option_overrides = parse_tool_assignments(self.args.tool_options)
        self.progress = Progress(enabled=bool(self.args.progress) and not bool(self.args.quiet))
        self.alerts = AlertSink(self.root, self.target, console=not bool(self.args.no_alert_console), desktop=bool(self.args.alert_desktop))
        self.checkpoint_path = self.root / "checkpoint.json"
        chosen = {value.strip() for value in str(args.catalog_modules or "").split(",") if value.strip()}
        raw_catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.native_capabilities = {
            str(item.get("native_capability"))
            for item in raw_catalog.get("native_capabilities", [])
            if str(item.get("id")) in chosen and item.get("native_capability")
        }
        planned_stages = getattr(args, "integrated_native_stages", None)
        self.integrated_native_stages: frozenset[str] | None = None
        if planned_stages is not None:
            self.integrated_native_stages = frozenset(
                value.strip()
                for value in str(planned_stages).split(",")
                if value.strip()
            )
        for profile in ("baseline", "full", "deep"):
            if f"profile-{profile}" in self.native_capabilities:
                self.args.profile = profile
        if "profile-baseline" in self.native_capabilities:
            self.args.active = False
            self.args.passive = True
        if "proxy-active" in self.native_capabilities:
            self.args.zap_active = True

    def native_stage_enabled(self, *capabilities: str) -> bool:
        """Return whether an explicitly selected native adapter enables a stage."""
        if self.integrated_native_stages is None and not self.native_capabilities:
            return True
        allowed: set[str] = set(self.integrated_native_stages or ())
        for capability in self.native_capabilities:
            if capability in capabilities:
                return True
            allowed.update(NATIVE_SELECTOR_CONTRACTS.get(capability, {}).get("stages", set()))
        return bool(allowed.intersection(capabilities))

    def selected_advanced_consumers(self) -> set[str] | None:
        """Return the exact advanced-runner subset selected by native adapters."""
        if self.integrated_native_stages is None and not self.native_capabilities:
            return None
        capabilities = {
            "template-assessment": "template-checks",
            "web-server-assessment": "web-server-check",
            "secondary-web-audit": "web-audit-secondary",
            "proxy-passive": "web-proxy-passive",
            "proxy-active": "web-proxy-active",
            "parameter-validation": "parameter-validation",
        }
        if self.native_capabilities & {"profile-full", "profile-deep"}:
            return set(capabilities.values()) | {"tls-configuration"}
        selected = set(self.native_capabilities) | set(self.integrated_native_stages or ())
        return {runner_id for capability, runner_id in capabilities.items() if capability in selected}

    def event(self, value: dict[str, Any]) -> None:
        self.events.append(value)
        self.current_stage = str(value.get("engine") or value.get("stage") or self.current_stage)
        with (self.root / "module_status.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            (self.root / "module_status.jsonl").chmod(0o600)
        except OSError:
            pass
        try:
            checkpoint(
                self.checkpoint_path,
                self.current_stage,
                "running",
                events=len(self.events),
                budget_status=self.execution_budget.snapshot()["status"],
            )
        except OSError:
            # A progress checkpoint is best-effort; the event itself remains
            # authoritative and the final integrity gate reports write loss.
            pass

    def run_native(self) -> None:
        if self.args.no_native:
            self.event({"engine": "recon_core", "status": "skipped", "reason": "--no-core"})
            return
        self.progress.show("core: discovery, range, web, ICS, and queue stages")
        profile = self.args.profile
        cmd = [sys.executable, str(CORE_ENGINE), "--target", self.target, "--output", str(self.core_root), "--profile", profile, "--run", profile, "--non-interactive", "--timeout", str(min(self.args.native_timeout, 1800))]
        cmd.extend(["--wordlist-tier", self.args.wordlist_tier])
        if getattr(self.args, "no_dictionaries", False):
            cmd.append("--no-dictionaries")
        cmd.extend(["--range-ports", self.args.range_ports, "--range-rate", str(self.args.range_rate), "--range-host-limit", str(self.args.range_host_limit)])
        for assignment in self.args.tool_options:
            cmd.extend(["--tool-option", assignment])
        if self.args.active:
            cmd.append("--intrusive")
        if self.args.dry_run:
            self.event({"engine": "recon_core", "status": "planned", "command": cmd, "reason": "--dry-run"})
            return
        started = time.monotonic()
        target_slug = slug(self.target)
        rc, timed_out, duration = run_process(cmd, self.root, self.root / f"{target_slug}.core.console.txt", self.root / f"{target_slug}.core.error.txt", self.args.native_timeout)
        core_files = list(self.core_root.rglob("*.txt")) + list(self.core_root.rglob("*.jsonl"))
        ordered_queue = next(iter(self.core_root.rglob("*.analysis-order.txt")), None)
        if ordered_queue and ordered_queue.is_file():
            ordered = [line.strip() for line in ordered_queue.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
            self.seed_urls = merge_ordered(self.seed_urls, scoped_urls([value for value in ordered if value.startswith(("http://", "https://"))], self.target))
        self.seed_urls = merge_ordered(self.seed_urls, scoped_urls(extract_urls(core_files), self.target))
        for queue_file in self.core_root.rglob("*.hosts.txt"):
            try:
                self.seed_hosts = sorted(set(self.seed_hosts + [line.strip() for line in queue_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]))
            except OSError:
                pass
        for service_file in self.core_root.glob("10-range/*.masscan.services.txt"):
            try:
                for line in service_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    host, separator, port = line.partition("\t")
                    if not separator or not host or not port:
                        continue
                    self.seed_hosts.append(host.strip())
                    if port.strip() in {"80", "443", "8000", "8080", "8443"}:
                        scheme = "https" if port.strip() in {"443", "8443"} else "http"
                        candidate = f"{scheme}://{host.strip()}:{port.strip()}/"
                        if in_target_scope(candidate, self.target):
                            self.seed_urls.append(candidate)
            except OSError:
                pass
        if "/" in self.target:
            self.seed_hosts = [host for host in sorted(set(self.seed_hosts)) if "/" not in host][: self.args.range_host_limit]
        else:
            self.seed_hosts = sorted(set(self.seed_hosts))[: self.args.range_host_limit]
        self.seed_urls = merge_ordered(self.seed_urls, [])
        status = "timeout" if timed_out else ("success" if rc == 0 else "partial")
        self.event({"engine": "recon_core", "status": status, "exit_code": rc, "duration": round(duration, 3), "files": len(core_files), "started": started})
        self.ingest_core_alerts()

    def selected_modules(self) -> list[dict[str, Any]]:
        modules = load_modules()
        if self.args.catalog_modules:
            expanded, scripts = catalog_selection(self.args.catalog_modules)
            modules = [m for m in modules if str(m.get("id")) in expanded or m.get("script") in scripts]
        if self.args.catalog_limit:
            modules = modules[: self.args.catalog_limit]
        return modules

    def module_inputs(self, item: dict[str, Any]) -> list[str]:
        primary = str(item.get("primary_input", "")).lower()
        limit = self.args.max_inputs
        if "token" in primary or "string" in primary:
            values = [self.target]
        elif any(hint in primary for hint in AUTHORITY_INPUT_HINTS):
            values = [target_authority(self.target)]
        elif any(hint in primary for hint in URL_INPUT_HINTS):
            values = origins(self.seed_urls, self.target)
        else:
            values = self.seed_hosts
        return values if limit == 0 else values[:limit]

    def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
        script = item["script"]
        module_id = str(item["id"])
        name = item.get("name", script)
        classification = module_class(item)
        destination = self.module_root / f"{module_id}-{slug(name)}" / str(index)
        destination.mkdir(parents=True, mode=0o700)
        module_slug = slug(name)
        stdout_path = destination / f"{slug(self.target)}.{module_slug}.stdout.txt"
        stderr_path = destination / f"{slug(self.target)}.{module_slug}.stderr.txt"
        command_path = destination / f"{slug(self.target)}.{module_slug}.command.json"
        base_event = {"engine": "ahpuch_modules", "module_id": module_id, "module": name, "script": script, "class": classification, "input": input_value}
        if classification == "native-selector":
            capability = str(item.get("native_capability", ""))
            component = native_capability_component(capability)
            if not component:
                self.write_module_text(
                    destination,
                    {**base_event, "engine": "native_capability", "capability": capability, "reason": "unmapped native capability"},
                    "failed",
                    "Native capability has no production component mapping.\n",
                )
                return
            terminal_engine = {
                "recon-dns": "recon_core", "http-inventory": "http_inventory",
                "web-fanout": "web_fanout", "network-profile": "network_profile_runtime",
                "tls-inventory": "tls_inventory", "template-assessment": "advanced_consumers",
                "web-server-assessment": "advanced_consumers", "secondary-web-audit": "advanced_consumers",
                "proxy-passive": "advanced_consumers", "proxy-active": "advanced_consumers",
                "parameter-validation": "advanced_consumers",
            }.get(capability, "")
            downstream = next(
                (row for row in reversed(self.events) if terminal_engine and row.get("engine") == terminal_engine),
                None,
            )
            terminal_status = str(downstream.get("status")) if downstream else ""
            status = "planned" if self.args.dry_run else (terminal_status or "selected")
            self.write_module_text(
                destination,
                {
                    **base_event, "engine": "native_capability", "capability": capability,
                    "component": component, "terminal_engine": terminal_engine,
                    "downstream_events": 1 if downstream else 0,
                },
                status,
                (
                    f"Native capability completed through production component: {component}.\n"
                    if downstream else f"Native capability routed through production component: {component}.\n"
                ),
            )
            return
        if classification in {"active-explicit", "explicit-only"} and not self.args.active:
            self.write_module_text(destination, {**base_event, "reason": "explicit active module requires --active"}, "skipped", "Explicit active module requires --active; no subprocess was started.\n")
            return
        if classification == "optional-api" and not has_api_key(script):
            self.write_module_text(destination, {**base_event, "reason": "API key not configured"}, "skipped", "Optional API key is not configured; no subprocess was started.\n")
            return
        work_dir = destination / ".work"
        work_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        opts = module_options(
            item,
            self.args.module_timeout,
            self.args.threads,
            input_value,
            self.args.wordlist_tier,
            not getattr(self.args, "no_dictionaries", False),
        )
        apply_module_option_overrides(
            item,
            opts,
            self.option_overrides,
            self.module_option_overrides,
        )
        cmd = build_module_command(script, input_value, self.args.threads, opts, self.args.module_timeout)
        if self.args.dry_run:
            write_json(command_path, {"command": cmd, "target": input_value, "options": sanitize_module_options(opts), "status": "planned"})
            self.write_module_text(destination, {**base_event, "reason": "--dry-run"}, "planned", "Command recorded; no subprocess was started.\n")
            return
        started = time.monotonic()
        rc, timed_out, duration = run_process(cmd, work_dir, stdout_path, stderr_path, self.args.module_timeout)
        write_json(command_path, {"command": cmd, "target": input_value, "options": sanitize_module_options(opts)})
        text = ""
        try:
            text = stdout_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        generated: list[str] = []
        for generated_path in work_dir.rglob("*"):
            if not generated_path.is_file():
                continue
            try:
                if generated_path.stat().st_size <= 5_000_000:
                    generated.append(f"[{generated_path.relative_to(work_dir)}]\n{generated_path.read_text(encoding='utf-8', errors='replace').rstrip()}")
            except (OSError, UnicodeError):
                continue
        if generated:
            text = (text.rstrip() + "\n\n" if text.strip() else "") + "\n\n".join(generated)
        shutil.rmtree(work_dir, ignore_errors=True)
        self.seed_urls = merge_ordered(self.seed_urls, scoped_urls(URL_RE.findall(text), self.target))
        stderr_text = ""
        try:
            stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        if timed_out:
            status = "timeout"
        elif rc == 0:
            status = "success"
        else:
            status = "failed"
        event = {**base_event, "status": status, "exit_code": rc, "duration": round(duration, 3), "result_dir": str(destination.relative_to(self.root)), "started": started}
        self.write_module_text(destination, event, status, text)

    def write_module_text(self, destination: Path, event: dict[str, Any], status: str, body: str) -> None:
        """Write a stable human-readable TXT projection for every module result."""
        lines = [f"module={event.get('module', '')}", f"module_id={event.get('module_id', '')}", f"status={status}", f"input={event.get('input', '')}"]
        if event.get("reason"):
            lines.append(f"reason={event['reason']}")
        lines.extend(["", body.rstrip(), ""])
        write_text(destination / f"{slug(self.target)}.{slug(str(event.get('module', 'module')))}.txt", "\n".join(lines))
        self.event({**event, "status": status, "result_dir": str(destination.relative_to(self.root))})

    def run_catalog(self) -> None:
        if self.args.no_catalog:
            self.event({"engine": "ahpuch_modules", "status": "skipped", "reason": "--no-modules"})
            return
        modules = self.selected_modules()
        for item in modules:
            classification = module_class(item)
            if classification == "native-selector":
                # A native selector represents a production stage, not a
                # discovered-host fan-out.  Record it once even for CIDR and
                # local contracts whose ordinary module input queue is empty.
                self.run_catalog_module(item, self.target, 1)
                continue
            if "/" in self.target:
                primary = str(item.get("primary_input", "")).lower()
                has_range_inputs = bool(self.seed_hosts or self.seed_urls)
                supported = any(token in primary for token in ("ip", "cidr", "domain/ip", "domain/url", "url", "host"))
                if not has_range_inputs or not supported:
                    self.event({"engine": "ahpuch_modules", "module_id": str(item["id"]), "module": item.get("name"), "status": "skipped", "reason": "no compatible range input"})
                    continue
            operator_selection = getattr(self.args, "operator_catalog_modules", None)
            if operator_selection is None:
                operator_selection = "" if str(getattr(self.args, "integrated_capabilities", "") or "").strip() else self.args.catalog_modules
            operator_ids, operator_scripts = catalog_selection(str(operator_selection))
            explicitly_selected = str(item.get("id")) in operator_ids or str(item.get("script", "")) in operator_scripts
            skip_reason = "explicit module was not selected by operator" if classification == "explicit-only" and not explicitly_selected else "baseline profile"
            if (classification == "explicit-only" and not explicitly_selected) or (
                self.args.profile == "baseline" and not explicitly_selected and classification not in {"automatic-passive", "analysis-only", "optional-api"}
            ):
                self.event({"engine": "ahpuch_modules", "module_id": str(item["id"]), "module": item.get("name"), "class": classification, "status": "skipped", "reason": skip_reason})
                continue
            for index, input_value in enumerate(self.module_inputs(item), start=1):
                self.run_catalog_module(item, input_value, index)

    def run_camera_surface(self) -> None:
        if self.args.no_camera:
            self.event({"engine": "camera_surface", "status": "skipped", "reason": "--no-camera-analysis"})
            return
        started = time.monotonic()
        try:
            if self.args.dry_run:
                self.event({"engine": "camera_surface", "status": "planned", "reason": "--dry-run"})
                return
            result = analyze_camera_surface(
                self.root,
                self.target,
                active=bool(self.args.active),
                timeout=self.args.module_timeout,
            )
            self.seed_urls = merge_ordered(self.seed_urls, scoped_urls(result.get("urls", []), self.target))
            self.seed_hosts = sorted(set(self.seed_hosts + result.get("hosts", [])))
            self.integrate_camera_queue(result.get("endpoints", []))
            self.event({
                "engine": "camera_surface",
                "status": "success",
                "duration": round(time.monotonic() - started, 3),
                **result.get("summary", {}),
            })
            summary = result.get("summary", {})
            if summary.get("camera_indicators", 0) or summary.get("candidate_endpoints", 0):
                self.alerts.emit("camera/video surface", "high" if summary.get("camera_indicators", 0) else "medium", "medium", f"{summary.get('candidate_endpoints', 0)} candidate endpoints; {summary.get('camera_indicators', 0)} indicators", "camera_surface", "review camera queue")
        except Exception as exc:  # keep the main run reportable if this adapter fails
            self.event({
                "engine": "camera_surface",
                "status": "failed",
                "duration": round(time.monotonic() - started, 3),
                "error": f"{type(exc).__name__}: {exc}",
            })

    def ingest_core_alerts(self) -> None:
        """Promote core ICS alerts into the unified target alert stream."""
        for path in self.core_root.glob("alerts/*.alerts.txt"):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                evidence = line.split("\tevidence=", 1)[-1].strip()
                category = line.split("\tsource=", 1)[0].strip() or "industrial indicator"
                self.alerts.emit(category, "high", "medium", evidence, str(path.relative_to(self.root)), "review ICS queue")

    def dispatch_followups(self) -> None:
        """Run bounded second-pass modules for newly classified queues."""
        if self.args.dry_run:
            self.event({"engine": "follow_up", "status": "planned", "reason": "--dry-run"})
            return
        if not self.args.follow_up or self.args.follow_up_rounds < 1:
            self.event({"engine": "follow_up", "status": "skipped", "reason": "follow-up disabled"})
            return
        camera_file = self.queue_root / f"{slug(self.target)}.camera.candidates.txt"
        ics_file = self.core_root / "09-ics" / f"{slug(self.target)}.ics-candidates.txt"
        camera_values = [line.strip() for line in camera_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()] if camera_file.is_file() else []
        ics_values = [line.strip() for line in ics_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()] if ics_file.is_file() else []
        modules = {str(item.get("name")): item for item in load_modules()}
        camera_names = ("Server Info", "HTTP Headers", "HTTP/2 and HTTP/3 Support Checker", "TLS Security Configuration")
        ics_names = ("Open Ports Scan", "Server Info", "UDP Service Sampler", "IP Info")
        plan = self.root / "queues" / f"{slug(self.target)}.follow-up-plan.jsonl"
        plan.parent.mkdir(parents=True, exist_ok=True)
        rounds = max(1, min(self.args.follow_up_rounds, 3))
        dispatched = 0
        with plan.open("w", encoding="utf-8") as handle:
            for round_number in range(1, rounds + 1):
                if round_number > 1 and not (camera_values or ics_values):
                    break
                for kind, values, names in (("camera", camera_values, camera_names), ("ics", ics_values, ics_names)):
                    for value in values[: self.args.range_host_limit]:
                        if kind == "camera" and not value.startswith(("http://", "https://")):
                            continue
                        for name in names:
                            item = modules.get(name)
                            if not item:
                                continue
                            handle.write(json.dumps({"round": round_number, "kind": kind, "module": name, "input": value}, ensure_ascii=False) + "\n")
                            self.run_catalog_module(item, value, dispatched + 1)
                            dispatched += 1
        try:
            plan.chmod(0o600)
        except OSError:
            pass
        self.event({"engine": "follow_up", "status": "success", "rounds": rounds, "camera_inputs": len(camera_values), "ics_inputs": len(ics_values), "dispatched": dispatched, "plan": str(plan.relative_to(self.root))})

    def integrate_camera_queue(self, endpoints: list[str]) -> None:
        """Make camera endpoints visible to the shared analysis-order queue."""
        if not endpoints:
            return
        queue_path = self.queue_root / f"{slug(self.target)}.camera.candidates.txt"
        existing = set()
        if queue_path.is_file():
            existing.update(line.strip() for line in queue_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        existing.update(value.strip() for value in endpoints if value.strip())
        write_text(queue_path, "\n".join(sorted(existing)) + "\n")

        order_path = self.queue_root / f"{slug(self.target)}.analysis-order.tsv"
        order: dict[str, tuple[int, str, str, str]] = {}
        if order_path.is_file():
            for line in order_path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
                fields = line.split("\t", 4)
                if len(fields) != 5:
                    continue
                try:
                    order[fields[3]] = (int(fields[0]), fields[1], fields[2], fields[4])
                except ValueError:
                    continue
        for endpoint in existing:
            order.setdefault(endpoint, (96, "camera.candidates", "camera-service-review", "camera or video-device service candidate"))
        rows = ["score\tqueue\tconsumer\tvalue\treason"]
        rows.extend(
            f"{score}\t{queue}\t{consumer}\t{value}\t{reason}"
            for value, (score, queue, consumer, reason) in sorted(order.items(), key=lambda item: (-item[1][0], item[0]))
        )
        write_text(order_path, "\n".join(rows) + "\n")

    def finish(self) -> int:
        urls = sorted(set(self.seed_urls))
        write_text(self.queue_root / f"{slug(self.target)}.urls.txt", "\n".join(urls) + ("\n" if urls else ""))
        hosts = sorted({urlsplit(u).hostname for u in urls if urlsplit(u).hostname} | {target_host(self.target)})
        write_text(self.queue_root / f"{slug(self.target)}.hosts.txt", "\n".join(hosts) + ("\n" if hosts else ""))
        counts: dict[str, int] = {}
        for event in self.events:
            key = str(event.get("status", "unknown"))
            counts[key] = counts.get(key, 0) + 1
        write_json(self.root / f"{slug(self.target)}.summary.json", {"version": VERSION, "target": self.target, "run": str(self.root), "events": len(self.events), "statuses": counts, "urls": len(urls), "hosts": len(hosts)})
        lines = [f"{PROGRAM} {VERSION}", f"target={self.target}", f"run={self.root}", f"urls={len(urls)}", f"hosts={len(hosts)}"]
        lines.extend(f"{key}={value}" for key, value in sorted(counts.items()))
        write_text(self.root / f"{slug(self.target)}.summary.txt", "\n".join(lines) + "\n")
        result_files = sorted(path for path in self.root.rglob("*.txt") if path.name != "combined.txt")
        combined: list[str] = [f"{PROGRAM} {VERSION} TXT result bundle", f"target={self.target}", ""]
        for path in result_files:
            combined.extend([f"===== {path.relative_to(self.root)} =====", path.read_text(encoding="utf-8", errors="replace").rstrip(), ""])
        combined_path = self.module_root / f"{slug(self.target)}.combined.txt"
        write_text(combined_path, "\n".join(combined))
        result_files = sorted(self.root.rglob("*.txt"))
        index_lines = ["path\tengine\tmodule\tstatus"]
        for path in result_files:
            relative = path.relative_to(self.root)
            event = next((item for item in reversed(self.events) if item.get("result_dir") == str(path.parent.relative_to(self.root))), {})
            index_lines.append("\t".join((str(relative), str(event.get("engine", "recon_core")), str(event.get("module", path.stem)), str(event.get("status", "recorded")))))
        write_text(self.root / f"{slug(self.target)}.txt-index.tsv", "\n".join(index_lines) + "\n")
        status_rows: list[dict[str, Any]] = []
        try:
            for raw in (self.root / "module_status.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    status_rows.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass
        write_json(self.root / "module_status.json", status_rows)
        manifest_path = self.root / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = {}
        manifest["integrity"] = {"status": "sealed", "algorithm": "sha256", "checksums": "checksums.sha256", "inventory": "storage_inventory.tsv"}
        write_json(manifest_path, manifest)
        write_integrity_artifacts(self.root)
        return 0 if counts.get("failed", 0) == 0 and counts.get("timeout", 0) == 0 else 10

    def execute(self) -> int:
        try:
            return self._execute_stages()
        except BaseException as exc:
            try:
                write_recovery_artifact(
                    self.root,
                    stage=self.current_stage,
                    status="interrupted",
                    error=exc,
                    metadata={"events": len(self.events), "budget": self.execution_budget.snapshot()},
                )
                checkpoint(
                    self.checkpoint_path,
                    self.current_stage,
                    "failed",
                    events=len(self.events),
                    interrupted=True,
                    error_type=type(exc).__name__,
                )
                write_integrity_artifacts(self.root)
            except (OSError, ValueError, RuntimeError):
                pass
            raise
        finally:
            try:
                write_budget_artifact(self.root, self.execution_budget, phase="terminal")
                # The budget/recovery artifacts are created after the regular
                # finish seal; reseal so --verify-run describes the real tree.
                reseal_saved_run(self.root)
            except (OSError, ValueError, RuntimeError):
                pass
            try:
                from .runtime_hardening import deactivate_budget
            except ImportError:
                from runtime_hardening import deactivate_budget
            deactivate_budget(self._budget_context)

    def _execute_stages(self) -> int:
        safe_reference = safe_target(self.target)
        write_json(self.root / "manifest.json", {"version": VERSION, "target": safe_reference, "target_sha256": hashlib.sha256(safe_reference.encode("utf-8")).hexdigest(), "profile": self.args.profile, "preset": self.args.preset, "run": self.args.run, "catalog_modules": self.args.catalog_modules, "active": bool(self.args.active), "passive": bool(self.args.passive), "follow_up_rounds": self.args.follow_up_rounds, "module_options": sanitize_module_options(self.args.module_options), "tool_options": self.tool_option_overrides, "no_dictionaries": bool(getattr(self.args, "no_dictionaries", False)), "runtime_limits": dict(self.execution_budget.limits), "dry_run": self.args.dry_run, "created": dt.datetime.now(dt.timezone.utc).isoformat()})
        self.progress.start(5)
        self.run_native()
        self.progress.step("core stages complete")
        self.run_catalog()
        self.progress.step("catalog modules complete")
        camera_requested = self.native_stage_enabled(
            "device", "device-fingerprint", "device-resume", "device-web", "device-stream",
            "device-technology", "device-report",
        )
        if camera_requested and (self.native_capabilities or self.args.camera_only or self.args.profile in {"full", "deep"} or self.args.run in {"camera", "cameras"}):
            self.run_camera_surface()
        self.progress.step("camera and video surface stage complete")
        self.dispatch_followups()
        self.progress.step("finding follow-up stage complete")
        self.alerts.finish()
        rc = self.finish()
        checkpoint(self.checkpoint_path, "complete", "success" if rc == 0 else "failed", profile=self.args.profile, preset=self.args.preset, events=len(self.events), exit_code=rc)
        self.progress.finish("run complete" if rc == 0 else "run completed with failures")
        return rc


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=PROGRAM, description="Unified automatic target assessment runner")
    p.add_argument("target", nargs="?", help=TARGET_INPUT_CONTRACT)
    p.add_argument("-t", "--target", dest="target_opt", help=f"explicit {TARGET_INPUT_CONTRACT}")
    p.add_argument("-T", "--targets-file", metavar="FILE", help="UTF-8 target file; one domain, HTTP(S) URL, IP, host:port, or CIDR range per line")
    p.add_argument("-B", "--build-wordlist", metavar="OUTPUT", help="build a deduplicated wordlist from category files")
    p.add_argument("-WS", "--wordlist-source", default=str(ROOT / "data" / "wordlists" / "categories"))
    p.add_argument("-wt", "--wordlist-timeout", type=int, default=0, metavar="SECONDS", help="optional bound for local external wordlist sorting (0 means no bound)")
    p.add_argument("-bd", "--build-dictionary", dest="build_dictionary", metavar="OUTPUT", help="build a cleaned, deduplicated Ah-Puch directory dictionary")
    p.add_argument("-ds", "--dictionary-source", dest="dictionary_source", default=str(ROOT / "data" / "wordlists" / "categories"), metavar="DIR")
    p.add_argument("-dt", "--dictionary-tier", dest="dictionary_tier", choices=("micro", "short", "long", "all"), default="short")
    p.add_argument("-ads", "--advisory-source", dest="advisory_source", default="", metavar="DIR", help="override the bundled private advisory corpus with a local source")
    p.add_argument("-ai", "--index-advisory-corpus", dest="index_advisory_corpus", default="", metavar="DIR", help="index a local Markdown advisory corpus without requiring a target")
    p.add_argument("-aio", "--advisory-index-output", dest="advisory_index_output", default="", metavar="DIR", help="destination for --index-advisory-corpus")
    p.add_argument("-cpa", "--capture-adapter", choices=tuple(sorted(ADAPTER_CATALOG)), default="", help="offline canonical capture adapter; never contacts a target")
    p.add_argument("-cpi", "--capture-input", default="", metavar="FILE", help="bounded local TXT/CSV/JSON capture for --capture-adapter")
    p.add_argument("-cpo", "--capture-output", default="", metavar="FILE", help="explicit JSON destination for --capture-adapter")
    p.add_argument("-R", "--rebuild-run", metavar="RUN_DIR", help="rebuild analysis-order and queues from a saved run")
    p.add_argument("-vr", "--verify-run", metavar="RUN_DIR", help="verify a saved run checksum ledger without contact")
    p.add_argument("-er", "--export-run", metavar="RUN_DIR", help="export a sealed saved run to a deterministic local archive")
    p.add_argument("-eo", "--export-output", metavar="ARCHIVE.tar.gz", help="explicit out-of-run destination required by --export-run")
    p.add_argument("-sr", "--saved-run", metavar="RUN_DIR", help="inspect a saved run without network contact")
    p.add_argument("-so", "--saved-operation", choices=("view", "view-module", "view-runner", "grep", "inventory", "receipts", "compare", "resume"), default="view")
    p.add_argument("-sq", "--saved-query", default="", help="local search text for --saved-operation grep")
    p.add_argument("-cr", "--compare-run", metavar="RUN_DIR", help="second local run for --saved-operation compare")
    p.add_argument("-o", "--output", default="ah-puch-results")
    p.add_argument("-mxt", "--max-targets", type=int, default=1024, metavar="N", help="invocation-wide maximum targets from --targets-file")
    p.add_argument("-mrq", "--max-requests", type=int, default=10000, metavar="N", help="invocation-wide HTTP/request budget")
    p.add_argument("-mre", "--max-results", type=int, default=20000, metavar="N", help="invocation-wide accepted-result budget")
    p.add_argument("-mrb", "--max-response-bytes", type=int, default=67108864, metavar="BYTES", help="invocation-wide response-body budget")
    p.add_argument("-mob", "--max-output-bytes", type=int, default=20971520, metavar="BYTES", help="maximum captured stdout/stderr per external process")
    p.add_argument("-mex", "--max-executions", type=int, default=4096, metavar="N", help="invocation-wide external execution budget")
    p.add_argument("-mcc", "--max-concurrency", type=int, default=64, metavar="N", help="hard upper bound for all worker-pool settings")
    p.add_argument("-mes", "--max-elapsed-seconds", type=int, default=86400, metavar="SECONDS", help="invocation-wide elapsed-time policy recorded in evidence")
    p.add_argument("-C", "--config", metavar="NAME", help="load a saved non-secret runner configuration")
    p.add_argument("-sc", "--save-config", metavar="NAME", help="save the effective non-secret runner configuration")
    p.add_argument("-dc", "--delete-config", metavar="NAME", help="delete a saved runner configuration")
    p.add_argument("-lc", "--list-configs", action="store_true", help="list saved runner configurations")
    p.add_argument("-shc", "--show-config", action="store_true", help="print the loaded or effective runner configuration")
    p.add_argument("-p", "--profile", choices=("baseline", "full", "deep"), default="full")
    p.add_argument("-P", "--preset", choices=tuple(PRESETS), default="", help="named depth preset for the menu and adaptive runners")
    p.add_argument("-r", "--run", default="", help="full, baseline, deep, core, surface, cameras, capability name, or comma-separated module IDs")
    p.add_argument("-m", "--modules", dest="catalog_modules", metavar="MODULE_IDS", default="", help="Module IDs or script names separated by commas")
    p.add_argument("-l", "--surface-limit", dest="catalog_limit", metavar="COUNT", type=int, default=0)
    p.add_argument("-x", "--module-option", dest="module_options", action="append", default=[], metavar="[ID.]KEY=VALUE", help="override a catalog option globally or for one module ID; repeat for multiple options")
    p.add_argument("-X", "--tool-option", dest="tool_options", action="append", default=[], metavar="TOOL.KEY=VALUE", help="override a native tool option; repeat for multiple options")
    p.add_argument("-d", "--depth", type=int, default=None, help="common crawl/module depth override")
    p.add_argument("-M", "--max-pages", type=int, default=None, help="common maximum page override")
    p.add_argument("-S", "--max-scripts", type=int, default=None, help="common maximum JavaScript override")
    p.add_argument("-Q", "--max-params", type=int, default=None, help="common maximum parameter override")
    p.add_argument("-H", "--max-hosts", type=int, default=None, help="common maximum host override")
    p.add_argument("-W", "--workers", type=int, default=None, help="common worker override")
    p.add_argument("-L", "--rate-limit", type=int, default=None, help="common request rate-limit override")
    p.add_argument("-s", "--samples", type=int, default=None, help="common sample-count override")
    p.add_argument("-j", "--threads", type=int, default=4)
    p.add_argument("-i", "--max-inputs", type=int, default=0, help="maximum inputs per module; 0 uses every discovered input")
    p.add_argument("-w", "--wordlist-tier", choices=("micro", "short", "long"), default="micro", help="bundled directory dictionary tier: micro, short, or long/imported")
    p.add_argument("-ndic", "--no-dictionaries", action="store_true", help="skip dictionary-backed discovery methods; other recon stages continue")
    p.add_argument("-mt", "--module-timeout", type=int, default=60)
    p.add_argument("-ct", "--core-timeout", dest="native_timeout", metavar="SECONDS", type=int, default=3600)
    p.add_argument("-f", "--follow-up", action="store_true", help="dispatch finding queues to bounded follow-up runners")
    p.add_argument("-fr", "--follow-up-rounds", type=int, default=0, help="maximum adaptive follow-up rounds; 0 disables extra rounds")
    p.add_argument("-rp", "--range-ports", default="80,443,554,8000,8080,8554,502,102,20000,47808", help="range service ports or a bounded port expression")
    p.add_argument("-rr", "--range-rate", type=int, default=500, help="range discovery packet rate")
    p.add_argument("-rh", "--range-host-limit", type=int, default=256, help="maximum range hosts passed to follow-up stages")
    p.add_argument("-pr", "--progress", dest="progress", action="store_true", help="show live stage progress in the terminal")
    p.add_argument("-npr", "--no-progress", dest="progress", action="store_false", help="disable live stage progress")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    p.add_argument("-ad", "--alert-desktop", action="store_true", help="send desktop notifications when notify-send is available")
    p.add_argument("-nac", "--no-alert-console", action="store_true", help="write alerts to files without printing them")
    p.set_defaults(progress=True)
    p.add_argument("-a", "--active", action="store_true", help="enable active modules")
    p.add_argument("-pa", "--passive", action="store_true", help="keep active modules out of automatic profiles")
    p.add_argument("-ni", "--non-interactive", action="store_true")
    p.add_argument("-nco", "--no-core", dest="no_native", action="store_true")
    p.add_argument("-nsm", "--no-modules", dest="no_catalog", action="store_true")
    p.add_argument("-co", "--camera-only", action="store_true", help="run camera and video-device surface detection only")
    p.add_argument("-ncam", "--no-camera-analysis", dest="no_camera", action="store_true", help="skip camera and video-device surface detection")
    p.add_argument("-D", "--dry-run", action="store_true", help="write the plan and commands without contacting targets")
    p.add_argument("-ep", "--explain-plan", action="store_true", help="print the resolved offline plan, limits and tool options, then exit")
    p.add_argument("-cs", "--command-surface", action="store_true", help="list every catalog/tool/legacy command contract without executing it")
    p.add_argument("-cso", "--command-surface-output", metavar="FILE", help="write the targetless command surface JSON to a private local file")
    p.add_argument("-I", "--info", action="store_true", help="list the core pipeline and all catalog modules")
    p.add_argument("-cb", "--catalog-browser", action="store_true", help="browse, configure and select modules through the unified runner")
    p.add_argument("-V", "--version", action="version", version=f"{PROGRAM} {VERSION}")
    return p


def choose_module_options(args: argparse.Namespace, selected: list[str], modules: dict[str, dict[str, Any]]) -> None:
    """Collect catalog options for the modules selected in the capability menu."""
    available: dict[str, list[str]] = {}
    for module_id in selected:
        options = [str(value) for value in modules[module_id].get("options", [])]
        if options:
            available[module_id] = options
    if not available:
        print("No module-specific options are declared for this selection.")
        return
    print("\nModule options (KEY=VALUE globally or ID.KEY=VALUE per module; blank to continue)")
    print("Use -x/--module-option on the CLI for the same assignments.")
    for module_id in sorted(available, key=lambda value: int(value)):
        item = modules[module_id]
        print(f"{module_id:>3}  {item.get('name', item.get('script', ''))}: {','.join(available[module_id])}")
    allowed = {option for options in available.values() for option in options}
    while True:
        raw = input("module option: ").strip()
        if not raw or raw.lower() in {"done", "continue"}:
            return
        if "=" not in raw:
            print("Use KEY=VALUE, or press Enter to continue.")
            continue
        owner_and_option = raw.split("=", 1)[0].strip()
        owner, option = owner_and_option.split(".", 1) if "." in owner_and_option else ("", owner_and_option)
        if owner and owner not in available:
            print(f"module {owner!r} is not part of this selection.")
            continue
        if option not in allowed:
            print(f"{option!r} is not declared by the selected modules.")
            continue
        if option in {"advisory_store", "device_data"}:
            value = raw.split("=", 1)[1].strip()
            if not value or "\x00" in value or "\n" in value or "\r" in value:
                print(f"{option!r} requires a local artifact path.")
                continue
            setattr(args, option, value)
            print(f"accepted: {option}=<local-artifact>")
            continue
        try:
            parse_option_assignments([raw])
        except ValueError as exc:
            print(exc)
            continue
        args.module_options.append(raw)
        print(f"accepted: {raw}")


def choose_capability_group(key: str, args: argparse.Namespace) -> str:
    group = CAPABILITY_GROUPS[key]
    allowed = set(group["ids"])
    modules = {str(item["id"]): item for item in load_modules() if int(item["id"]) in allowed}
    print(f"\n{group['label']}")
    print(group["description"])
    for module_id in sorted(modules, key=lambda value: int(value)):
        item = modules[module_id]
        options = ",".join(item.get("options", [])) or "-"
        print(f"{module_id:>3}  {item.get('name', item.get('script', ''))}")
        print(f"     input={item.get('primary_input', '-')}  options={options}")
    print(" A   Run every option in this capability")
    print(" C   Choose module IDs")
    print(" B   Back")
    choice = input("Select: ").strip().lower()
    if choice in {"b", "back", "00"}:
        return ""
    if choice in {"a", "all"}:
        selected = sorted(modules, key=lambda value: int(value))
        choose_module_options(args, selected, modules)
        return ",".join(selected)
    if choice in {"c", "custom"}:
        choice = input("Module IDs separated by commas: ").strip()
    selected = [value.strip() for value in choice.split(",") if value.strip() in modules]
    if not selected:
        raise SystemExit("no valid module IDs selected")
    choose_module_options(args, list(dict.fromkeys(selected)), modules)
    return ",".join(dict.fromkeys(selected))


INTEGRATED_CAPABILITY_GROUPS = {
    "1": ("Web and evidence", ("complete-web-evidence", "range-http-verification")),
    "2": ("Discovery and infrastructure", ("subdomain-infrastructure", "complete-assessment")),
    "3": ("Industrial, devices and SSH", ("industrial-protocol-followup", "device-inventory", "ssh-credential-audit")),
    "4": ("Intelligence and data", ("intelligence-catalog", "advisory-correlation", "knowledge-index", "dictionary-corpus")),
    "5": ("Complete integrated cycle", ("complete-recon",)),
}


def choose_integrated_capability(args: argparse.Namespace) -> bool:
    """Choose the same public integrated-capability flag used by the CLI."""
    while True:
        print("\nIntegrated Ah-Puch capabilities")
        for key, (label, _values) in INTEGRATED_CAPABILITY_GROUPS.items():
            print(f"{key} {label}")
        print("0 Back")
        group = input("Select group: ").strip()
        if group in {"0", "b", "back"}:
            return False
        if group not in INTEGRATED_CAPABILITY_GROUPS:
            print("invalid group")
            continue
        label, values = INTEGRATED_CAPABILITY_GROUPS[group]
        print(f"\n{label}")
        for index, value in enumerate(values, 1):
            print(f"{index} {value}")
        print("0 Back")
        selected = input("Select capability: ").strip()
        if selected in {"0", "b", "back"}:
            continue
        if not selected.isdigit() or not 1 <= int(selected) <= len(values):
            print("invalid capability")
            continue
        args.integrated_capabilities = values[int(selected) - 1]
        args.target = input(TARGET_INPUT_PROMPT).strip()
        args.profile = "deep"
        args.pipeline_mode = "all"
        args.active = True
        args.passive = False
        return True


def choose_wordlist_tier(args: argparse.Namespace) -> None:
    current = "off" if getattr(args, "no_dictionaries", False) else getattr(args, "wordlist_tier", "micro")
    value = input(f"Dictionary tier [micro/short/long/off, default {current}]: ").strip().lower()
    if value in {"off", "none", "no", "disabled", "disable"}:
        args.no_dictionaries = True
        return
    if value in {"micro", "short", "long"}:
        args.no_dictionaries = False
        args.wordlist_tier = value


def choose_custom_options(args: argparse.Namespace) -> None:
    """Interactive equivalent of the common depth and tool flags."""
    print("\nAdvanced configuration (press Enter to keep the current value)")
    fields = (
        ("depth", "Depth", 2), ("max_pages", "Maximum pages", 10),
        ("max_scripts", "Maximum JavaScript files", 20),
        ("max_params", "Maximum parameters", 24), ("max_hosts", "Maximum hosts", 10),
        ("workers", "Workers", 4), ("rate_limit", "Request rate limit", 1),
        ("samples", "Samples", 2),
    )
    for key, label, default in fields:
        current = next((value.split("=", 1)[1] for value in reversed(args.module_options) if value.startswith(f"{key}=")), str(default))
        raw = input(f"{label} [{current}]: ").strip()
        if raw:
            try:
                number = int(raw)
            except ValueError:
                print(f"invalid integer for {key}; keeping {current}")
                continue
            if number < 0:
                print(f"negative value for {key}; keeping {current}")
                continue
            args.module_options.append(f"{key}={number}")
    print("Native tool override (TOOL.KEY=VALUE; blank to finish)")
    while True:
        raw = input("tool option: ").strip()
        if not raw:
            break
        try:
            parse_tool_assignments([raw])
        except ValueError as exc:
            print(exc)
            continue
        args.tool_options.append(raw)


def choose_device_options(args: argparse.Namespace) -> None:
    """Collect the bounded native device controls exposed by the CLI."""
    profile = input(f"Port profile [quick/standard/comprehensive/all/custom, {args.device_port_profile}]: ").strip().lower()
    if profile in {"quick", "standard", "comprehensive", "all", "custom"}:
        args.device_port_profile = profile
    if args.device_port_profile == "custom":
        args.device_custom_ports = input("Custom ports (comma/ranges): ").strip()
    args.device_model = input(f"Model filter [{args.device_model or 'all'}]: ").strip()
    args.device_vendor = input(f"Vendor filter [{args.device_vendor or 'all'}]: ").strip()
    args.device_resume = input("Checkpoint/run to resume [none]: ").strip()
    numeric = (
        ("device_workers", "Workers", 1, 64),
        ("device_connect_timeout", "Connection timeout seconds", 0.1, 120.0),
        ("device_session_timeout", "Session timeout seconds", 1, 86400),
        ("device_retries", "Retries", 0, 10),
        ("range_rate", "Discovery rate", 1, 1_000_000),
        ("device_network_chunks", "Maximum CIDR chunks", 1, 1_000_000),
    )
    for field, label, minimum, maximum in numeric:
        current = getattr(args, field)
        raw = input(f"{label} [{current}]: ").strip()
        if not raw:
            continue
        try:
            value = float(raw) if isinstance(current, float) else int(raw)
        except ValueError:
            print(f"invalid value for {field}; keeping {current}")
            continue
        if not minimum <= value <= maximum:
            print(f"value outside {minimum}-{maximum}; keeping {current}")
            continue
        setattr(args, field, value)
    args.device_run_tags = input("Run tags (comma separated) [none]: ").strip()
    args.device_egress_label = input("Egress metadata label [none]: ").strip()
    export_mode = input(f"Export mode [redacted/evidence, {args.device_export_mode}]: ").strip().lower()
    if export_mode in {"redacted", "evidence"}:
        args.device_export_mode = export_mode
    if input("Disable optional technology enrichment? [y/N]: ").strip().lower() in {"y", "yes"}:
        args.no_device_tech = True


def saved_config_menu(args: argparse.Namespace) -> None:
    print("\nSaved configurations")
    configs = load_saved_configs()
    print("Available: " + (", ".join(sorted(configs)) if configs else "none"))
    print("L  Load configuration")
    print("S  Save current configuration")
    print("B  Back")
    choice = input("Select: ").strip().lower()
    if choice in {"b", "back", ""}:
        return
    if choice in {"l", "load"}:
        name = input("Configuration name: ").strip()
        try:
            values = load_saved_config(name)
            apply_saved_values(args, {key: value for key, value in values.items() if key not in {"module_options", "tool_options"}})
            args.module_options = list(values.get("module_options", []))
            args.tool_options = list(values.get("tool_options", []))
            args.config = name
            print(f"loaded: {name}")
        except (KeyError, ValueError) as exc:
            print(exc)
    elif choice in {"s", "save"}:
        name = input("Configuration name: ").strip()
        try:
            path = save_saved_config(name, config_snapshot(args))
            print(f"saved: {path}")
        except ValueError as exc:
            print(exc)


def choose_preset_menu(args: argparse.Namespace) -> None:
    print("\nPreset runs — depth is selected here; detailed flags remain available on the CLI")
    choices = preset_choices()
    for index, preset in enumerate(choices, start=1):
        mode = "active" if preset.active else "passive"
        print(f"{index:02d} {preset.label:<34} [{mode}] {preset.description}")
    print("B  Back")
    choice = input("Select preset: ").strip().lower()
    if choice in {"b", "back", "00"}:
        return
    try:
        preset = choices[int(choice) - 1]
    except (ValueError, IndexError):
        print("invalid preset selection")
        return
    apply_preset(args, preset.key)
    customize = input("Customize this preset? [y/N]: ").strip().lower()
    if customize in {"y", "yes"}:
        choose_custom_options(args)
    args.target = input(TARGET_INPUT_PROMPT).strip()
    choose_wordlist_tier(args)


def interactive_capability_menu(args: argparse.Namespace) -> None:
    menu = {
        "02": "recon", "03": "dns", "04": "http", "05": "crawling",
        "06": "content", "07": "endpoints", "08": "secrets",
        "09": "network", "10": "web", "11": "threat", "12": "advisories",
    }
    while True:
        print(f"\n{PROGRAM} 2.0 — capability menu")
        print("01 Full analysis")
        for number, key in menu.items():
            print(f"{number} {CAPABILITY_GROUPS[key]['label']}")
        print("13 Camera and video-device surfaces")
        print("14 Analyze saved results and rebuild queues")
        print("15 Dictionary inventory")
        print("16 Tool and orchestration catalog")
        print("17 Preset runs by depth")
        print("18 Saved configurations")
        print("19 Advanced configuration")
        print("20 Help and flags")
        print("21 Integrated Ah-Puch capabilities")
        print("00 Exit")
        choice = input("Select: ").strip().lower()
        if choice in {"0", "00", "exit", "quit"}:
            raise SystemExit(0)
        if choice == "15":
            print_dictionary_info()
            raise SystemExit(0)
        if choice == "16":
            print_tool_info()
            if not catalog_browser(args):
                continue
            args.run = "full"
            args.profile = "full"
            return
        if choice == "17":
            choose_preset_menu(args)
            if args.target:
                return
            continue
        if choice == "18":
            saved_config_menu(args)
            continue
        if choice == "19":
            choose_custom_options(args)
            continue
        if choice == "20":
            print(parser().format_help())
            print(tool_option_help())
            continue
        if choice == "21":
            if choose_integrated_capability(args):
                return
            continue
        if choice == "14":
            print("Saved-run operations: verify, rebuild, view-module, view-runner, grep, inventory, receipts, compare, resume")
            operation = input("Operation [view]: ").strip().lower() or "view"
            path = input("Saved run directory: ").strip()
            if operation == "verify":
                args.verify_run = path
            elif operation == "rebuild":
                args.rebuild_run = path
            elif operation in {"view", "view-module", "view-runner", "grep", "inventory", "receipts", "compare", "resume"}:
                args.saved_run = path
                args.saved_operation = operation
                if operation == "grep":
                    args.saved_query = input("Search text: ").strip()
                elif operation == "compare":
                    args.compare_run = input("Second saved run directory: ").strip()
            else:
                print("invalid saved-run operation")
                continue
            args.target = None
            return
        if choice == "13":
            ids = choose_capability_group("device", args)
            if not ids:
                continue
            args.target = input(TARGET_INPUT_PROMPT).strip()
            choose_device_options(args)
            args.catalog_modules = ids
            args.run = "full"
            args.profile = "full"
            return
        if choice == "01":
            args.target = input(TARGET_INPUT_PROMPT).strip()
            choose_wordlist_tier(args)
            args.run = "full"
            args.profile = "full"
            return
        if choice in menu:
            ids = choose_capability_group(menu[choice], args)
            if not ids:
                continue
            args.target = input(TARGET_INPUT_PROMPT).strip()
            choose_wordlist_tier(args)
            args.run = "full"
            args.profile = "full"
            args.catalog_modules = ids
            return
        print("invalid menu selection")


# The capability menu is the only interactive entry point.
interactive_menu = interactive_capability_menu


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser_instance = parser()
    args = parser_instance.parse_args(raw_argv)
    if args.command_surface or args.command_surface_output:
        try:
            try:
                from .catalog_frontend import load_catalog as load_effective_catalog
                catalog_rows = load_effective_catalog()
            except (ImportError, RuntimeError, ValueError, OSError):
                raw_catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
                catalog_rows = []
                for section, records in raw_catalog.items():
                    for record in records:
                        item = dict(record)
                        item["section"] = section
                        item["execution_kind"] = "family-selector" if section in {"run_all", "special"} else ("native-selector" if item.get("native_capability") else "executable")
                        catalog_rows.append(item)
            try:
                from .command_surface import build_command_surface, write_command_surface
            except ImportError:
                from command_surface import build_command_surface, write_command_surface
            payload = build_command_surface(
                catalog_rows=catalog_rows,
                parser=parser_instance,
                module_command_builder=build_module_command,
                module_option_builder=module_options,
                root=ROOT,
            )
            if args.command_surface_output:
                output = write_command_surface(payload, Path(args.command_surface_output))
                print(json.dumps({"status": "success", "output": str(output), "summary": payload["summary"]}, ensure_ascii=False, sort_keys=True))
            else:
                print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        except (OSError, TypeError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            parser_instance.error(str(exc))
        return 0
    if args.wordlist_timeout < 0:
        parser_instance.error("wordlist timeout must be zero or positive")
    cli_fields = explicit_cli_fields(raw_argv, parser_instance)
    cli_values = {field: getattr(args, field) for field in cli_fields if hasattr(args, field)}
    cli_module_options = list(args.module_options)
    cli_tool_options = list(args.tool_options)
    args.module_options = []
    args.tool_options = []
    if args.follow_up and args.follow_up_rounds == 0:
        args.follow_up_rounds = 1
    saved_values: dict[str, Any] = {}
    if args.config:
        try:
            saved_values = load_saved_config(args.config)
        except (KeyError, ValueError) as exc:
            parser().error(str(exc))
    if args.preset:
        apply_preset(args, args.preset)
    if saved_values:
        saved_without_lists = {key: value for key, value in saved_values.items() if key not in {"module_options", "tool_options"}}
        apply_saved_values(args, saved_without_lists)
        args.module_options.extend(str(value) for value in saved_values.get("module_options", []) if isinstance(value, str))
        args.tool_options.extend(str(value) for value in saved_values.get("tool_options", []) if isinstance(value, str))
    args.module_options.extend(cli_module_options)
    args.tool_options.extend(cli_tool_options)
    for field, value in cli_values.items():
        if field not in {"module_options", "tool_options"} and field in PERSISTED_FIELDS:
            setattr(args, field, value)
    if "passive" in cli_fields and "active" not in cli_fields and args.passive:
        args.active = False
    elif "active" in cli_fields and "passive" not in cli_fields and args.active:
        args.passive = False
    args.module_options = list(dict.fromkeys(args.module_options))
    args.tool_options = list(dict.fromkeys(args.tool_options))
    apply_common_customizations(args)
    args.module_options = list(dict.fromkeys(args.module_options))
    try:
        parse_option_assignments(args.module_options)
        parse_tool_assignments(args.tool_options)
        run_alias = str(getattr(args, "run", "")).strip().casefold()
        if run_alias in INTEGRATED_CAPABILITY_NAMES and not str(getattr(args, "integrated_capabilities", "")).strip():
            args.integrated_capabilities = run_alias
        selected_integrated = selected_capabilities(getattr(args, "integrated_capabilities", ""))
    except ValueError as exc:
        parser().error(str(exc))
    if selected_integrated:
        apply_execution_plan(args)
    if args.preset and args.run in CAPABILITY_GROUPS:
        args.catalog_modules = ",".join(str(value) for value in CAPABILITY_GROUPS[args.run]["ids"])
    limit_errors = validate_namespace_limits(args)
    if limit_errors:
        parser_instance.error("; ".join(limit_errors))
    load_saved_api_env()
    if args.capture_adapter:
        if args.target_opt or args.target or args.targets_file:
            parser_instance.error("--capture-adapter is local-only and cannot be combined with a target")
        try:
            if args.capture_input:
                result = normalize_file(args.capture_adapter, args.capture_input, args.capture_output or None)
            elif args.capture_adapter in REFERENCE_ONLY:
                result = normalize_captured_output(args.capture_adapter, "")
                if args.capture_output:
                    destination = Path(args.capture_output).expanduser()
                    if destination.exists() and destination.is_symlink():
                        raise ValueError("capture output must not be a symlink")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    result = {**result, "output": str(destination)}
            else:
                parser_instance.error("--capture-input is required for this adapter")
        except (OSError, TypeError, ValueError) as exc:
            parser_instance.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.explain_plan:
        print(json.dumps(explain_plan(args), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.list_configs:
        print_saved_config()
        return 0
    if args.delete_config:
        try:
            deleted = delete_saved_config(args.delete_config)
        except ValueError as exc:
            parser().error(str(exc))
        print(f"config {'deleted' if deleted else 'not found'}: {args.delete_config}")
        return 0
    if args.show_config:
        if args.config:
            print_saved_config(args.config)
        else:
            print(json.dumps(config_snapshot(args), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.save_config:
        try:
            saved_path = save_saved_config(args.save_config, config_snapshot(args))
        except ValueError as exc:
            parser().error(str(exc))
        print(f"config saved: {saved_path}")
        if not args.target_opt and not args.target and not args.targets_file:
            return 0
    if args.build_wordlist:
        output = Path(args.build_wordlist).expanduser().resolve()
        rc = build_wordlist(
            Path(args.wordlist_source).expanduser().resolve(),
            output,
            args.wordlist_tier,
            args.wordlist_timeout or None,
        )
        if rc == 0:
            print(f"wordlist built: {output}")
        else:
            print(f"no {args.wordlist_tier} category files found in {args.wordlist_source}", file=sys.stderr)
        return rc
    if args.build_dictionary:
        try:
            result = build_dictionary(
                Path(args.dictionary_source).expanduser(),
                Path(args.build_dictionary).expanduser(),
                args.dictionary_tier,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            parser_instance.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    if args.index_advisory_corpus:
        output = Path(args.advisory_index_output or (Path(args.output).expanduser() / "advisory-index"))
        try:
            result = index_advisory_corpus(Path(args.index_advisory_corpus).expanduser(), output)
        except (OSError, ValueError) as exc:
            parser_instance.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    if args.info:
        print_tool_info()
        return 0
    if args.catalog_browser:
        if not catalog_browser(args):
            return 0
    if getattr(args, "import_device_data", None):
        if not args.device_data_output or not args.device_data_provenance:
            parser_instance.error("--import-device-data requires --device-data-output and --device-data-provenance")
        try:
            artifact = import_device_data(
                [Path(value).expanduser() for value in args.import_device_data],
                Path(args.device_data_output).expanduser(),
                provenance_label=args.device_data_provenance,
            )
        except (OSError, ValueError) as exc:
            parser_instance.error(str(exc))
        print(json.dumps({"status": "imported", "counts": {key: len(artifact[key]) for key in ("fingerprints", "devices", "ports", "paths")}}, sort_keys=True))
        return 0
    if getattr(args, "import_advisories", None):
        if not args.advisory_store:
            parser_instance.error("--import-advisories requires --advisory-store")
        try:
            result = import_advisory_file(Path(args.import_advisories).expanduser(), Path(args.advisory_store).expanduser())
        except (OSError, ValueError) as exc:
            parser_instance.error(str(exc))
        print(json.dumps({"status": "imported", "records": result.record_count, "source_sha256": result.source_sha256}, sort_keys=True))
        return 0
    if args.verify_run:
        return verify_integrity_artifacts(Path(args.verify_run).expanduser().resolve())
    if args.export_run:
        if not args.export_output:
            parser_instance.error("--export-run requires --export-output")
        saved = Path(args.export_run).expanduser().resolve()
        if verify_integrity_artifacts(saved) != 0:
            return 10
        try:
            result = export_saved_run(saved, Path(args.export_output))
        except (OSError, ValueError) as exc:
            parser_instance.error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.saved_run:
        try:
            result = inspect_saved_run(
                Path(args.saved_run), args.saved_operation, query=args.saved_query,
                compare=Path(args.compare_run) if args.compare_run else None,
            )
        except (OSError, ValueError) as exc:
            parser().error(str(exc))
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    for field in ("threads", "max_inputs", "module_timeout", "native_timeout", "follow_up_rounds", "range_rate", "range_host_limit"):
        value = getattr(args, field, None)
        if isinstance(value, bool) or not isinstance(value, int):
            parser().error(f"saved configuration field {field!r} must be an integer")
    if args.threads < 1 or args.max_inputs < 0 or args.module_timeout < 1 or args.native_timeout < 1:
        parser().error("thread, input, and timeout values must be positive")
    if not 1 <= getattr(args, "recon_max_rounds", 2) <= 10:
        parser().error("recon max rounds must be between 1 and 10")
    for field in ("range_max_requests", "ics_max_urls", "ics_max_followups", "ics_timeout"):
        if hasattr(args, field) and (type(getattr(args, field)) is not int or getattr(args, field) < 1):
            parser().error(f"{field.replace('_', ' ')} must be a positive integer")
    if getattr(args, "pipeline_workers", 4) < 1 or getattr(args, "pipeline_workers", 4) > 64 or getattr(args, "pipeline_input_limit", 32) < 1:
        parser().error("pipeline workers must be 1-64 and pipeline input limit must be positive")
    for field in ("device_workers", "device_session_timeout", "device_network_chunks"):
        if hasattr(args, field) and (type(getattr(args, field)) is not int or getattr(args, field) < 1):
            parser().error(f"{field.replace('_', ' ')} must be a positive integer")
    if hasattr(args, "device_retries") and (type(args.device_retries) is not int or not 0 <= args.device_retries <= 10):
        parser().error("device retries must be between 0 and 10")
    if hasattr(args, "device_connect_timeout") and not 0.1 <= float(args.device_connect_timeout) <= 120:
        parser().error("device connect timeout must be between 0.1 and 120 seconds")
    for field in ("device_run_tags", "device_egress_label"):
        value = str(getattr(args, field, ""))
        if value and (len(value) > 256 or not re.fullmatch(r"[A-Za-z0-9._,: -]+", value)):
            parser().error(f"{field.replace('_', ' ')} contains unsupported characters")
    if args.rebuild_run:
        saved = Path(args.rebuild_run).expanduser().resolve()
        manifest = saved / "manifest.json"
        if not manifest.is_file():
            parser().error("--rebuild-run must point to a saved run containing manifest.json")
        try:
            manifest_target = json.loads(manifest.read_text(encoding="utf-8")).get("target", "")
            raw_target = str(manifest_target.get("raw", "") if isinstance(manifest_target, dict) else manifest_target)
            target = clean_target(raw_target)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser().error(f"could not read saved target: {exc}")
        return rebuild_saved_run(saved, target, args.native_timeout)
    if args.target_opt and args.target:
        parser().error("use one target form")
    if args.target_opt:
        args.target = args.target_opt
    if args.targets_file and args.target:
        parser().error("--targets-file cannot be combined with a target")
    if not args.targets_file and not args.target:
        if args.non_interactive:
            parser().error("a target or --targets-file is required")
        interactive_menu(args)
    # Interactive capability selection happens after the initial CLI/config
    # compilation above. Compile that selection through the exact same plan
    # function before targets and run aliases are resolved.
    if str(getattr(args, "integrated_capabilities", "")).strip():
        try:
            apply_execution_plan(args)
        except ValueError as exc:
            parser().error(str(exc))
    if args.targets_file:
        targets = read_raw_targets(Path(args.targets_file).expanduser())
    elif args.target:
        targets = [clean_target(args.target)]
    else:
        parser().error("a target or --targets-file is required")
    if not targets:
        parser().error("the target file contains no valid targets")
    if len(targets) > args.max_targets:
        parser().error(
            f"target file contains {len(targets)} targets; increase --max-targets (hard cap is enforced)"
        )
    if args.camera_only:
        args.run = "cameras"
        args.profile = "full"
        args.no_native = True
        args.no_catalog = True
    run_name = (args.run or args.profile).lower()
    if not args.preset:
        aliases = {"website-crawling": "crawling", "website": "crawling", "web-analysis": "web", "threat-intelligence": "threat", "network-ics": "network", "camera": "cameras", "video": "cameras", "device-surfaces": "cameras"}
        capability = aliases.get(run_name, run_name)
        if capability == "cameras":
            args.run = "cameras"
            args.profile = "full"
            args.camera_only = True
            args.no_native = True
            args.no_catalog = True
            run_name = "cameras"
        elif capability in CAPABILITY_GROUPS:
            args.run = "full"
            args.profile = "full"
            args.catalog_modules = ",".join(str(value) for value in CAPABILITY_GROUPS[capability]["ids"])
            run_name = "full"
        elif capability in INTEGRATED_CAPABILITY_NAMES:
            args.integrated_capabilities = capability
            apply_execution_plan(args)
            run_name = str(args.run)
    if not args.preset:
        if run_name == "core":
            args.no_catalog = True
        elif run_name == "surface":
            args.no_native = True
        elif run_name not in {"full", "baseline", "deep"}:
            args.catalog_modules = args.run
            args.no_native = True
    if args.passive:
        args.active = False
    rc = 0
    for target in targets:
        current = argparse.Namespace(**vars(args))
        if run_name in {"baseline", "full", "deep"}:
            current.profile = run_name
        rc = max(rc, UnifiedRun(target, current).execute())
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
