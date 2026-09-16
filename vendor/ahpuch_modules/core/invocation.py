"""Single argv contract shared by the unified and legacy module runners."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ARGPARSE_SCRIPTS = {"open_ports.py"}
ARGPARSE_THREADS_SCRIPTS = {
    "ssl_expiry.py",
    "certificate_authority_recon.py",
    "ssl_labs_report.py",
    "ssl_pinning_check.py",
}
ARGPARSE_TLS_SCRIPTS = {"tls_handshake.py", "tls_security_config.py"}
ARGPARSE_TARGET_ONLY_SCRIPTS = {"subdomain_takeover.py", "traceroute.py"}
ARGPARSE_TIMEOUT_SCRIPTS = {"jwt_token_analyzer.py"}
JSON_ONLY_SCRIPTS = {"dns_caa_checker.py", "dual_stack_diff.py", "ip_reputation_trending.py", "privacy_gdpr.py"}
TARGET_ONLY_SCRIPTS: set[str] = set()
UDP_SERVICE_SAMPLER = "udp_service_sampler.py"


def _enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def build_module_command(script: str, target: str, threads: int, options: dict[str, Any] | None = None, timeout: int = 60) -> list[str]:
    """Build the exact argv accepted by a catalog module's real parser."""
    options = options or {}
    module_name = Path(script).stem
    prefix = [sys.executable, "-m", f"ahpuch_modules.modules.{module_name}", target]
    if script in ARGPARSE_SCRIPTS:
        command = prefix + [
            "-p", str(options.get("ports", "1-1024")),
            "-t", str(options.get("threads", threads)),
            "-T", str(min(int(options.get("timeout", timeout)), 10)),
        ]
        if _enabled(options.get("no_fallback", False)):
            command.append("--no-fallback")
        return command
    if script == UDP_SERVICE_SAMPLER:
        return prefix + [
            str(options.get("threads", threads)),
            "--ports", str(options.get("ports", "53,123,161,500,514,69")),
            "--retries", str(max(1, int(options.get("retries", 1)))),
            "--max-hosts", str(max(1, int(options.get("max_hosts", 256)))),
        ]
    if script in ARGPARSE_THREADS_SCRIPTS:
        command = prefix + ["--threads", str(options.get("threads", threads))]
        if script == "ssl_labs_report.py" and _enabled(options.get("no_cache", False)):
            command.append("--no-cache")
        return command
    if script in ARGPARSE_TLS_SCRIPTS:
        command = prefix + ["--threads", str(options.get("threads", threads)), "--port", str(options.get("port", 443))]
        if script == "tls_security_config.py":
            command += ["--timeout", str(options.get("timeout", timeout))]
        return command
    if script in ARGPARSE_TARGET_ONLY_SCRIPTS:
        return prefix
    if script in ARGPARSE_TIMEOUT_SCRIPTS:
        return prefix + ["-t", str(min(int(options.get("timeout", timeout)), 10))]
    if script in JSON_ONLY_SCRIPTS:
        return prefix + [json.dumps(options, ensure_ascii=False, sort_keys=True)]
    if script in TARGET_ONLY_SCRIPTS:
        return prefix
    return prefix + [str(options.get("threads", threads)), json.dumps(options, ensure_ascii=False, sort_keys=True)]
