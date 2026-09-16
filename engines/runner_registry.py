#!/usr/bin/env python3
"""Registered runner discovery, integration metadata and bounded execution."""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

try:
    from .runtime_hardening import cap_file, current_budget
except ImportError:
    from runtime_hardening import cap_file, current_budget


INVENTORY_PATH = Path(__file__).resolve().parents[1] / "config" / "tool_inventory.json"


def _spec(
    binary: str,
    version: list[str],
    help_args: list[str],
    capability: str,
    required_help: tuple[tuple[str, ...], ...] = (),
    identity: tuple[str, ...] = (),
    *,
    integration: str = "VERIFIED_GATED",
    superseded_by: str = "",
    alternate_binaries: tuple[str, ...] = (),
    identity_source: str = "version",
    probe_timeout: float = 3.0,
    native: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "binary": binary,
        "version": version,
        "help": help_args,
        "capability": capability,
        "required_help": required_help,
        "identity": identity or (binary.casefold(),),
        "integration": integration,
        "superseded_by": superseded_by,
        "alternate_binaries": alternate_binaries,
        "identity_source": identity_source,
        "probe_timeout": probe_timeout,
        "native": native,
    }
    if metadata:
        result.update(metadata)
    return result


RUNNERS: dict[str, dict[str, Any]] = {
    "historical_url_collection": _spec("gau", ["--version"], ["--help"], "historical URL collection", (("--subs",), ("--threads",), ("--o", "--output"))),
    "subdomain_discovery": _spec("subfinder", ["-version", "-duc"], ["-h"], "passive subdomain discovery", (("-d",), ("-o",)), probe_timeout=15.0),
    "address_attribution": _spec(
        "", [], [], "discovered-host address attribution",
        integration="VERIFIED_NATIVE", native=True,
        metadata={"replacement": "recon_core_v2.ScopedCoreRun.discover/socket.getaddrinfo"},
    ),
    "dns_query": _spec("dig", ["-v"], ["-h"], "DNS record queries"),
    "http_probe": _spec("httpx", ["-version"], ["-h"], "batch HTTP probing and metadata", (("-l",), ("-json", "-j"), ("-silent",)), identity_source="version-or-help"),
    "crawl_primary": _spec("katana", ["-version", "-duc"], ["-h"], "bounded endpoint crawling", (("-u",), ("-d",), ("-c",), ("-silent",), ("-o",)), identity_source="version-or-help", probe_timeout=15.0),
    "crawl_secondary": _spec("gospider", ["--version"], ["-h"], "secondary crawl and source collection", (("-s", "-S"), ("-t",), ("-c",), ("-d",), ("--other-source",), ("-o",)), identity_source="version-or-help"),
    "directory_primary": _spec("dirsearch", ["--version"], ["--help"], "primary directory and file enumeration", (("-u", "--url"), ("-w", "--wordlist"), ("--threads",), ("--max-time",), ("-o", "--output"))),
    "network_service": _spec("nmap", ["--version"], ["--help"], "port/service/protocol validation", (("-p", "-p-"), ("-sV",), ("-sU",), ("-oA", "-oG", "-oN", "-oX"))),
    "web_server_check": _spec("nikto", ["-Version"], ["-Help"], "web server checks", (("-h", "-host"), ("-ask",), ("-timeout",), ("-o", "-output"))),
    "web_audit_report": _spec(
        "", [], [], "built-in assessment evidence aggregation",
        integration="VERIFIED_NATIVE", native=True,
    ),
    "parameter_validation": _spec("sqlmap", ["--version"], ["-hh"], "parameterized endpoint validation", (("-u",), ("-m",), ("--batch",), ("--level",), ("--risk",), ("--timeout",), ("--output-dir",)), identity_source="version-or-help", probe_timeout=10.0),
    "range_discovery": _spec("masscan", ["--version"], ["--nmap"], "scalable range service discovery", (("-p",), ("--max-rate",), ("--output-filename", "--output-file", "-oJ", "-oL"))),
    "tls_configuration": _spec("testssl.sh", ["--version"], ["--help"], "TLS configuration checks", (("--warnings",), ("--color",), ("--jsonfile",), ("--htmlfile",)), identity=("testssl",), alternate_binaries=("testssl",), identity_source="version-or-help", probe_timeout=10.0),
    "template_checks": _spec("nuclei", ["-version", "-duc"], ["-h"], "template-based checks", (("-u", "-l"), ("-jsonl",), ("-timeout",), ("-o",)), probe_timeout=15.0),
    "web_audit_secondary": _spec("wapiti", ["--version"], ["--help"], "optional web audit consumer", (("-u",), ("--scope",), ("-m",), ("-f",), ("-o",)), identity_source="version-or-help", probe_timeout=10.0),
    "web_proxy_passive": _spec("podman", ["--version"], ["--help"], "containerized passive web report consumer", identity=("podman", "docker"), alternate_binaries=("docker",)),
    "web_proxy_active": _spec("podman", ["--version"], ["--help"], "containerized explicitly enabled web report consumer", identity=("podman", "docker"), alternate_binaries=("docker",)),
    "container_runtime": _spec("podman", ["--version"], ["--help"], "local containerized report execution", identity=("podman", "docker"), alternate_binaries=("docker",)),
    "http_client": _spec(
        "curl", ["--version"], ["--help", "all"], "HTTP response and path verification", (("--max-time", "-m"),),
        integration="VERIFIED_GATED",
    ),
    "directory_secondary": _spec("gobuster", ["--version"], ["dir", "--help"], "bounded secondary directory enumeration", (("-u", "--url"), ("-w", "--wordlist")), identity_source="version-or-help"),
    "content_fuzz": _spec(
        "ffuf", ["-V"], ["-h"], "bounded content fuzzing",
        (("-u",), ("-w",), ("-o",), ("-of",), ("-t",), ("-timeout",), ("-maxtime",), ("-noninteractive",), ("-s",)),
    ),
    "technology_fingerprint": _spec("whatweb", ["--version"], ["--help"], "HTTP technology fingerprint enrichment", (("--log-json",),)),
    "crawl_fallback": _spec("hakrawler", ["-h"], ["-h"], "optional lightweight crawl fallback", (("-d",), ("-timeout",), ("-t",))),
    "shodan": _spec("shodan", ["version"], ["--help"], "Shodan asset enrichment", identity_source="version-or-help"),
}


def load_tool_inventory(path: Path = INVENTORY_PATH) -> dict[str, Any]:
    """Load and validate the single machine-readable method inventory."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid tool inventory {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError("tool inventory must be a schema-version 1 object")
    blocks = payload.get("blocks")
    tools = payload.get("tools")
    if not isinstance(blocks, list) or len(blocks) != len(set(blocks)):
        raise RuntimeError("tool inventory blocks must be a unique list")
    if not isinstance(tools, list):
        raise RuntimeError("tool inventory tools must be a list")
    ids: set[str] = set()
    runners: set[str] = set()
    for row in tools:
        if not isinstance(row, dict):
            raise RuntimeError("tool inventory rows must be objects")
        required = {"id", "runner_id", "binary", "block", "capability", "inputs", "outputs", "profiles", "contact", "adapter"}
        missing = required - set(row)
        if missing:
            raise RuntimeError(f"tool inventory row is missing: {', '.join(sorted(missing))}")
        tool_id = str(row["id"])
        runner_id = str(row["runner_id"])
        if not tool_id or tool_id in ids or not runner_id or runner_id in runners:
            raise RuntimeError(f"duplicate or empty tool/runner identity: {tool_id}/{runner_id}")
        if row["block"] not in blocks:
            raise RuntimeError(f"unknown inventory block for {tool_id}: {row['block']}")
        ids.add(tool_id)
        runners.add(runner_id)
    return payload


TOOL_INVENTORY = load_tool_inventory()
TOOL_BY_ID = {str(row["id"]): dict(row) for row in TOOL_INVENTORY["tools"]}
TOOL_BY_RUNNER = {str(row["runner_id"]): dict(row) for row in TOOL_INVENTORY["tools"]}
DEFAULT_DOCTOR_TIMEOUT = 120.0
CONTAINER_RUNTIME_RUNNERS = frozenset({
    "container_runtime", "web_proxy_passive", "web_proxy_active",
})
ZAP_RUNTIME_RUNNERS = frozenset({"web_proxy_passive", "web_proxy_active"})
NATIVE_ZAP_RUNNERS = ZAP_RUNTIME_RUNNERS
NATIVE_ZAP_PROBE_TIMEOUT = 45.0
_NATIVE_ZAP_CACHE: dict[str, dict[str, Any]] = {}
_NATIVE_ZAP_CACHE_LOCK = threading.Lock()
_NATIVE_ZAP_PROBE_LOCK = threading.Lock()


def _merge_inventory_runners() -> None:
    """Make every independent inventory method visible to doctor and dispatch."""
    for runner_id, row in TOOL_BY_RUNNER.items():
        metadata = {
            "tool_id": str(row["id"]),
            "block": str(row["block"]),
            "inputs": tuple(str(value) for value in row["inputs"]),
            "outputs": tuple(str(value) for value in row["outputs"]),
            "profiles": tuple(str(value) for value in row["profiles"]),
            "contact": str(row["contact"]),
            "adapter": str(row["adapter"]),
            "credential_env": str(row.get("credential_env", "")),
            "superseded_by": str(row.get("superseded_by", "")),
        }
        if runner_id in RUNNERS:
            RUNNERS[runner_id].update(metadata)
            continue
        binary = str(row["binary"])
        RUNNERS[runner_id] = _spec(
            binary,
            [str(value) for value in row.get("version", ["--version"])],
            [str(value) for value in row.get("help", ["--help"])],
            str(row["capability"]),
            identity=tuple(str(value).casefold() for value in row.get("identity", [binary]) if str(value)),
            alternate_binaries=tuple(str(value) for value in row.get("alternates", [])),
            identity_source="version-or-help",
            integration="VERIFIED_GATED" if binary else "VERIFIED_NATIVE",
            native=not bool(binary),
            metadata=metadata,
        )


_merge_inventory_runners()


INTEGRATION_DISPOSITIONS = frozenset({"VERIFIED_NATIVE", "VERIFIED_GATED"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _capture(command: list[str], timeout: float = 3.0) -> tuple[int, str]:
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                stdout, stderr = process.communicate()
            return 124, (stdout + "\n" + stderr).strip()[:100000]
        return process.returncode, (stdout + "\n" + stderr).strip()[:100000]
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"{type(exc).__name__}: {exc}"


def _probe(command: list[str], timeout: float, *, deadline: float | None = None) -> tuple[int, str]:
    """Retry one timed-out local identity probe after install/first-start load."""
    result = _capture(command, timeout)
    if result[0] == 124:
        retry_timeout = max(10.0, min(timeout * 2.0, 15.0))
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return result
            retry_timeout = min(retry_timeout, remaining)
        return _capture(command, retry_timeout)
    return result


def _help_contract(text: str, groups: tuple[tuple[str, ...], ...]) -> tuple[bool, list[str]]:
    if not groups:
        return True, []
    missing: list[str] = []
    for group in groups:
        if not any(token in text for token in group):
            missing.append("|".join(group))
    return not missing, missing


def _runtime_failure(text: str) -> bool:
    """Reject executable probes that only print loader/runtime failures."""
    lowered = text.casefold()
    if any(
        marker in lowered
        for marker in (
            "traceback (most recent call last):",
            "modulenotfounderror:",
            "importerror:",
            "cannot import name ",
        )
    ):
        return True
    shell_wrapper_failure = (
        (": cd: " in lowered or " exec: " in lowered or ": line " in lowered)
        and (
            "no such file or directory" in lowered
            or "command not found" in lowered
            or "cannot execute" in lowered
        )
    )
    return shell_wrapper_failure


def _container_runtime_contract(
    name: str,
    path: Path,
    timeout: float,
    *,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Prove that a container client can reach its local engine and image.

    A Docker/Podman version string only proves that the client binary exists.
    ZAP cannot run unless that client can reach its daemon/rootless service and
    the installer-prepared image is locally inspectable. These probes are
    local-only and never pull an image or contact a target.
    """
    runtime_rc, runtime_text = _probe([str(path), "info"], timeout, deadline=deadline)
    runtime_ready = runtime_rc == 0 and not _runtime_failure(runtime_text)
    result: dict[str, Any] = {
        "runtime_ready": runtime_ready,
        "runtime_rc": runtime_rc,
        "runtime_sample": runtime_text[:3000],
    }
    if not runtime_ready:
        lowered = runtime_text.casefold()
        result["runtime_reason"] = (
            "container-runtime-permission-denied"
            if "permission denied" in lowered or "access denied" in lowered
            else "container-runtime-unavailable"
        )
        return result
    if name not in ZAP_RUNTIME_RUNNERS:
        return result

    image = os.environ.get("AH_PUCH_ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable").strip()
    image_rc, image_text = _probe(
        [str(path), "image", "inspect", "--format", "{{.Id}}", image],
        timeout,
        deadline=deadline,
    )
    image_id = image_text.splitlines()[0].strip() if image_rc == 0 and image_text.strip() else ""
    result.update({
        "image_reference": image,
        "image_ready": bool(image_id),
        "image_rc": image_rc,
        "image_id": image_id,
        "image_sample": image_text[:3000],
    })
    if not image_id:
        result["runtime_reason"] = "container-image-unavailable"
    return result


def _which_all(binary: str) -> list[str]:
    """Return every known executable candidate for one binary name, in order.

    Installer-managed paths are preferred, then the operator's PATH, followed
    by standard per-user Go/Cargo/local-bin locations.  The fallback locations
    are only candidate sources: ``inspect_runner`` still proves identity,
    version and help flags before any path can be admitted for dispatch.
    """
    if not binary:
        return []
    if os.sep in binary:
        path = Path(binary)
        return [str(path)] if path.is_file() and os.access(path, os.X_OK) else []
    search_dirs: list[str] = []
    for raw in (
        os.environ.get("AH_PUCH_BIN_DIR", ""),
        os.environ.get("AH_PUCH_RUNNER_PATHS", ""),
        os.environ.get("PATH", ""),
    ):
        search_dirs.extend(item for item in raw.split(os.pathsep) if item)
    user_home = Path.home()
    search_dirs.extend(
        str(path)
        for path in (user_home / "go" / "bin", user_home / ".local" / "bin", user_home / ".cargo" / "bin")
    )
    found: list[str] = []
    seen: set[str] = set()
    for directory in search_dirs:
        candidate = Path(directory) / binary
        try:
            resolved = str(candidate.resolve())
        except OSError:
            continue
        if resolved in seen or not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        seen.add(resolved)
        found.append(str(candidate))
    return found


def _native_zap_candidates() -> list[str]:
    """Return installed native ZAP launchers in deterministic preference order."""
    found: list[str] = []
    for binary in ("zaproxy", "zap.sh"):
        for candidate in _which_all(binary):
            if candidate not in found:
                found.append(candidate)
    return found


def _native_zap_contract(path: str, *, deadline: float | None = None) -> dict[str, Any]:
    """Prove the native ZAP CLI and Automation Framework are usable locally.

    The probe starts ZAP only with local help/version flags. It never supplies
    a target URL, never installs add-ons, and never contacts a target.
    """
    with _NATIVE_ZAP_CACHE_LOCK:
        cached = _NATIVE_ZAP_CACHE.get(path)
    if cached is not None:
        return dict(cached)

    # A first native ZAP start can take tens of seconds on a cold JVM. The
    # doctor probes passive and active ZAP in parallel, so serialize the cold
    # probe and re-check the cache after waiting. This avoids two JVM starts
    # racing over the same first-run profile and lets the second runner reuse
    # the exact proof within the global doctor deadline.
    if deadline is None:
        acquired = _NATIVE_ZAP_PROBE_LOCK.acquire()
    else:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"native_zap_ready": False, "native_zap_reason": "native-zap-probe-deadline"}
        acquired = _NATIVE_ZAP_PROBE_LOCK.acquire(timeout=remaining)
    if not acquired:
        return {"native_zap_ready": False, "native_zap_reason": "native-zap-probe-deadline"}
    try:
        with _NATIVE_ZAP_CACHE_LOCK:
            cached = _NATIVE_ZAP_CACHE.get(path)
        if cached is not None:
            return dict(cached)

        probe_timeout = NATIVE_ZAP_PROBE_TIMEOUT
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"native_zap_ready": False, "native_zap_reason": "native-zap-probe-deadline"}
            probe_timeout = min(probe_timeout, max(1.0, remaining - 1.0))
        launcher = Path(path)
        version_rc, version_text = _probe(
            [str(launcher), "-Xmx512m", "-version"],
            probe_timeout,
            deadline=deadline,
        )
        version_match = next(
            (line.strip() for line in version_text.splitlines() if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][^\s]+)?", line.strip())),
            "",
        )
        version_ok = version_rc in {0, 1, 2} and bool(version_match) and not _runtime_failure(version_text)
        help_rc, help_text = _probe(
            [str(launcher), "-Xmx512m", "-cmd", "-silent", "-h"],
            probe_timeout,
            deadline=deadline,
        )
        required = ("-cmd", "-quickurl", "-quickout", "-autorun")
        missing = [token for token in required if token not in help_text]
        help_ok = help_rc in {0, 1, 2} and bool(help_text.strip()) and not missing and not _runtime_failure(help_text)
        result = {
            "native_zap_ready": version_ok and help_ok,
            "native_zap_path": str(launcher.resolve()),
            "native_zap_version": version_match,
            "native_zap_version_rc": version_rc,
            "native_zap_help_rc": help_rc,
            "native_zap_help_sample": help_text[:3000],
            "native_zap_missing_contract": missing,
            "native_zap_reason": "native-zap-contract-verified" if version_ok and help_ok else "native-zap-contract-mismatch",
        }
        if result["native_zap_ready"]:
            with _NATIVE_ZAP_CACHE_LOCK:
                _NATIVE_ZAP_CACHE[path] = dict(result)
        return result
    finally:
        _NATIVE_ZAP_PROBE_LOCK.release()


def _native_zap_fallback(
    name: str,
    row: dict[str, Any],
    *,
    deadline: float | None = None,
) -> dict[str, Any] | None:
    """Build a runner row for native ZAP when no container backend is admitted."""
    if name not in NATIVE_ZAP_RUNNERS:
        return None
    for candidate_path in _native_zap_candidates():
        if deadline is None:
            proof = _native_zap_contract(candidate_path)
        else:
            proof = _native_zap_contract(candidate_path, deadline=deadline)
        if not proof.get("native_zap_ready"):
            continue
        native_path = Path(str(proof["native_zap_path"]))
        candidate = dict(row)
        candidate.update({
            "binary": "zaproxy",
            "path": str(native_path),
            "sha256": _sha256(native_path),
            "version": str(proof.get("native_zap_version", "")),
            "version_rc": proof.get("native_zap_version_rc"),
            "version_contract_ok": True,
            "help_rc": proof.get("native_zap_help_rc"),
            "help_sample": str(proof.get("native_zap_help_sample", "")),
            "help_contract_ok": True,
            "available": True,
            "contract_ok": True,
            "disposition": "REACHABLE",
            "reason": "native-zap-fallback",
            "runtime_ready": True,
            "runtime_rc": 0,
            "runtime_kind": "native",
            "native_zap_ready": True,
            "native_zap_path": str(native_path),
            "native_zap_version": str(proof.get("native_zap_version", "")),
            "native_zap_reason": str(proof.get("native_zap_reason", "")),
            "image_ready": False,
            "image_reference": "",
            "image_id": "",
        })
        return candidate
    return None


def _initial_runner_row(name: str) -> dict[str, Any]:
    spec = RUNNERS[name]
    integration = str(spec.get("integration", ""))
    replacement = str(spec.get("superseded_by", ""))
    return {
        "id": name,
        "binary": spec["binary"],
        "capability": spec["capability"],
        "available": False,
        "contract_ok": False,
        "disposition": "BLOCKED_EXTERNAL",
        "integration_disposition": integration,
        "replacement": replacement,
        "reason": "executable-not-found",
        "tool_id": str(spec.get("tool_id", name)),
        "block": str(spec.get("block", "support")),
        "inputs": list(spec.get("inputs", ())),
        "outputs": list(spec.get("outputs", ())),
        "profiles": list(spec.get("profiles", ())),
        "contact": str(spec.get("contact", "none")),
        "adapter": str(spec.get("adapter", "support")),
    }


def _doctor_timeout_row(name: str) -> dict[str, Any]:
    row = _initial_runner_row(name)
    spec = RUNNERS[name]
    if spec.get("native"):
        row.update({
            "available": True,
            "contract_ok": True,
            "disposition": "REACHABLE",
            "reason": "native-component",
            "version": "built-in",
            "version_contract_ok": True,
            "help_contract_ok": True,
        })
        return row
    replacement = str(spec.get("superseded_by", ""))
    if replacement:
        row.update({
            "disposition": "SUPERSEDED",
            "reason": "canonical-native-supersession",
        })
        return row
    row["reason"] = "doctor-global-timeout"
    return row


def inspect_runner(name: str, *, deadline: float | None = None) -> dict[str, Any]:
    spec = RUNNERS[name]
    replacement = str(spec.get("superseded_by", ""))
    row = _initial_runner_row(name)

    if spec.get("native"):
        row.update({
            "available": True,
            "contract_ok": True,
            "disposition": "REACHABLE",
            "reason": "native-component",
            "version": "built-in",
            "version_contract_ok": True,
            "help_contract_ok": True,
        })
        return row

    # A superseded executable is intentionally not part of production dispatch.
    # Its capability remains present through a named canonical native component.
    if replacement:
        row.update({
            "disposition": "SUPERSEDED",
            "reason": "canonical-native-supersession",
        })
        return row

    if deadline is not None and time.monotonic() >= deadline:
        return _doctor_timeout_row(name)

    found_candidates: list[str] = []
    for binary in (spec["binary"], *tuple(spec.get("alternate_binaries", ()))):
        for found in _which_all(binary):
            if found not in found_candidates:
                found_candidates.append(found)
    if not found_candidates:
        native_fallback = _native_zap_fallback(name, row, deadline=deadline)
        if native_fallback:
            return native_fallback
        return row
    blocked: list[dict[str, Any]] = []
    for found in found_candidates:
        candidate = dict(row)
        path = Path(found).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            candidate.update({"path": str(path), "disposition": "BLOCKED_CONTRACT", "reason": "not-an-executable-file"})
            blocked.append(candidate)
            continue
        probe_timeout = max(1.0, min(float(spec.get("probe_timeout", 3.0)), 15.0))
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _doctor_timeout_row(name)
            probe_timeout = min(probe_timeout, remaining)
        version_rc, version = _probe([str(path), *spec["version"]], probe_timeout, deadline=deadline)
        if deadline is not None and time.monotonic() >= deadline:
            return _doctor_timeout_row(name)
        help_rc, help_text = _probe([str(path), *spec["help"]], probe_timeout, deadline=deadline)
        help_flags_ok, missing_help = _help_contract(help_text, tuple(spec.get("required_help", ())))
        identity_tokens = tuple(str(value).casefold() for value in spec.get("identity", ()))
        identity_text = version.casefold()
        if spec.get("identity_source") == "version-or-help":
            identity_text += "\n" + help_text.casefold()
        identity_ok = any(token in identity_text for token in identity_tokens)
        version_runtime_ok = not _runtime_failure(version)
        help_runtime_ok = not _runtime_failure(help_text)
        version_contract_ok = version_rc in {0, 1, 2} and bool(version) and identity_ok and version_runtime_ok
        help_contract_ok = help_rc in {0, 1, 2} and bool(help_text) and help_flags_ok and help_runtime_ok
        contract_ok = version_contract_ok and help_contract_ok
        reasons: list[str] = []
        if not version_contract_ok:
            reasons.append("version-contract-mismatch")
        if not version_runtime_ok:
            reasons.append("version-command-runtime-failure")
        if help_rc not in {0, 1, 2} or not help_text:
            reasons.append("help-command-failed")
        if not help_runtime_ok:
            reasons.append("help-command-runtime-failure")
        if missing_help:
            reasons.append("missing-required-help-flags:" + ",".join(missing_help))
        candidate.update(
            {
                "available": contract_ok,
                "contract_ok": contract_ok,
                "disposition": "REACHABLE" if contract_ok else "BLOCKED_CONTRACT",
                "reason": "contract-verified" if contract_ok else ";".join(reasons),
                "path": str(path),
                "sha256": _sha256(path),
                "version_rc": version_rc,
                "version": version.splitlines()[0] if version else "",
                "version_contract_ok": version_contract_ok,
                "help_rc": help_rc,
                "help_sample": help_text[:3000],
                "help_contract_ok": help_contract_ok,
                "missing_help_contract": missing_help,
                "candidates_checked": len(found_candidates),
            }
        )
        if contract_ok and name in CONTAINER_RUNTIME_RUNNERS:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return _doctor_timeout_row(name)
                probe_timeout = min(probe_timeout, remaining)
            runtime = _container_runtime_contract(
                name,
                path,
                probe_timeout,
                deadline=deadline,
            )
            runtime_ok = bool(runtime.get("runtime_ready")) and (
                name not in ZAP_RUNTIME_RUNNERS or bool(runtime.get("image_ready"))
            )
            candidate.update(runtime)
            candidate.update({
                "available": runtime_ok,
                "contract_ok": runtime_ok,
                "disposition": "REACHABLE" if runtime_ok else "BLOCKED_EXTERNAL",
                "reason": "contract-verified" if runtime_ok else str(runtime.get("runtime_reason", "container-runtime-unavailable")),
            })
            contract_ok = runtime_ok
        if contract_ok:
            return candidate
        blocked.append(candidate)
    native_fallback = _native_zap_fallback(name, row, deadline=deadline)
    if native_fallback:
        return native_fallback
    return blocked[0]


@lru_cache(maxsize=256)
def _cached_admitted_path(name: str, path_env: str, which_resolver: Any, inspector: Any) -> str:
    """Cache one process-local admission decision for a stable resolver environment."""
    del path_env, which_resolver
    row = inspector(name)
    if (
        row.get("available") is True
        and row.get("contract_ok") is True
        and row.get("disposition") == "REACHABLE"
    ):
        return str(row.get("path", ""))
    return ""


def admitted_path(name: str) -> str:
    """Return an executable only after its exact identity/help contract passes."""
    search_fingerprint = os.pathsep.join(
        (
            os.environ.get("PATH", ""),
            os.environ.get("HOME", ""),
            os.environ.get("AH_PUCH_BIN_DIR", ""),
            os.environ.get("AH_PUCH_RUNNER_PATHS", ""),
        )
    )
    return _cached_admitted_path(
        name,
        search_fingerprint,
        shutil.which,
        inspect_runner,
    )


def clear_admitted_cache() -> None:
    """Discard process-local admissions after an intentional environment change."""
    _cached_admitted_path.cache_clear()
    with _NATIVE_ZAP_CACHE_LOCK:
        _NATIVE_ZAP_CACHE.clear()


def snapshot(
    root: Path,
    *,
    workers: int = 4,
    timeout: float | None = DEFAULT_DOCTOR_TIMEOUT,
    progress: Callable[[str, dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    """Probe the registry concurrently without changing its deterministic order.

    Runner identity probes are independent and can be slow on first start. A
    bounded worker pool and global deadline keep doctor/install readiness
    practical while the returned JSON/TSV remains in the declared RUNNERS
    order. Unfinished probes receive an honest BLOCKED_EXTERNAL row.
    """
    names = list(RUNNERS)
    worker_count = max(1, min(int(workers), len(names) or 1))
    if timeout is not None and float(timeout) <= 0:
        raise ValueError("runner doctor timeout must be positive or None")
    deadline = None if timeout is None else time.monotonic() + float(timeout)
    by_name: dict[str, dict[str, Any]] = {}
    if worker_count == 1:
        for name in names:
            if deadline is not None and time.monotonic() >= deadline:
                row = _doctor_timeout_row(name)
            else:
                row = inspect_runner(name, deadline=deadline)
            by_name[name] = row
            if progress:
                progress(name, row)
    else:
        pool = ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="ah-puch-doctor")
        futures = {pool.submit(inspect_runner, name, deadline=deadline): name for name in names}
        pending = set(futures)
        try:
            while pending:
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                if remaining == 0.0:
                    break
                done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
                if not done:
                    break
                for future in done:
                    name = futures[future]
                    try:
                        row = future.result()
                    except Exception as exc:  # pragma: no cover - defensive local-probe boundary
                        row = _initial_runner_row(name)
                        row.update({
                            "disposition": "BLOCKED_CONTRACT",
                            "reason": f"doctor-probe-error:{type(exc).__name__}",
                        })
                    by_name[name] = row
                    if progress:
                        progress(name, row)
        finally:
            for future in pending:
                future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
        for name in names:
            if name in by_name:
                continue
            row = _doctor_timeout_row(name)
            by_name[name] = row
            if progress:
                progress(name, row)
    rows = [by_name[name] for name in names]
    destination = root / "runner-registry"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    json_path = destination / "runners.json"
    json_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    json_path.chmod(0o600)
    columns = (
        "id", "binary", "available", "contract_ok", "disposition", "integration_disposition",
        "replacement", "reason", "path", "sha256", "version", "version_rc",
        "version_contract_ok", "help_rc", "help_contract_ok", "capability", "missing_help_contract",
        "runtime_ready", "runtime_rc", "image_ready", "image_rc", "image_reference", "image_id",
        "runtime_kind", "native_zap_ready", "native_zap_path", "native_zap_version",
        "tool_id", "block", "inputs", "outputs", "profiles", "contact", "adapter",
    )
    tsv = ["\t".join(columns)]
    for row in rows:
        tsv.append("\t".join(str(row.get(key, "")) for key in columns))
    tsv_path = destination / "runners.tsv"
    tsv_path.write_text("\n".join(tsv) + "\n", encoding="utf-8")
    tsv_path.chmod(0o600)
    return rows


def planned_snapshot(root: Path) -> list[dict[str, Any]]:
    """Write a dry-run registry projection without starting any binary."""
    rows: list[dict[str, Any]] = []
    for name, spec in RUNNERS.items():
        rows.append({
            "id": name,
            "tool_id": str(spec.get("tool_id", name)),
            "binary": str(spec.get("binary", "")),
            "capability": str(spec.get("capability", "")),
            "available": False,
            "contract_ok": False,
            "disposition": "PLANNED",
            "integration_disposition": str(spec.get("integration", "")),
            "replacement": str(spec.get("superseded_by", "")),
            "reason": "dry-run: executable contract probe deferred",
            "block": str(spec.get("block", "support")),
            "inputs": list(spec.get("inputs", ())),
            "outputs": list(spec.get("outputs", ())),
            "profiles": list(spec.get("profiles", ())),
            "contact": str(spec.get("contact", "none")),
            "adapter": str(spec.get("adapter", "support")),
        })
    destination = Path(root) / "runner-registry"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    (destination / "runners.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (destination / "runners.json").chmod(0o600)
    columns = ("id", "binary", "available", "contract_ok", "disposition", "integration_disposition", "replacement", "reason", "tool_id", "block", "adapter")
    (destination / "runners.tsv").write_text("\t".join(columns) + "\n" + "\n".join("\t".join(str(row.get(key, "")) for key in columns) for row in rows) + "\n", encoding="utf-8")
    (destination / "runners.tsv").chmod(0o600)
    return rows


def inventory_snapshot(root: Path) -> list[dict[str, Any]]:
    """Write the registered runner inventory for a target run without probing binaries."""
    rows: list[dict[str, Any]] = []
    for name, spec in RUNNERS.items():
        rows.append({
            "id": name,
            "tool_id": str(spec.get("tool_id", name)),
            "binary": str(spec.get("binary", "")),
            "capability": str(spec.get("capability", "")),
            "available": None,
            "contract_ok": None,
            "disposition": "RECORDED",
            "integration_disposition": str(spec.get("integration", "")),
            "replacement": str(spec.get("superseded_by", "")),
            "reason": "target run: executable contract probe deferred; run --runner-doctor for full validation",
            "block": str(spec.get("block", "support")),
            "inputs": list(spec.get("inputs", ())),
            "outputs": list(spec.get("outputs", ())),
            "profiles": list(spec.get("profiles", ())),
            "contact": str(spec.get("contact", "none")),
            "adapter": str(spec.get("adapter", "support")),
        })
    destination = Path(root) / "runner-registry"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    (destination / "runners.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (destination / "runners.json").chmod(0o600)
    columns = (
        "id", "binary", "available", "contract_ok", "disposition",
        "integration_disposition", "replacement", "reason", "tool_id",
        "block", "inputs", "outputs", "profiles", "contact", "adapter",
    )
    (destination / "runners.tsv").write_text(
        "\t".join(columns) + "\n" +
        "\n".join("\t".join(str(row.get(key, "")) for key in columns) for row in rows) + "\n",
        encoding="utf-8",
    )
    (destination / "runners.tsv").chmod(0o600)
    return rows


def run_bounded(
    command: list[str],
    cwd: Path,
    stdout: Path,
    stderr: Path,
    timeout: int,
    *,
    stdin_path: Path | None = None,
) -> dict[str, Any]:
    """Run one external process with a bounded process-group lifecycle.

    ``stdin_path`` supports tools whose normal CLI contract consumes a target
    list from standard input. It is a regular-file-only input and preserves the
    same timeout/TERM/KILL behavior as every other registered runner.
    """
    stdout.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    timed_out = False
    input_handle = None
    budget = current_budget()
    if budget is not None and not budget.reserve_execution("registered-runner"):
        stderr.parent.mkdir(parents=True, exist_ok=True)
        stderr.write_text("budget-exhausted: max_executions\n", encoding="utf-8")
        stderr.chmod(0o600)
        return {
            "command": command,
            "exit_code": 125,
            "timed_out": False,
            "duration": 0.0,
            "stdout": str(stdout),
            "stderr": str(stderr),
            "stdin": str(stdin_path) if stdin_path is not None else "",
            "budget_exhausted": True,
        }
    try:
        if stdin_path is not None:
            candidate = Path(stdin_path)
            if not candidate.is_file() or candidate.is_symlink():
                raise OSError("stdin_path must be a regular non-symlink file")
            input_handle = candidate.open("r", encoding="utf-8", errors="replace")
        with stdout.open("w", encoding="utf-8", errors="replace") as out, stderr.open("w", encoding="utf-8", errors="replace") as err:
            process = subprocess.Popen(
                command,
                cwd=str(cwd),
                stdin=input_handle,
                stdout=out,
                stderr=err,
                text=True,
                start_new_session=True,
            )
            try:
                rc = process.wait(timeout=max(1, timeout))
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    process.wait()
                rc = 124
    except OSError as exc:
        stderr.parent.mkdir(parents=True, exist_ok=True)
        stderr.write_text(f"process-start-error: {exc}\n", encoding="utf-8")
        rc = 127
        timed_out = False
    finally:
        if input_handle is not None:
            input_handle.close()
    try:
        if budget is not None:
            cap_file(stdout, budget.limits["max_output_bytes"])
            cap_file(stderr, budget.limits["max_output_bytes"])
        stdout.chmod(0o600)
        stderr.chmod(0o600)
    except OSError:
        pass
    return {
        "command": command,
        "exit_code": rc,
        "timed_out": timed_out,
        "duration": round(time.monotonic() - started, 3),
        "stdout": str(stdout),
        "stderr": str(stderr),
        "stdin": str(stdin_path) if stdin_path is not None else "",
        "budget_exhausted": bool(budget.exhausted) if budget is not None else False,
    }
