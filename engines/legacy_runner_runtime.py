#!/usr/bin/env python3
"""Canonical integration for legacy external-runner capabilities.

This is a transition layer, not a second execution engine. It augments the
existing web and advanced-consumer fan-outs with capabilities that were still
registry-only after legacy consolidation, and records explicit canonical
supersession for legacy binaries whose useful behavior is already native.

No runner is installed or downloaded here. Every subprocess is bounded and
receives only origins already admitted by the canonical runtime.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    from .artifact_contract import inspect_artifact, classify
    from .content_fuzz_policy import ffuf_args
    from .dictionary_broker import explicit_info, receipt_info, resolve, resolve_info
    from .runner_registry import inspect_runner, run_bounded
except ImportError:
    from artifact_contract import inspect_artifact, classify
    from content_fuzz_policy import ffuf_args
    from dictionary_broker import explicit_info, receipt_info, resolve, resolve_info
    from runner_registry import inspect_runner, run_bounded


LEGACY_RUNNER_DISPOSITIONS: dict[str, dict[str, str]] = {
    "address_attribution": {
        "status": "VERIFIED_NATIVE",
        "replacement": "recon_core_v2.ScopedCoreRun.discover/socket.getaddrinfo",
        "reason": "native address attribution produces the canonical discovery address artifact",
    },
    "http_client": {
        "status": "VERIFIED_NATIVE",
        "replacement": "http_inventory._probe/_metadata",
        "reason": "native urllib HTTPS/HTTP probing owns redirects, TLS verification and metadata sampling",
    },
    "container_runtime": {
        "status": "VERIFIED_GATED",
        "replacement": "advanced_consumers._zap local-container/native path",
        "reason": "A prepared local container is preferred and the verified native ZAP Automation Framework is the fallback; neither installs during a run",
    },
    "web_proxy_passive": {
        "status": "VERIFIED_GATED",
        "replacement": "advanced_consumers._zap(zap-baseline.py)",
        "reason": "legacy ZAP baseline behavior is dispatched inside a bounded local container or native Automation Framework plan",
    },
    "web_proxy_active": {
        "status": "VERIFIED_GATED",
        "replacement": "advanced_consumers._zap(zap-full-scan.py)",
        "reason": "legacy ZAP active behavior is dispatched inside a bounded local container or native Automation Framework plan when explicitly selected",
    },
    "content_fuzz": {
        "status": "VERIFIED_GATED",
        "replacement": "legacy_runner_runtime web-fanout FFUF adapter",
        "reason": "bounded FFUF content discovery consumes the canonical directory dictionary and admitted origin",
    },
    "crawl_fallback": {
        "status": "VERIFIED_GATED",
        "replacement": "legacy_runner_runtime web-fanout Hakrawler fallback",
        "reason": "Hakrawler is a bounded stdin-driven fallback when canonical crawlers do not complete usefully",
    },
    "web_audit_report": {
        "status": "VERIFIED_GATED",
        "replacement": "legacy_runner_runtime advanced-consumer Arachni adapter",
        "reason": "Arachni is a bounded secondary audit sibling restricted to the admitted canonical origin with a native AFR artifact",
    },
}


def _slug(origin: str) -> str:
    parsed = urlsplit(origin)
    host = (parsed.hostname or "origin").replace(":", "_")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}-{port}-{parsed.scheme}"


def _same_origin_or_subdomain(value: str, origin: str) -> bool:
    try:
        candidate = urlsplit(value)
        root = urlsplit(origin)
    except ValueError:
        return False
    if candidate.scheme not in {"http", "https"} or not candidate.hostname or not root.hostname:
        return False
    candidate_host = candidate.hostname.lower().rstrip(".")
    root_host = root.hostname.lower().rstrip(".")
    return candidate_host == root_host or candidate_host.endswith("." + root_host)


def _origin_scope_pattern(origin: str) -> str:
    """Build a Ruby-regexp include pattern pinned to one exact origin.

    Arachni's include-pattern is a Ruby regular expression. Escaping the exact
    canonical ``scheme://authority/`` prefix prevents the scanner from using a
    discovered link to cross scheme, host or port boundaries.
    """
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Arachni origin must be canonical HTTP(S)")
    host = parsed.hostname.lower().rstrip(".")
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    authority = display_host if port == default_port else f"{display_host}:{port}"
    prefix = f"{parsed.scheme.lower()}://{authority}/"
    # Ruby regex literals are supplied as a plain CLI string; slash therefore
    # needs escaping in addition to the ordinary regexp metacharacters.
    escaped = re.sub(r"([\\.^$|?*+(){}\[\]/])", r"\\\1", prefix)
    return r"\A" + escaped


def _read_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _directory_resolution(tier: str, configured_dictionary: str = "") -> tuple[Path | None, dict[str, Any]]:
    if configured_dictionary:
        info = explicit_info("directory", configured_dictionary, tier=tier)
        return (Path(str(info["path"])) if info.get("available") else None), info
    try:
        selected = resolve("directory", tier=tier)
    except Exception as exc:
        return None, {
            "class": "directory",
            "requested_tier": tier,
            "effective_tier": tier,
            "tier_exact": False,
            "path": "",
            "available": False,
            "source": "error",
            "provenance": f"{type(exc).__name__}: {exc}",
        }
    if not selected:
        return None, {
            "class": "directory",
            "requested_tier": tier,
            "effective_tier": tier,
            "tier_exact": False,
            "path": "",
            "available": False,
            "source": "unavailable",
            "provenance": "canonical-broker",
        }
    selected_path = Path(selected)
    try:
        broker = resolve_info("directory", tier=tier)
        if broker.get("available") and Path(str(broker.get("path", ""))) == selected_path:
            return selected_path, broker
    except Exception:
        pass
    return selected_path, {
        "class": "directory",
        "requested_tier": tier,
        "effective_tier": tier,
        "tier_exact": True,
        "path": str(selected_path),
        "available": selected_path.is_file() and selected_path.stat().st_size > 0,
        "source": "canonical-broker",
        "provenance": "runtime",
    }


def _counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status", "unknown"))
        result[status] = result.get(status, 0) + 1
    return result


def _canonical_crawl_completed(rows: list[dict[str, Any]], origin: str) -> bool:
    """Return true only when a canonical crawler produced a usable terminal.

    Binary presence is not completion: an installed but broken/mismatched
    crawler must not suppress the legacy fallback. ``partial`` is considered
    usable because its artifacts may still contain valid bounded URLs.
    """
    return any(
        str(row.get("origin", "")) == origin
        and str(row.get("runner", "")) in {"crawl-primary", "crawl-secondary"}
        and str(row.get("status", "")) in {"success", "partial"}
        for row in rows
    )


def _ffuf_urls(path: Path, origin: str) -> set[str]:
    if not path.is_file():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return set()
    results = payload.get("results", []) if isinstance(payload, dict) else []
    if not isinstance(results, list):
        return set()
    values: set[str] = set()
    for row in results:
        if not isinstance(row, dict):
            continue
        value = str(row.get("url", "")).strip()
        if value and _same_origin_or_subdomain(value, origin):
            values.add(value)
    return values


def _augment_web_fanout(
    original: Callable[..., dict[str, Any]],
    root: Path,
    origins: list[str],
    *,
    active: bool,
    tier: str,
    timeout: int,
    threads: int,
    max_origins: int = 32,
    tool_options: dict[str, dict[str, Any]] | None = None,
    use_dictionaries: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    result = original(
        root,
        origins,
        active=active,
        tier=tier,
        timeout=timeout,
        threads=threads,
        max_origins=max_origins,
        tool_options=tool_options,
        use_dictionaries=use_dictionaries,
        **kwargs,
    )
    destination = root / "web-fanout"
    ledger = destination / "runs.jsonl"
    rows = _read_rows(ledger)
    crawl_path = destination / "crawl.urls.txt"
    crawl_urls = {
        line.strip()
        for line in crawl_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    } if crawl_path.is_file() else set()

    directory_options = tool_options.get("dirsearch", {}) if isinstance(tool_options, dict) else {}
    configured_dictionary = str(directory_options.get("wordlist", "") or "").strip() if isinstance(directory_options, dict) else ""
    requested_tier = str(directory_options.get("tier", "") or tier).strip().lower() if isinstance(directory_options, dict) else str(tier).strip().lower()
    if use_dictionaries:
        dictionary, dictionary_info = _directory_resolution(requested_tier, configured_dictionary)
    else:
        dictionary_info = {
            "class": "directory",
            "requested_tier": tier,
            "effective_tier": tier,
            "tier_exact": False,
            "path": "",
            "available": False,
            "source": "disabled",
            "provenance": "runtime-disabled",
        }
        dictionary = None
    ffuf = inspect_runner("content_fuzz")
    ffuf_options = tool_options.get("ffuf", {}) if isinstance(tool_options, dict) else {}
    dictionary_skip_reason = "dictionary routing disabled" if not use_dictionaries else "no local/imported directory dictionary available"
    if use_dictionaries and configured_dictionary and not dictionary:
        dictionary_skip_reason = "configured directory dictionary rejected: " + str(dictionary_info.get("reason", "invalid resource"))
    hakrawler = inspect_runner("crawl_fallback")

    for origin in origins[: max(1, max_origins)]:
        origin_dir = destination / _slug(origin)
        origin_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # FFUF complements directory discovery but never invents a new target:
        # FUZZ is appended only to an already admitted canonical origin.
        if not active:
            rows.append({"origin": origin, "runner": "content-fuzz", "status": "skipped", "reason": "active web fan-out disabled"})
        elif not use_dictionaries:
            rows.append({"origin": origin, "runner": "content-fuzz", "status": "skipped", "reason": "dictionary routing disabled"})
        elif not dictionary:
            rows.append({"origin": origin, "runner": "content-fuzz", "status": "skipped", "reason": dictionary_skip_reason})
        elif not ffuf.get("available"):
            rows.append({"origin": origin, "runner": "content-fuzz", "status": "skipped", "reason": "ffuf dependency unavailable or contract mismatch"})
        else:
            report = origin_dir / "content-fuzz.json"
            command = [
                str(ffuf["path"]),
                "-u", origin.rstrip("/") + "/FUZZ",
                "-w", str(dictionary),
                "-of", "json",
                "-o", str(report),
                *ffuf_args(ffuf_options, timeout=timeout, threads=threads),
                "-noninteractive",
                "-s",
            ]
            executed = run_bounded(
                command,
                origin_dir,
                origin_dir / "content-fuzz.console.txt",
                origin_dir / "content-fuzz.stderr.txt",
                min(max(1, int(timeout)), 240),
            )
            artifacts = [inspect_artifact(report, required=True)]
            rows.append({"origin": origin, "runner": "content-fuzz", "status": classify(executed, artifacts), "artifacts": artifacts, **executed})
            crawl_urls.update(_ffuf_urls(report, origin))

        # Hakrawler is a fallback based on observed canonical completion, not
        # merely executable presence. An installed crawler that timed out or
        # failed must not suppress the fallback path.
        canonical_completed = _canonical_crawl_completed(rows, origin)
        if canonical_completed:
            rows.append({"origin": origin, "runner": "crawl-fallback", "status": "skipped", "reason": "canonical crawler completed; fallback not required"})
        elif not active:
            rows.append({"origin": origin, "runner": "crawl-fallback", "status": "skipped", "reason": "active web fan-out disabled"})
        elif not hakrawler.get("available"):
            rows.append({"origin": origin, "runner": "crawl-fallback", "status": "skipped", "reason": "hakrawler dependency unavailable or contract mismatch"})
        else:
            stdin_path = origin_dir / "crawl-fallback-input.txt"
            stdout_path = origin_dir / "crawl-fallback.txt"
            stdin_path.write_text(origin + "\n", encoding="utf-8")
            stdin_path.chmod(0o600)
            command = [
                str(hakrawler["path"]),
                "-d", "2",
                "-t", str(max(1, min(int(threads), 16))),
                "-timeout", str(max(1, min(int(timeout), 30))),
            ]
            executed = run_bounded(
                command,
                origin_dir,
                stdout_path,
                origin_dir / "crawl-fallback.stderr.txt",
                min(max(1, int(timeout)), 120),
                stdin_path=stdin_path,
            )
            artifacts = [inspect_artifact(stdout_path, required=True)]
            rows.append({"origin": origin, "runner": "crawl-fallback", "status": classify(executed, artifacts), "artifacts": artifacts, **executed})
            for value in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines() if stdout_path.is_file() else []:
                clean = value.strip()
                if clean and _same_origin_or_subdomain(clean, origin):
                    crawl_urls.add(clean)

    _write_rows(ledger, rows)
    crawl_path.write_text("\n".join(sorted(crawl_urls)) + ("\n" if crawl_urls else ""), encoding="utf-8")
    crawl_path.chmod(0o600)
    return {
        **result,
        "runs": len(rows),
        "statuses": _counts(rows),
        "crawl_urls": len(crawl_urls),
        "dictionary_enabled": bool(use_dictionaries),
        "dictionary_resolution": receipt_info(dictionary_info),
        "legacy_runner_integrations": ["content_fuzz", "crawl_fallback"],
    }


def _arachni(origin: str, outdir: Path, timeout: int, options: dict[str, Any] | None = None) -> dict[str, Any]:
    runner = inspect_runner("web_audit_report")
    if not runner.get("available"):
        return {"origin": origin, "runner": "web-audit-report", "status": "skipped", "reason": "arachni dependency unavailable or contract mismatch"}
    if not runner.get("path"):
        return {
            "origin": origin,
            "runner": "web-audit-report",
            "status": "skipped",
            "reason": "built-in assessment aggregation executes in the typed pipeline",
        }
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = outdir / "report.afr"
    values = options or {}
    command = [
        str(runner["path"]),
        origin,
        "--scope-include-pattern", _origin_scope_pattern(origin),
        f"--report-save-path={report}",
    ]
    if int(values.get("audit_links", 1)):
        command.append("--audit-links")
    if int(values.get("audit_forms", 1)):
        command.append("--audit-forms")
    if int(values.get("audit_headers", 0)):
        command.append("--audit-headers")
    checks = str(values.get("checks", "") or "").strip()
    if checks:
        command.append(f"--checks={checks}")
    executed = run_bounded(
        command,
        outdir,
        outdir / "console.txt",
        outdir / "stderr.txt",
        min(max(60, int(timeout)), 3600),
    )
    artifacts = [inspect_artifact(report, required=True)]
    return {"origin": origin, "runner": "web-audit-report", "status": classify(executed, artifacts), "artifacts": artifacts, **executed}


def _augment_advanced_consumers(original: Callable[..., dict[str, Any]], root: Path, origins: list[str], **kwargs: Any) -> dict[str, Any]:
    result = original(root, origins, **kwargs)
    selected = kwargs.get("selected_consumers")
    secondary_selected = selected is None or "web-audit-secondary" in set(selected)
    if not secondary_selected:
        return result

    destination = root / "advanced-consumers"
    ledger = destination / "runs.jsonl"
    rows = _read_rows(ledger)
    enabled = bool(kwargs.get("enabled", False))
    timeout = int(kwargs.get("timeout", 3600))
    max_origins = max(1, int(kwargs.get("max_origins", 12)))
    allow_origin = kwargs.get("allow_origin")
    tool_options = kwargs.get("tool_options") or {}
    arachni_options = tool_options.get("arachni", {}) if isinstance(tool_options, dict) else {}
    permitted = [origin for origin in origins if not allow_origin or allow_origin(origin)][:max_origins]

    if not enabled:
        rows.append({"runner": "web-audit-report", "status": "skipped", "reason": "active assessment fan-out disabled", "gate": "active-mode"})
    elif not permitted:
        rows.append({"runner": "web-audit-report", "status": "skipped", "reason": "no target final-200 origins", "gate": "origin-availability"})
    else:
        for origin in permitted:
            try:
                rows.append(_arachni(origin, destination / _slug(origin) / "web-audit-arachni", timeout, arachni_options))
            except Exception as exc:
                rows.append({"origin": origin, "runner": "web-audit-report", "status": "failed", "error": f"{type(exc).__name__}: {exc}"})

    _write_rows(ledger, rows)
    return {
        **result,
        "runs": len(rows),
        "statuses": _counts(rows),
        "legacy_runner_integrations": sorted(set(result.get("legacy_runner_integrations", [])) | {"web_audit_report"}),
    }


def install(v2_module: Any, runtime_module: Any) -> None:
    """Bind the legacy runners into the already canonical family fan-outs."""
    if getattr(v2_module, "_ah_puch_legacy_runner_runtime", False):
        return

    original_web = v2_module.run_all_origins
    original_advanced = runtime_module.run_advanced_consumers

    def web_wrapper(root: Path, origins: list[str], **kwargs: Any) -> dict[str, Any]:
        return _augment_web_fanout(original_web, root, origins, **kwargs)

    web_wrapper._ah_puch_legacy_web_fanout = True  # type: ignore[attr-defined]

    def advanced_wrapper(root: Path, origins: list[str], **kwargs: Any) -> dict[str, Any]:
        return _augment_advanced_consumers(original_advanced, root, origins, **kwargs)

    v2_module.run_all_origins = web_wrapper
    runtime_module.run_advanced_consumers = advanced_wrapper
    stage_runners = dict(getattr(runtime_module, "_PROFILE_STAGE_RUNNERS", {}))
    secondary = set(stage_runners.get("secondary-web-audit", frozenset()))
    secondary.add("web-audit-report")
    stage_runners["secondary-web-audit"] = frozenset(secondary)
    runtime_module._PROFILE_STAGE_RUNNERS = stage_runners
    v2_module._ah_puch_legacy_runner_runtime = True
