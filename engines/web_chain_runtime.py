#!/usr/bin/env python3
"""Canonical URL/content/assessment handoff layer for Ah-Puch Phase 5.

This module constrains the existing production adapters so consumer inputs come
from the normalized artifact bus and producer outputs are projected only with
their terminal status. Its only direct network handoff is the bounded canonical
HTTP re-observation performed after crawler and content discoveries. Legacy
text indexes remain temporary compatibility projections of promoted bus
records, never independent evidence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin

try:
    from . import advanced_consumers, artifact_bus, http_reverification, runner_v2
except ImportError:
    import advanced_consumers
    import artifact_bus
    import http_reverification
    import runner_v2

_COMPLETED = frozenset({"success", "partial"})
_MAX_ARTIFACT_BYTES = 20_000_000
_TEXT_RESULT_SUFFIXES = frozenset({".txt", ".json", ".jsonl", ".csv", ".html", ".log"})
_RELATIVE_PATH_RE = re.compile(r"(?<!\S)(/(?!/)[^\s\"'<>]*)")
_ORIGINAL_WEB_FANOUT = runner_v2.run_all_origins
_INSTALLED = False


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _safe_artifact(root: Path, value: object, subtree: str) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        base = (root / subtree).resolve(strict=True)
        if not resolved.is_relative_to(base) or not resolved.is_file():
            return None
        if resolved.stat().st_size > _MAX_ARTIFACT_BYTES:
            return None
    except OSError:
        return None
    return resolved


def _safe_result_files(root: Path, result_dir: object) -> list[Path]:
    raw = str(result_dir or "").strip()
    if not raw:
        return []
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        if candidate.is_symlink():
            return []
        resolved = candidate.resolve(strict=True)
        base = (root / "ahpuch_modules").resolve(strict=True)
        if not resolved.is_relative_to(base) or not resolved.is_dir():
            return []
    except OSError:
        return []
    result: list[Path] = []
    for path in sorted(resolved.rglob("*")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() not in _TEXT_RESULT_SUFFIXES:
                continue
            if path.stat().st_size > _MAX_ARTIFACT_BYTES:
                continue
        except OSError:
            continue
        result.append(path)
    return result


def _artifact_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _urls_from_text(text: str) -> list[str]:
    values = {
        value.rstrip(".,;:)]}")
        for value in artifact_bus.URL_RE.findall(text)
        if artifact_bus.canonical_url(value.rstrip(".,;:)]}"))
    }
    return sorted(values)


def _urls_from_artifact(path: Path) -> list[str]:
    return _urls_from_text(_artifact_text(path))


def _directory_urls_from_artifact(path: Path, origin: str) -> list[str]:
    text = _artifact_text(path)
    values = set(_urls_from_text(text))
    base = artifact_bus.canonical_origin(origin)
    if not base:
        return sorted(values)
    for match in _RELATIVE_PATH_RE.finditer(text):
        relative = match.group(1).rstrip(".,;:)]}")
        if not relative or any(character in relative for character in ("\\", "\x00")):
            continue
        candidate = urljoin(base, relative)
        if artifact_bus.canonical_url(candidate):
            values.add(candidate)
    return sorted(values)


def _artifact_paths(root: Path, row: dict[str, Any], subtree: str) -> list[Path]:
    artifacts = row.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    result: list[Path] = []
    for artifact in artifacts:
        value = artifact.get("path") if isinstance(artifact, dict) else artifact
        path = _safe_artifact(root, value, subtree)
        if path is not None:
            result.append(path)
    return sorted(set(result))


def _promotable_observation(observation: object, producer_prefix: str = "") -> bool:
    if not isinstance(observation, dict):
        return False
    if producer_prefix and not str(observation.get("producer", "")).startswith(producer_prefix):
        return False
    return bool(
        observation.get("within_target")
        and observation.get("observed")
        and str(observation.get("status", "")) in artifact_bus.PROMOTABLE_STATUSES
    )


def ingest_web_fanout_status_aware(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow: Callable[[str], bool],
) -> int:
    """Project only ledger-backed web artifacts with the producer terminal state.

    A stray or stale ``crawl.urls.txt`` has no authority by itself. Failed,
    timeout, skipped and planned rows may retain provenance when their artifact
    exists, but their status cannot satisfy the bus promotion rule.
    """
    ledger = root / "web-fanout" / "runs.jsonl"
    rows = _jsonl(ledger)
    count = 0
    for row in rows:
        runner = str(row.get("runner", "unknown")).strip() or "unknown"
        if not (
            runner.startswith("crawl-")
            or runner.startswith("directory-")
            or runner == "content-fuzz"
        ):
            continue
        status = str(row.get("status", "unknown")).strip().lower() or "unknown"
        origin = str(row.get("origin", "")).strip()
        for path in _artifact_paths(root, row, "web-fanout"):
            source = str(path.relative_to(root))
            values = (
                _directory_urls_from_artifact(path, origin)
                if runner.startswith("directory-")
                else _urls_from_artifact(path)
            )
            for value in values:
                within_target = bool(allow(value))
                bus.observe_url_components(
                    value,
                    producer=f"web-fanout/{runner}",
                    source=source,
                    status=status,
                    within_target=within_target,
                )
                count += 1
    return count


def _web_promoted_urls(bus: artifact_bus.ArtifactBus, runner_prefixes: tuple[str, ...] = ()) -> list[str]:
    values: list[str] = []
    for row in bus.records("url", promotable_only=True):
        observations = row.get("observations", [])
        if any(
            _promotable_observation(item, prefix)
            for item in observations
            for prefix in (runner_prefixes or ("web-fanout/",))
        ):
            values.append(str(row["value"]))
    return sorted(set(values))


def _compatibility_index(root: Path, values: list[str]) -> None:
    path = root / "web-fanout" / "crawl.urls.txt"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")
    path.chmod(0o600)


def _allowed_origin_set(origins: list[str]) -> set[str]:
    return {
        value
        for raw in origins
        if (value := artifact_bus.canonical_origin(raw))
    }


def _allow_from_origins(origins: set[str]) -> Callable[[str], bool]:
    def allowed(value: str) -> bool:
        origin = artifact_bus.canonical_origin(value)
        return bool(origin and origin in origins)
    return allowed


def run_web_fanout_from_bus(root: Path, origins: list[str], **kwargs: Any) -> dict[str, Any]:
    """Run the existing web fanout from canonical completed HTTP origin records."""
    local_kwargs = dict(kwargs)
    verify_limit = max(0, int(local_kwargs.pop("max_verify_urls", 200)))
    allowed_origins = _allowed_origin_set(origins)
    allow = _allow_from_origins(allowed_origins)
    bus = artifact_bus.ArtifactBus(root, next(iter(sorted(allowed_origins)), ""))
    artifact_bus.ingest_http_inventory(bus, root, allow)
    bus.save()
    queued_origins = [
        str(row["value"])
        for row in bus.records("origin", promotable_only=True)
        if str(row["value"]) in allowed_origins
    ]
    result = _ORIGINAL_WEB_FANOUT(root, sorted(set(queued_origins)), **local_kwargs)
    ingest_web_fanout_status_aware(bus, root, allow)
    bus.save()
    promoted = _web_promoted_urls(bus)
    active = bool(local_kwargs.get("active", False))
    timeout = int(local_kwargs.get("timeout", 30))
    threads = int(local_kwargs.get("threads", 4))
    post_crawl = http_reverification.run_phase(
        root,
        "post-crawl",
        _web_promoted_urls(bus, ("web-fanout/crawl-",)),
        active=active,
        timeout=timeout,
        threads=threads,
        limit=verify_limit,
        allow_url=allow,
    )
    post_content = http_reverification.run_phase(
        root,
        "post-content",
        _web_promoted_urls(bus, ("web-fanout/directory-", "web-fanout/content-fuzz")),
        active=active,
        timeout=timeout,
        threads=threads,
        limit=verify_limit,
        allow_url=allow,
    )
    _compatibility_index(root, promoted)
    return {
        **result,
        "canonical_origin_inputs": len(set(queued_origins)),
        "canonical_promoted_urls": len(promoted),
        "http_reverification": {"post_crawl": post_crawl, "post_content": post_content},
        "http_reverification_observed": post_crawl["observed"] + post_content["observed"],
        "artifact": "http-reverification",
    }


def parameterized_urls_from_bus(root: Path, allowed_origins: set[str], limit: int) -> list[str]:
    """Build the parameter-validation queue solely from promotable observations."""
    allowed = {
        value
        for raw in allowed_origins
        if (value := artifact_bus.canonical_origin(raw))
    }
    bus = artifact_bus.ArtifactBus(root, "")
    found: set[str] = set()
    for row in bus.records("parameter", promotable_only=True):
        for observation in row.get("observations", []):
            if not _promotable_observation(observation):
                continue
            attributes = observation.get("attributes", {})
            if not isinstance(attributes, dict):
                continue
            value = artifact_bus.canonical_url(str(attributes.get("url", "")))
            if not value or artifact_bus.canonical_origin(value) not in allowed:
                continue
            found.add(value)
    return sorted(found)[: max(0, int(limit))]


def _nuclei_rows(path: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for row in _jsonl(path):
        template_id = str(row.get("template-id", row.get("templateID", row.get("template_id", "")))).strip()
        matched = str(row.get("matched-at", row.get("matched", row.get("host", "")))).strip()
        if not template_id or not matched:
            continue
        info = row.get("info", {}) if isinstance(row.get("info"), dict) else {}
        findings.append(
            {
                "finding_id": template_id[:512],
                "url": artifact_bus.canonical_url(matched),
                "name": str(info.get("name", row.get("name", "")))[:1024],
                "severity": str(info.get("severity", row.get("severity", "")))[:64].lower(),
            }
        )
    return findings


def ingest_advanced_consumers_status_aware(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    allow: Callable[[str], bool],
) -> int:
    """Separate execution receipts from recognized structured findings."""
    ledger = root / "advanced-consumers" / "runs.jsonl"
    count = 0
    for row in _jsonl(ledger):
        runner = str(row.get("runner", "unknown")).strip() or "unknown"
        origin = str(row.get("origin", "")).strip()
        status = str(row.get("status", "unknown")).strip().lower() or "unknown"
        origin_within_target = bool(origin and allow(origin))
        bus.observe(
            "finding",
            f"execution:{runner}:{artifact_bus.canonical_origin(origin) or origin or 'none'}",
            producer=f"advanced-consumers/{runner}",
            source="advanced-consumers/runs.jsonl",
            status=f"execution-{status}",
            within_target=origin_within_target,
            observed=False,
            attributes={"finding_type": "consumer-execution", "runner": runner},
        )
        count += 1

        if runner != "template-checks":
            continue
        source_status = status if status in _COMPLETED else f"source-{status}"
        for path in _artifact_paths(root, row, "advanced-consumers"):
            if path.name != "findings.jsonl":
                continue
            source = str(path.relative_to(root))
            for finding in _nuclei_rows(path):
                url = finding.get("url", "")
                within_target = bool(url and allow(url))
                identity = f"nuclei:{finding['finding_id']}@{url or artifact_bus.canonical_origin(origin)}"
                bus.observe(
                    "finding",
                    identity,
                    producer="advanced-consumers/template-checks",
                    source=source,
                    status=source_status,
                    within_target=within_target,
                    observed=True,
                    attributes={
                        "finding_type": "nuclei",
                        "finding_id": finding["finding_id"],
                        "name": finding["name"],
                        "severity": finding["severity"],
                        "url": url,
                    },
                )
                if url:
                    bus.observe_url_components(
                        url,
                        producer="advanced-consumers/template-checks",
                        source=source,
                        status=source_status,
                        within_target=within_target,
                    )
                count += 1
    return count


def _advanced_promoted_urls(root: Path) -> list[str]:
    bus = artifact_bus.ArtifactBus(root, "")
    values: list[str] = []
    for row in bus.records("url", promotable_only=True):
        if any(_promotable_observation(item, "advanced-consumers/") for item in row.get("observations", [])):
            values.append(str(row["value"]))
    return sorted(set(values))


def _has_verified_http_200(row: dict[str, Any]) -> bool:
    for observation in row.get("observations", []):
        if not isinstance(observation, dict):
            continue
        if not observation.get("within_target") or not observation.get("observed", True):
            continue
        status = str(observation.get("status", "")).strip().lower()
        if status in {"http-200", "verified"}:
            return True
        attributes = observation.get("attributes", {})
        if not isinstance(attributes, dict):
            continue
        for key in ("status_code", "http_status", "status"):
            try:
                if int(attributes.get(key, 0) or 0) == 200:
                    return True
            except (TypeError, ValueError):
                continue
    return False


def _project_catalog_event(
    bus: artifact_bus.ArtifactBus,
    root: Path,
    event: dict[str, Any],
    allow: Callable[[str], bool],
) -> int:
    """Project one catalog event after its terminal status is known."""
    status = str(event.get("status", "unknown")).strip().lower() or "unknown"
    module_id = str(event.get("module_id", "unknown")).strip() or "unknown"
    count = 0
    seen: set[tuple[str, str]] = set()
    for path in _safe_result_files(root, event.get("result_dir", "")):
        source = str(path.relative_to(root))
        for value in _urls_from_artifact(path):
            canonical = artifact_bus.canonical_url(value)
            marker = (source, canonical)
            if not canonical or marker in seen:
                continue
            seen.add(marker)
            bus.observe_url_components(
                value,
                producer=f"catalog/{module_id}",
                source=source,
                status=status,
                within_target=bool(allow(value)),
            )
            count += 1
    return count


def _canonical_catalog_inputs(
    root: Path,
    target: str,
    allow: Callable[[str], bool],
) -> list[str]:
    bus = artifact_bus.ArtifactBus(root, target)
    verified = {
        str(row["value"])
        for kind in ("url", "origin")
        for row in bus.records(kind, promotable_only=True)
        if allow(str(row["value"])) and _has_verified_http_200(row)
    }
    if verified:
        return sorted(verified)
    values = {
        str(row["value"])
        for kind in ("url", "origin")
        for row in bus.records(kind, promotable_only=True)
        if allow(str(row["value"]))
    }
    return sorted(values)


def install(runtime_module: Any) -> Any:
    """Install Phase-5 handoff semantics over the already composed runtime."""
    global _INSTALLED
    if _INSTALLED or getattr(runtime_module, "_ah_puch_web_chain", False):
        return runtime_module

    original_advanced = runtime_module.run_advanced_consumers
    base = runtime_module.v2.base
    current = base.UnifiedRun

    class WebChainUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_web_chain_catalog = True

        def module_inputs(self, item: dict[str, Any]) -> list[str]:
            primary = str(item.get("primary_input", "")).lower()
            if not any(hint in primary for hint in base.URL_INPUT_HINTS):
                return super().module_inputs(item)
            values = _canonical_catalog_inputs(self.root, self.target, self._allowed)
            if not values:
                return []
            canonical_origins = base.origins(values, self.target)
            limit = self.args.max_inputs
            return canonical_origins if limit == 0 else canonical_origins[:limit]

        def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
            if item.get("native_capability"):
                super().run_catalog_module(item, input_value, index)
                return
            previous_urls = list(self.seed_urls)
            event_start = len(self.events)
            try:
                super().run_catalog_module(item, input_value, index)
            finally:
                # Base compatibility code extracts URLs before it knows the
                # terminal status. Roll that mutation back even on exceptions.
                self.seed_urls = previous_urls
            module_id = str(item.get("id", ""))
            event = next(
                (
                    row for row in reversed(self.events[event_start:])
                    if str(row.get("module_id", "")) == module_id
                ),
                None,
            )
            if not event or not event.get("result_dir"):
                return
            try:
                bus = artifact_bus.ArtifactBus(self.root, self.target)
                _project_catalog_event(bus, self.root, event, self._allowed)
                bus.save()
            except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
                if hasattr(self, "_artifact_bus_failed"):
                    self._artifact_bus_failed = True
                self.event({
                    "engine": "artifact_bus_catalog_handoff",
                    "module_id": module_id,
                    "status": "failed",
                    "error": f"{type(exc).__name__}: {exc}",
                })

    WebChainUnifiedRun.__name__ = "WebChainUnifiedRun"
    WebChainUnifiedRun.__qualname__ = "WebChainUnifiedRun"
    base.UnifiedRun = WebChainUnifiedRun

    def run_advanced_from_bus(root: Path, origins: list[str], **kwargs: Any) -> dict[str, Any]:
        allow = kwargs.get("allow_origin")
        if not callable(allow):
            allowed = _allowed_origin_set(origins)
            allow = _allow_from_origins(allowed)
        bus = artifact_bus.ArtifactBus(root, next(iter(origins), ""))
        artifact_bus.ingest_http_inventory(bus, root, allow)
        ingest_web_fanout_status_aware(bus, root, allow)
        bus.save()
        supplied = _allowed_origin_set(origins)
        queued = [
            str(row["value"])
            for row in bus.records("origin", promotable_only=True)
            if str(row["value"]) in supplied and allow(str(row["value"]))
        ]
        result = original_advanced(root, sorted(set(queued)), **kwargs)
        post = artifact_bus.ArtifactBus(root, next(iter(queued), ""))
        ingest_advanced_consumers_status_aware(post, root, allow)
        summary = post.save()
        return {
            **result,
            "canonical_origin_inputs": len(set(queued)),
            "structured_findings": summary["promotable"].get("finding", 0),
        }

    artifact_bus.ingest_web_fanout = ingest_web_fanout_status_aware
    artifact_bus.ingest_advanced_consumers = ingest_advanced_consumers_status_aware
    advanced_consumers._parameterized_urls = parameterized_urls_from_bus
    runner_v2.run_all_origins = run_web_fanout_from_bus
    runtime_module.run_advanced_consumers = run_advanced_from_bus
    runtime_module._collect_urls = _advanced_promoted_urls
    runtime_module._ah_puch_web_chain = True
    _INSTALLED = True
    return runtime_module
