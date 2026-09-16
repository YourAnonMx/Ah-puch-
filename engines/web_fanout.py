#!/usr/bin/env python3
"""All-origin bounded crawl, directory and technology fan-out."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .artifact_contract import classify, inspect_artifact
    from .content_fuzz_policy import dirsearch_args, gobuster_args
    from .dictionary_broker import explicit_info, receipt_info, resolve, resolve_info
    from .runner_registry import admitted_path, run_bounded
except ImportError:
    from artifact_contract import classify, inspect_artifact
    from content_fuzz_policy import dirsearch_args, gobuster_args
    from dictionary_broker import explicit_info, receipt_info, resolve, resolve_info
    from runner_registry import admitted_path, run_bounded

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _slug(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or "origin"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host.replace(':', '_')}-{port}-{parsed.scheme}"


def _record(origin: str, runner: str, result: dict, artifacts: list[dict]) -> dict:
    return {"origin": origin, "runner": runner, "status": classify(result, artifacts), "artifacts": artifacts, **result}


def _urls_from_path(path: Path) -> set[str]:
    if not path.exists():
        return set()
    values: set[str] = set()
    files = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
    for item in files:
        try:
            text = item.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        values.update(value.rstrip(".,;:)]}") for value in URL_RE.findall(text))
    return values


def _same_origin_or_subdomain(value: str, origin: str) -> bool:
    try:
        candidate = urlsplit(value)
        root = urlsplit(origin)
    except ValueError:
        return False
    if candidate.scheme not in {"http", "https"} or not candidate.hostname or not root.hostname:
        return False
    chost = candidate.hostname.lower().rstrip(".")
    rhost = root.hostname.lower().rstrip(".")
    return chost == rhost or chost.endswith("." + rhost)


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


def run_all_origins(
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
    **_unused: Any,
) -> dict:
    destination = root / "web-fanout"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    options = tool_options or {}
    directory_options = options.get("dirsearch", {})
    requested_tier = str(directory_options.get("tier", "") or tier)
    configured_dictionary = str(directory_options.get("wordlist", "")).strip()
    dictionary_resolution: dict[str, Any] = {
        "class": "directory",
        "requested_tier": requested_tier,
        "effective_tier": requested_tier,
        "tier_exact": False,
        "path": "",
        "available": False,
        "source": "disabled",
        "provenance": "runtime-disabled",
    }
    if use_dictionaries:
        dictionary, dictionary_resolution = _directory_resolution(requested_tier, configured_dictionary)
    else:
        dictionary = None
    if not use_dictionaries:
        dictionary_skip_reason = "dictionary routing disabled"
    elif configured_dictionary and not dictionary:
        dictionary_skip_reason = "configured directory dictionary rejected: " + str(dictionary_resolution.get("reason", "invalid resource"))
    else:
        dictionary_skip_reason = "no local/imported directory dictionary available"
    rows: list[dict] = []
    all_crawl_urls: set[str] = set()
    dirsearch = admitted_path("directory_primary")
    gobuster = admitted_path("directory_secondary")
    whatweb = admitted_path("technology_fingerprint")
    katana = admitted_path("crawl_primary")
    gospider = admitted_path("crawl_secondary")
    katana_options = options.get("katana", {})
    spider_options = options.get("gospider", {})

    for origin in origins[: max(1, max_origins)]:
        origin_dir = destination / _slug(origin)
        origin_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not active:
            rows.append(
                {
                    "origin": origin,
                    "runner": "all-origin",
                    "status": "planned-passive",
                    "dictionary": str(dictionary or ""),
                    "dictionary_class": "directory",
                    "dictionary_tier": str(dictionary_resolution.get("effective_tier", requested_tier)),
                    "dictionary_source": str(dictionary_resolution.get("source", "")),
                }
            )
            continue

        # Primary crawler. This runs only after the architecture-v2 HTTP
        # inventory has already classified the origin as a target final
        # HTTP 200 destination.
        crawl_urls: set[str] = set()
        if katana:
            out = origin_dir / "crawl-primary.txt"
            katana_concurrency = katana_options.get("concurrency", katana_options.get("threads", threads))
            command = [
                    katana,
                    "-u",
                    origin,
                    "-silent",
                    "-d",
                    str(max(1, min(int(katana_options.get("depth", 2)), 10))),
                    "-c",
                    str(max(1, min(int(katana_concurrency), 64))),
                    "-o",
                    str(out),
                ]
            if katana_options.get("js_crawl"):
                command.append("-jc")
            if katana_options.get("headless"):
                command.append("-headless")
            if int(katana_options.get("rate", 0)) > 0:
                command.extend(["-rl", str(int(katana_options["rate"]))])
            if int(katana_options.get("duration", 0)) > 0:
                command.extend(["-ct", str(int(katana_options["duration"]))])
            result = run_bounded(
                command,
                origin_dir,
                origin_dir / "crawl-primary.console.txt",
                origin_dir / "crawl-primary.stderr.txt",
                min(timeout, 240),
            )
            artifacts = [inspect_artifact(out, required=True)]
            rows.append(_record(origin, "crawl-primary", result, artifacts))
            primary_urls = sorted(_urls_from_path(out))
            if int(katana_options.get("max_urls", 0)) > 0:
                primary_urls = primary_urls[: int(katana_options["max_urls"])]
                out.write_text("\n".join(primary_urls) + ("\n" if primary_urls else ""), encoding="utf-8")
                out.chmod(0o600)
            crawl_urls.update(primary_urls)
        else:
            rows.append({"origin": origin, "runner": "crawl-primary", "status": "skipped", "reason": "primary crawler unavailable"})

        # Secondary crawler preserves the independent-source comparison from
        # the older workflows without retaining their shell structure.
        if gospider:
            raw_dir = origin_dir / "crawl-secondary-raw"
            command = [
                    gospider,
                    "-s",
                    origin,
                    "-t",
                    str(max(1, min(int(spider_options.get("threads", threads)), 32))),
                    "-c",
                    str(max(1, min(int(spider_options.get("concurrency", threads)), 32))),
                    "-d",
                    str(max(1, min(int(spider_options.get("depth", 2)), 10))),
                    "-o",
                    str(raw_dir),
                ]
            if spider_options.get("other_source", 1):
                command.append("--other-source")
            result = run_bounded(
                command,
                origin_dir,
                origin_dir / "crawl-secondary.console.txt",
                origin_dir / "crawl-secondary.stderr.txt",
                min(timeout, 240),
            )
            secondary_urls = sorted(_urls_from_path(raw_dir))
            secondary_out = origin_dir / "crawl-secondary.txt"
            secondary_out.write_text("\n".join(secondary_urls) + ("\n" if secondary_urls else ""), encoding="utf-8")
            secondary_out.chmod(0o600)
            artifacts = [inspect_artifact(secondary_out, required=True)]
            rows.append(_record(origin, "crawl-secondary", result, artifacts))
            crawl_urls.update(secondary_urls)
        else:
            rows.append({"origin": origin, "runner": "crawl-secondary", "status": "skipped", "reason": "secondary crawler unavailable"})

        scoped_crawl = sorted(value for value in crawl_urls if _same_origin_or_subdomain(value, origin))
        crawl_path = origin_dir / "crawl.urls.txt"
        crawl_path.write_text("\n".join(scoped_crawl) + ("\n" if scoped_crawl else ""), encoding="utf-8")
        crawl_path.chmod(0o600)
        all_crawl_urls.update(scoped_crawl)

        if not dictionary:
            rows.append({"origin": origin, "runner": "directory", "status": "skipped", "reason": dictionary_skip_reason})
        if dictionary and dirsearch:
            out = origin_dir / "directory-primary.txt"
            err = origin_dir / "directory-primary.stderr.txt"
            command = [
                    dirsearch,
                    "-u",
                    origin,
                    "--format=plain",
                    "-o",
                    str(out),
                    *dirsearch_args(directory_options, timeout=timeout, threads=threads),
                    "-w",
                    str(dictionary),
                ]
            result = run_bounded(
                command,
                origin_dir,
                origin_dir / "directory-primary.console.txt",
                err,
                min(timeout, 240),
            )
            artifacts = [inspect_artifact(out, required=True)]
            rows.append(_record(origin, "directory-primary", result, artifacts))
        elif dictionary:
            rows.append({"origin": origin, "runner": "directory-primary", "status": "skipped", "reason": "dirsearch unavailable"})

        if dictionary and gobuster:
            out = origin_dir / "directory-secondary.txt"
            result = run_bounded(
                [
                    gobuster,
                    "dir",
                    "-u",
                    origin,
                    "-w",
                    str(dictionary),
                    "-q",
                    "--no-error",
                    *gobuster_args(options.get("gobuster", {}), timeout=timeout, threads=threads),
                    "-o",
                    str(out),
                ],
                origin_dir,
                origin_dir / "directory-secondary.console.txt",
                origin_dir / "directory-secondary.stderr.txt",
                min(timeout, 240),
            )
            artifacts = [inspect_artifact(out, required=True)]
            rows.append(_record(origin, "directory-secondary", result, artifacts))
        elif dictionary:
            rows.append({"origin": origin, "runner": "directory-secondary", "status": "skipped", "reason": "secondary directory runner unavailable"})

        if whatweb:
            out = origin_dir / "technology.json"
            result = run_bounded(
                [whatweb, "--no-errors", "--color=never", f"--log-json={out}", origin],
                origin_dir,
                origin_dir / "technology.console.txt",
                origin_dir / "technology.stderr.txt",
                min(timeout, 90),
            )
            artifacts = [inspect_artifact(out, required=True)]
            rows.append(_record(origin, "technology-fingerprint", result, artifacts))
        else:
            rows.append({"origin": origin, "runner": "technology-fingerprint", "status": "skipped", "reason": "technology fingerprint runner unavailable"})

    crawl_index = destination / "crawl.urls.txt"
    crawl_index.write_text("\n".join(sorted(all_crawl_urls)) + ("\n" if all_crawl_urls else ""), encoding="utf-8")
    crawl_index.chmod(0o600)

    ledger = destination / "runs.jsonl"
    ledger.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    ledger.chmod(0o600)
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return {
        "runs": len(rows),
        "origins": min(len(origins), max_origins),
        "dictionary": str(dictionary or ""),
        "dictionary_enabled": bool(use_dictionaries),
        "dictionary_resolution": receipt_info(dictionary_resolution),
        "crawl_urls": len(all_crawl_urls),
        "statuses": counts,
    }
