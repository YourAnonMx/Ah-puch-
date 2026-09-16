#!/usr/bin/env python3
"""All-origin advanced assessment consumers for explicitly active target runs.

This layer keeps third-party executables behind native Ah-Puch contracts. It
never expands scope, never downloads tools or container images during a live
run, and preserves each runner's native evidence plus an honest terminal state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

try:
    from .artifact_contract import classify, inspect_artifact
    from .runner_registry import admitted_path, inspect_runner, run_bounded
    from .tool_options import TOOL_OPTION_DEFAULTS, WAPITI_DEFAULT_MODULES
except ImportError:
    from artifact_contract import classify, inspect_artifact
    from runner_registry import admitted_path, inspect_runner, run_bounded
    from tool_options import TOOL_OPTION_DEFAULTS, WAPITI_DEFAULT_MODULES

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _slug(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "origin").replace(":", "_")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}-{port}-{parsed.scheme}"


def _same_origin(value: str, origin: str) -> bool:
    try:
        a = urlsplit(value)
        b = urlsplit(origin)
    except ValueError:
        return False
    if a.scheme not in {"http", "https"} or not a.hostname or not b.hostname:
        return False
    aport = a.port or (443 if a.scheme == "https" else 80)
    bport = b.port or (443 if b.scheme == "https" else 80)
    return a.scheme == b.scheme and a.hostname.lower().rstrip(".") == b.hostname.lower().rstrip(".") and aport == bport


def _runner_ready(name: str) -> tuple[bool, str]:
    row = inspect_runner(name)
    if not row.get("available"):
        missing = row.get("missing_help_contract") or []
        reason = "runner unavailable"
        if row.get("path") and not row.get("contract_ok"):
            reason = "runner help/capability contract mismatch"
        if missing:
            reason += ": " + ",".join(str(value) for value in missing)
        return False, reason
    return True, str(row.get("path", ""))


def _record(origin: str, runner: str, result: dict, artifacts: list[dict]) -> dict:
    return {
        "origin": origin,
        "runner": runner,
        "status": classify(result, artifacts),
        "artifacts": artifacts,
        **result,
    }


def _parameterized_urls(root: Path, allowed_origins: set[str], limit: int) -> list[str]:
    found: set[str] = set()
    candidate_paths = [
        root / "web-fanout" / "crawl.urls.txt",
        *root.glob("queues/*.parameterized.urls.txt"),
        *root.rglob("*.injection.urls.txt"),
        *root.rglob("*.parameters.txt"),
    ]
    for path in candidate_paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for value in URL_RE.findall(text):
            clean = value.rstrip(".,;:)]}")
            if "?" not in clean or "=" not in clean:
                continue
            if any(_same_origin(clean, origin) for origin in allowed_origins):
                found.add(clean)
    return sorted(found)[: max(0, limit)]


def _nikto(origin: str, outdir: Path, timeout: int, deep: bool, options: dict[str, Any] | None = None) -> dict:
    ready, binary = _runner_ready("web_server_check")
    if not ready:
        return {"origin": origin, "runner": "web-server-check", "status": "skipped", "reason": binary}
    report = outdir / "report.json"
    options = options or {}
    command = [binary, "-host", origin, "-ask", "no", "-nointeractive", "-timeout", "15", "-Format", "json", "-output", str(report)]
    if options.get("mutate"):
        command.extend(["-mutate", str(options["mutate"])])
    if deep or options.get("cgi_dirs"):
        command.extend(["-Cgidirs", str(options.get("cgi_dirs", "all"))])
    result = run_bounded(command, outdir, outdir / "console.txt", outdir / "stderr.txt", min(timeout, 10800))
    return _record(origin, "web-server-check", result, [inspect_artifact(report, required=True)])


def _tls(origin: str, outdir: Path, timeout: int, options: dict[str, Any] | None = None) -> dict:
    if urlsplit(origin).scheme != "https":
        return {"origin": origin, "runner": "tls-configuration", "status": "skipped", "reason": "origin is not HTTPS"}
    ready, binary = _runner_ready("tls_configuration")
    if not ready:
        return {"origin": origin, "runner": "tls-configuration", "status": "skipped", "reason": binary}
    report = outdir / "report.json"
    html = outdir / "report.html"
    options = options or {}
    command = [binary, "--quiet", "--color", str(int(options.get("color", 0))), "--warnings", str(options.get("warnings", "batch")), "--jsonfile", str(report), "--htmlfile", str(html), origin]
    result = run_bounded(command, outdir, outdir / "console.txt", outdir / "stderr.txt", min(timeout, 10800))
    return _record(origin, "tls-configuration", result, [inspect_artifact(report, required=True), inspect_artifact(html, required=False)])


def _nuclei(origin: str, outdir: Path, timeout: int, deep: bool, options: dict[str, Any] | None = None) -> dict:
    ready, binary = _runner_ready("template_checks")
    if not ready:
        return {"origin": origin, "runner": "template-checks", "status": "skipped", "reason": binary}
    report = outdir / "findings.jsonl"
    options = options or {}
    command = [binary, "-u", origin, "-silent", "-jsonl", "-o", str(report), "-timeout", str(max(1, int(options.get("timeout", 15)))), "-retries", "1"]
    if options.get("severity"):
        command.extend(["-severity", str(options["severity"])])
    if int(options.get("rate_limit", 0)) > 0:
        command.extend(["-rl", str(int(options["rate_limit"]))])
    if int(options.get("threads", 0)) > 0:
        command.extend(["-c", str(int(options["threads"]))])
    if options.get("templates"):
        command.extend(["-t", str(options["templates"])])
    if options.get("profile"):
        command.extend(["-profile", str(options["profile"])])
    if not int(options.get("oast", 0)):
        command.append("-ni")
    if int(options.get("code", 0)):
        command.append("-code")
    if not int(options.get("unsigned", 0)):
        command.append("-dut")
    if deep or options.get("dast"):
        inspected = inspect_runner("template_checks")
        help_sample = str(inspected.get("help_sample", ""))
        if "-dast" in help_sample:
            command.append("-dast")
        if "-headless" in help_sample:
            command.append("-headless")
    result = run_bounded(command, outdir, outdir / "console.txt", outdir / "stderr.txt", min(timeout, 43200))
    return _record(origin, "template-checks", result, [inspect_artifact(report, required=True)])


def _wapiti(origin: str, outdir: Path, timeout: int, deep: bool, options: dict[str, Any] | None = None) -> dict:
    ready, binary = _runner_ready("web_audit_secondary")
    if not ready:
        return {"origin": origin, "runner": "web-audit-secondary", "status": "skipped", "reason": binary}
    report = outdir / "report.json"
    options = options or {}
    command = [binary, "-u", origin, "--scope", "url", "-m", str(options.get("modules", WAPITI_DEFAULT_MODULES)), "-f", str(options.get("format", "json")), "-o", str(report), "--tasks", str(max(1, int(options.get("tasks", 1)))), "--timeout", str(max(1, int(options.get("timeout", 15))))]
    if int(options.get("wait", 0)) > 0:
        command.extend(["--wait", str(int(options["wait"]))])
    command.extend(["--verify-ssl", "1" if int(options.get("verify_ssl", 1)) else "0"])
    if int(options.get("headless", 0)):
        command.extend(["--headless", str(options.get("headless_mode", "hidden"))])
    if int(options.get("max_scan_time", 0)) > 0:
        command.extend(["--max-scan-time", str(int(options["max_scan_time"]))])
    if int(options.get("max_attack_time", 0)) > 0:
        command.extend(["--max-attack-time", str(int(options["max_attack_time"]))])
    if int(options.get("no_bugreport", 1)):
        command.append("--no-bugreport")
    if deep:
        command.extend(["-l", "2", "-S", "insane"])
    result = run_bounded(command, outdir, outdir / "console.txt", outdir / "stderr.txt", min(timeout, 86400))
    return _record(origin, "web-audit-secondary", result, [inspect_artifact(report, required=True)])


def _local_zap_image(image: str) -> str:
    docker = admitted_path("container_runtime")
    if not docker or not image.strip():
        return ""
    try:
        result = subprocess.run(
            [docker, "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def zap_backend(
    active: bool,
    *,
    runtime: str = "",
    image: str = "",
    image_id: str = "",
) -> dict[str, Any]:
    """Return the admitted ZAP backend without downloading anything.

    A prepared local container remains the preferred backend. The native Kali
    launcher is an equivalent fallback when Docker/Podman is unavailable or
    its image has not been prepared. The runner registry proves both paths.
    """
    runner_name = "web_proxy_active" if active else "web_proxy_passive"
    container_path = runtime or admitted_path("container_runtime")
    local_image_id = image_id or (_local_zap_image(image) if container_path else "")
    if container_path and local_image_id:
        return {
            "available": True,
            "kind": "container",
            "path": container_path,
            "image_reference": image,
            "image_id": local_image_id,
            "identity": local_image_id,
            "reason": "local-container-backend",
        }

    row = inspect_runner(runner_name)
    if row.get("available") and row.get("contract_ok") and row.get("disposition") == "REACHABLE":
        kind = str(row.get("runtime_kind", "container"))
        path = str(row.get("path", ""))
        if kind == "native" and row.get("native_zap_ready") and path:
            identity = "native:" + str(row.get("sha256") or row.get("native_zap_version") or path)
            return {
                "available": True,
                "kind": "native",
                "path": path,
                "image_reference": image,
                "image_id": "",
                "identity": identity,
                "native_zap_version": str(row.get("native_zap_version", "")),
                "reason": "native-zap-fallback",
            }
        row_image_id = str(row.get("image_id", ""))
        if kind == "container" and path and row_image_id:
            return {
                "available": True,
                "kind": "container",
                "path": path,
                "image_reference": str(row.get("image_reference", image)),
                "image_id": row_image_id,
                "identity": row_image_id,
                "reason": "local-container-backend",
            }
    return {
        "available": False,
        "kind": "",
        "path": "",
        "image_reference": image,
        "image_id": "",
        "identity": "",
        "reason": str(row.get("reason", "usable local ZAP backend unavailable")),
    }


def _yaml_quote(value: str) -> str:
    """Encode one value as a YAML single-quoted scalar."""
    return "'" + str(value).replace("'", "''") + "'"


def _native_zap_plan(
    origin: str,
    outdir: Path,
    active: bool,
    ajax: bool,
    effective: dict[str, Any],
) -> Path:
    """Write a self-contained, target-bound native ZAP automation plan."""
    context_url = origin.rstrip("/") or origin
    include_regex = "^" + re.escape(context_url) + r"(?:/.*)?$"
    lines = [
        "env:",
        "  contexts:",
        "    - name: ah-puch-target",
        "      urls:",
        f"        - {_yaml_quote(origin)}",
        "      includePaths:",
        f"        - {_yaml_quote(include_regex)}",
        "  parameters:",
        "    failOnError: true",
        "    failOnWarning: false",
        "    continueOnFailure: false",
        "    progressToStdout: true",
        "jobs:",
        "  - type: spider",
        "    parameters:",
        "      context: ah-puch-target",
        f"      url: {_yaml_quote(origin)}",
        f"      maxDuration: {int(effective['minutes'])}",
        "      maxDepth: 5",
    ]
    if effective["max_urls"] > 0:
        lines.append(f"      maxChildren: {int(effective['max_urls'])}")
    if ajax:
        lines.extend([
            "  - type: spiderAjax",
            "    parameters:",
            "      context: ah-puch-target",
            f"      url: {_yaml_quote(origin)}",
            f"      maxDuration: {int(effective['minutes'])}",
            "      maxCrawlDepth: 5",
            "      numberOfBrowsers: 1",
        ])
    lines.extend([
        "  - type: passiveScan-wait",
        "    parameters:",
        f"      maxDuration: {int(effective['minutes'])}",
    ])
    if active:
        lines.extend([
            "  - type: activeScan",
            "    parameters:",
            "      context: ah-puch-target",
            f"      url: {_yaml_quote(origin)}",
            f"      maxScanDurationInMins: {int(effective['minutes'])}",
        ])
        lines.extend([
            "  - type: passiveScan-wait",
            "    parameters:",
            f"      maxDuration: {int(effective['minutes'])}",
        ])
    lines.extend([
        "  - type: report",
        "    parameters:",
        "      template: traditional-json",
        f"      reportDir: {_yaml_quote(str(outdir.resolve()))}",
        "      reportFile: report.json",
        "      reportTitle: Ah Puch ZAP JSON",
        "      displayReport: false",
        "    sites:",
        f"      - {_yaml_quote(context_url)}",
        "  - type: report",
        "    parameters:",
        "      template: traditional-html",
        f"      reportDir: {_yaml_quote(str(outdir.resolve()))}",
        "      reportFile: report.html",
        "      reportTitle: Ah Puch ZAP HTML",
        "      displayReport: false",
        "    sites:",
        f"      - {_yaml_quote(context_url)}",
        "  - type: exitStatus",
        "    parameters:",
        "      okExitValue: 0",
        "      errorExitValue: 1",
        "      warnExitValue: 2",
    ])
    plan = outdir / "automation-plan.yaml"
    plan.write_text("\n".join(lines) + "\n", encoding="utf-8")
    plan.chmod(0o600)
    return plan


def effective_zap_options(active: bool, ajax: bool, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the bounded ZAP contract after applying all declared defaults."""
    merged = dict(TOOL_OPTION_DEFAULTS["zap"])
    merged.update(options or {})
    minute_key = "active_minutes" if active else "passive_minutes"
    return {
        "minutes": max(1, min(60, int(merged[minute_key]))),
        "ajax": int(bool(ajax)),
        "memory_mb": max(128, int(merged["memory_mb"])),
        "cpus": merged["cpus"],
        "pids": max(64, int(merged["pids"])),
        "max_urls": max(0, int(merged["max_urls"])),
    }


def zap_contract_sha256(
    origin: str,
    image_id: str,
    active: bool,
    ajax: bool,
    options: dict[str, Any] | None = None,
    *,
    runtime_kind: str = "container",
    runtime_identity: str = "",
) -> str:
    """Identify one reproducible ZAP invocation across orchestration layers."""
    runtime_identity = runtime_identity or image_id
    payload = {
        "origin": origin,
        "image_id": image_id,
        "runner": "web-proxy-active" if active else "web-proxy-passive",
        "runtime_kind": runtime_kind,
        "runtime_identity": runtime_identity,
        "options": effective_zap_options(active, ajax, options),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _zap(
    origin: str,
    outdir: Path,
    timeout: int,
    image: str,
    active: bool,
    ajax: bool,
    options: dict[str, Any] | None = None,
    *,
    runtime: str = "",
    image_id: str = "",
    backend: dict[str, Any] | None = None,
) -> dict:
    selected = backend or zap_backend(active, runtime=runtime, image=image, image_id=image_id)
    if not selected.get("available"):
        return {
            "origin": origin,
            "runner": "web-proxy-active" if active else "web-proxy-passive",
            "status": "skipped",
            "reason": str(selected.get("reason", "usable local ZAP backend unavailable")) + "; no pull attempted",
            "image_reference": image,
            "pull_during_run": False,
        }
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    report_json = outdir / "report.json"
    report_html = outdir / "report.html"
    effective = effective_zap_options(active, ajax, options)
    runtime_kind = str(selected.get("kind", "container"))
    runtime_identity = str(selected.get("identity", ""))
    selected_image_id = str(selected.get("image_id", ""))
    contract_sha256 = zap_contract_sha256(
        origin,
        selected_image_id,
        active,
        ajax,
        options,
        runtime_kind=runtime_kind,
        runtime_identity=runtime_identity,
    )
    if runtime_kind == "native":
        plan = _native_zap_plan(origin, outdir, active, bool(effective["ajax"]), effective)
        command = [
            str(selected["path"]),
            f"-Xmx{int(effective['memory_mb'])}m",
            "-cmd", "-silent", "-notel", "-dir", str((outdir / ".zap-home").resolve()),
            "-autorun", str(plan.resolve()),
        ]
    else:
        docker = str(selected["path"])
        command = [docker, "run", "--rm", "--pull", "never"]
        if Path(docker).name == "podman":
            command.append("--userns=keep-id")
        command.extend([
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--pids-limit", str(effective["pids"]),
            "--memory", f"{effective['memory_mb']}m", "--cpus", str(effective["cpus"]), "-e", "HOME=/tmp", "-v", f"{outdir.resolve()}:/zap/wrk:rw",
            selected_image_id, "zap-full-scan.py" if active else "zap-baseline.py", "-t", origin, "-J", "report.json", "-r", "report.html", "-m", str(effective["minutes"]),
        ])
        if effective["max_urls"] > 0:
            command.extend(["-z", f"-config spider.maxChildren={effective['max_urls']}"])
        if effective["ajax"]:
            command.append("-j")
    result = run_bounded(command, outdir, outdir / "console.txt", outdir / "stderr.txt", min(timeout, 86400))
    record = _record(origin, "web-proxy-active" if active else "web-proxy-passive", result, [inspect_artifact(report_json, required=True), inspect_artifact(report_html, required=False)])
    record.update({
        "contract_sha256": contract_sha256,
        "effective_options": effective,
        "image_reference": image,
        "image_id": selected_image_id,
        "runtime_kind": runtime_kind,
        "runtime_identity": runtime_identity,
        "backend_path": str(selected.get("path", "")),
        "pull_during_run": False,
    })
    if runtime_kind == "native":
        record["automation_plan"] = str(plan)
        record["reason"] = "bounded native ZAP Automation Framework assessment completed" if record["status"] == "success" else record.get("reason", "native ZAP Automation Framework failed")
    return record


def _sqlmap(root: Path, origins: list[str], outdir: Path, timeout: int, deep: bool, max_targets: int, options: dict[str, Any] | None = None) -> dict:
    ready, binary = _runner_ready("parameter_validation")
    if not ready:
        return {"runner": "parameter-validation", "status": "skipped", "reason": binary}
    targets = _parameterized_urls(root, set(origins), max_targets)
    if not targets:
        return {"runner": "parameter-validation", "status": "skipped", "reason": "no target parameterized URL queue"}
    target_file = outdir / "targets.txt"
    target_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    target_file.chmod(0o600)
    output_name = str(options.get("output", "results") or "results") if options else "results"
    output_name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(output_name).name).strip("._-") or "results"
    results_dir = outdir / output_name
    results_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    csv_report = outdir / "results.csv"
    options = options or {}
    level, risk = ((5, 3) if deep else (3, 2))
    level = int(options.get("level", level))
    risk = int(options.get("risk", risk))
    command = [
        binary, "-m", str(target_file), f"--level={level}", f"--risk={risk}",
        "--smart", "--forms", "--ignore-redirects", f"--timeout={max(1, int(options.get('timeout', 15)))}", f"--retries={max(0, int(options.get('retries', 2)))}",
        "--output-dir", str(results_dir), "--results-file", str(csv_report), "--disable-coloring", "--parse-errors",
    ]
    if int(options.get("batch", 1)):
        command.append("--batch")
    if int(options.get("skip_static", 1)):
        command.append("--skip-static")
    result = run_bounded(command, outdir, outdir / "console.txt", outdir / "stderr.txt", min(timeout, 86400))
    return {"runner": "parameter-validation", "targets": len(targets), **_record("MULTI", "parameter-validation", result, [inspect_artifact(csv_report, required=False)])}


def run(
    root: Path,
    origins: list[str],
    *,
    enabled: bool,
    profile: str,
    timeout: int,
    max_origins: int = 12,
    zap_image: str = "",
    zap_active: bool = False,
    max_sqlmap_targets: int = 50,
    allow_origin: Callable[[str], bool] | None = None,
    tool_options: dict[str, dict[str, Any]] | None = None,
    selected_consumers: set[str] | None = None,
) -> dict:
    destination = root / "advanced-consumers"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    rows: list[dict] = []
    permitted = [origin for origin in origins if not allow_origin or allow_origin(origin)][: max(1, max_origins)]
    tool_options = tool_options or {}
    all_consumers = {
        "web-server-check", "tls-configuration", "template-checks", "web-audit-secondary",
        "web-proxy-passive", "web-proxy-active", "parameter-validation",
    }
    selected = all_consumers if selected_consumers is None else set(selected_consumers)
    unknown = selected - all_consumers
    if unknown:
        raise ValueError("unknown advanced consumer selection: " + ",".join(sorted(unknown)))
    def zap_call(origin: str, outdir: Path, active: bool, deep: bool) -> dict:
        """Dispatch ZAP with the validated option, never profile side effects.

        ``deep`` controls the consumer set/profile, but AJAX spider activation is
        an independent, explicitly configured option.  Coupling the two made a
        deep run silently enable ``-j`` and made ``zap.ajax=0`` ineffective.
        Keep the default disabled when no option map is present.
        """
        options = tool_options.get("zap") or {}
        ajax = bool(options.get("ajax", 0))
        return _zap(origin, outdir, timeout, zap_image, active, ajax, options)
    if not enabled:
        for runner_id in sorted(selected):
            reason = "active mode is not enabled"
            if runner_id == "web-proxy-active" and not zap_active:
                reason = "active proxy option is disabled"
            rows.append({"runner": runner_id, "status": "skipped", "reason": reason, "gate": "active-mode"})
    else:
        deep = profile == "deep"
        for origin in permitted:
            od = destination / _slug(origin)
            od.mkdir(parents=True, exist_ok=True, mode=0o700)
            for name, func in (
                ("web-server-check", lambda: _nikto(origin, od / "web-server", timeout, deep, tool_options.get("nikto"))),
                ("tls-configuration", lambda: _tls(origin, od / "tls", timeout, tool_options.get("testssl"))),
                ("template-checks", lambda: _nuclei(origin, od / "templates", timeout, deep, tool_options.get("nuclei"))),
                ("web-audit-secondary", lambda: _wapiti(origin, od / "web-audit", timeout, deep, tool_options.get("wapiti"))),
                ("web-proxy-passive", lambda: zap_call(origin, od / "proxy-passive", False, deep)),
            ):
                if name not in selected:
                    continue
                try:
                    rows.append(func())
                except Exception as exc:  # preserve the rest of the origin fan-out
                    rows.append({"origin": origin, "runner": name, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
            if "web-proxy-active" in selected:
                if not zap_active:
                    rows.append({
                        "origin": origin,
                        "runner": "web-proxy-active",
                        "status": "skipped",
                        "reason": "active proxy option is disabled",
                        "gate": "active-mode",
                    })
                else:
                    try:
                        rows.append(zap_call(origin, od / "proxy-active", True, deep))
                    except Exception as exc:
                        rows.append({"origin": origin, "runner": "web-proxy-active", "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        if "parameter-validation" in selected:
            try:
                sql_options = tool_options.get("sqlmap", {})
                limit = min(max_sqlmap_targets, int(sql_options.get("max_targets", max_sqlmap_targets)))
                rows.append(_sqlmap(root, permitted, destination / "parameter-validation", timeout, profile == "deep", limit, sql_options))
            except Exception as exc:
                rows.append({"runner": "parameter-validation", "status": "failed", "error": f"{type(exc).__name__}: {exc}"})

    # Every declared consumer must have one terminal row, even when there are
    # no target final-200 origins to fan out. This keeps profile/full and
    # profile/deep evidence complete without enabling any gated stage.
    observed = {str(row.get("runner", "")) for row in rows}
    for runner_id in sorted(selected - observed):
        reason = "no target final-200 origins"
        gate = "origin-availability"
        if runner_id == "web-proxy-active" and not zap_active:
            reason = "active proxy option is disabled"
            gate = "active-mode"
        rows.append({
            "runner": runner_id,
            "status": "skipped",
            "reason": reason,
            "gate": gate,
        })

    ledger = destination / "runs.jsonl"
    ledger.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    ledger.chmod(0o600)
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return {"origins": len(permitted), "runs": len(rows), "statuses": counts}
