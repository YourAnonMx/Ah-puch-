#!/usr/bin/env python3
"""Canonical block coordinator for additive multi-method recon execution."""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

try:
    from . import artifact_bus
    from . import http_reverification
    from .capability_plans import execution_plan
    from .dictionary_broker import explicit_info, resolve_info
    from .native_pipeline_methods import execute_native
    from .recon_pipeline import ConvergenceLedger, FanIn, MethodPlan, MethodResult, ResultStore, inventory_tools, normalize_text, read_jsonl, write_barrier
    from .runner_registry import admitted_path, inspect_runner, run_bounded
    from .service_routing import origins_from_record
    from .target_contract import target_domain_seed, target_host_seed, target_ip_seed, target_network_seeds, target_parameter_url_seeds, target_service_seeds, target_url_seeds
    from .tool_adapters import Invocation, build_invocations
except ImportError:
    import artifact_bus
    import http_reverification
    from capability_plans import execution_plan
    from dictionary_broker import explicit_info, resolve_info
    from native_pipeline_methods import execute_native
    from recon_pipeline import ConvergenceLedger, FanIn, MethodPlan, MethodResult, ResultStore, inventory_tools, normalize_text, read_jsonl, write_barrier
    from runner_registry import admitted_path, inspect_runner, run_bounded
    from service_routing import origins_from_record
    from target_contract import target_domain_seed, target_host_seed, target_ip_seed, target_network_seeds, target_parameter_url_seeds, target_service_seeds, target_url_seeds
    from tool_adapters import Invocation, build_invocations


EXECUTION_BLOCKS = (
    "00-input-target", "01-discovery", "02-dns", "03-network", "04-http",
    "05-history", "09-fingerprint-waf-tls", "07-content", "06-crawl",
    "08-js-api-parameters", "10-assessment", "11-local-cloud", "12-device-ics",
)
HTTP_PHASE_AFTER_BLOCK = {
    "04-http": "initial",
    "06-crawl": "post-crawl",
    "07-content": "post-content",
}
HTTP_VERIFIED_CONSUMER_BLOCKS = frozenset({
    "06-crawl",
    "07-content",
    "08-js-api-parameters",
    "09-fingerprint-waf-tls",
    "10-assessment",
})
HTTP_VERIFIER_TOOL_IDS = {
    "native": {"native_http"},
    "wget": {"wget"},
    "curl": {"curl"},
    "httpx": {"httpx", "httpx_tech"},
}
ALL_HTTP_VERIFIER_TOOL_IDS = frozenset({tool_id for values in HTTP_VERIFIER_TOOL_IDS.values() for tool_id in values})
EXPLICIT_TOOLS = frozenset({"zap_full", "sqlmap", "ssrfmap", "dalfox", "nosqlmap"})
_HTTP_STATUS_RE = re.compile(r"\b(?:HTTP/\S+\s+)?([1-5]\d\d)\b")
DOMAIN_ONLY_TOOLS = frozenset(
    {
        "subfinder", "assetfinder", "amass", "findomain", "chaos", "crtsh",
        "certspotter", "ctfr", "dig", "dnsx", "puredns", "shuffledns",
        "massdns", "dnsrecon", "dnsenum", "dnsmap", "altdns", "knockpy",
        "dnstwist", "gau", "waybackurls", "waymore", "paramspider", "subzy",
        "cloudunflare", "hunter",
    }
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    path.chmod(0o600)


def _safe_read(path: Path, limit: int = 20_000_000) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _values_from_bus(root: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    derived_origins: list[str] = []
    for kind in artifact_bus.ARTIFACT_KINDS:
        rows = read_jsonl(root / "artifacts" / "queues" / f"{artifact_bus._PLURALS[kind]}.jsonl")
        values[kind] = sorted({str(row.get("value", "")) for row in rows if row.get("value")})
        if kind == "service":
            for row in rows:
                derived_origins.extend(origins_from_record(row))
    values["origin"] = sorted(set(values.get("origin", [])) | set(derived_origins))
    return values


def _merge_values(values: dict[str, list[str]], records: list[dict[str, Any]]) -> int:
    before = sum(len(items) for items in values.values())
    for row in records:
        if not row.get("promotable", True):
            continue
        kind = str(row.get("kind", ""))
        value = str(row.get("value", ""))
        if kind and value:
            values.setdefault(kind, []).append(value)
            if kind == "service":
                values.setdefault("origin", []).extend(origins_from_record(row))
    for kind in values:
        values[kind] = sorted(set(values[kind]))
    return sum(len(items) for items in values.values()) - before


def _credentials_present(expression: str) -> bool:
    names = [name.strip() for name in expression.split(",") if name.strip()]
    return all(bool(os.environ.get(name)) for name in names)


def _domain_values(values: list[str]) -> list[str]:
    return list(dict.fromkeys(seed for value in values if (seed := target_domain_seed(str(value)))))


def _input_values(tool: dict[str, Any], values: dict[str, list[str]], target: str) -> list[str]:
    result: list[str] = []
    for kind in tool["inputs"]:
        if kind == "target":
            result.append(target)
        elif kind in {"host", "host-list"}:
            result.extend(values.get("host", []))
        elif kind == "network-target-list":
            result.extend(values.get("host", []))
            result.extend(values.get("ip", []))
        elif kind == "origin":
            if str(tool.get("block", "")) in HTTP_VERIFIED_CONSUMER_BLOCKS and (
                "http_200_origin" in values
            ):
                result.extend(values.get("http_200_origin", []))
            else:
                result.extend(values.get("origin", []))
        elif kind in {"url", "url-list"}:
            if str(tool.get("block", "")) in HTTP_VERIFIED_CONSUMER_BLOCKS and (
                "http_200_url" in values or "http_200_origin" in values
            ):
                result.extend(values.get("http_200_url", []))
                result.extend(values.get("http_200_origin", []))
            else:
                result.extend(values.get("url", []))
                result.extend(values.get("origin", []))
        elif kind == "url-with-parameter":
            source = values.get("http_200_url", []) if (
                str(tool.get("block", "")) in HTTP_VERIFIED_CONSUMER_BLOCKS and "http_200_url" in values
            ) else values.get("url", [])
            result.extend(value for value in source if "?" in value)
        elif kind == "ip":
            result.extend(values.get("ip", []))
        elif kind == "service":
            result.extend(values.get("service", []))
        elif kind in {"technology", "fingerprint"}:
            result.extend(values.get(kind, []))
    domain_only = str(tool["id"]) in DOMAIN_ONLY_TOOLS
    if domain_only:
        result = _domain_values(result)
    if not result:
        input_kinds = set(str(kind) for kind in tool["inputs"])
        # Only inputs that can be grounded in the operator target may use a
        # deterministic seed. A service, parameterized URL, technology,
        # fingerprint, or local artifact must be discovered/provided first;
        # substituting the target would create a false applicability claim.
        if "target" in input_kinds:
            result.append(target)
        elif input_kinds & {"host", "host-list"}:
            host_seed = target_domain_seed(target) if domain_only else target_host_seed(target)
            if host_seed:
                result.append(host_seed)
        elif "ip" in input_kinds:
            ip_seed = target_ip_seed(target)
            if ip_seed:
                result.append(ip_seed)
        elif "network-target-list" in input_kinds:
            result.extend(target_network_seeds(target))
        elif "service" in input_kinds:
            result.extend(target_service_seeds(target))
        elif "url-with-parameter" in input_kinds:
            result.extend(target_parameter_url_seeds(target))
        elif input_kinds & {"url", "url-list", "origin"}:
            result.extend(target_url_seeds(target))
    return list(dict.fromkeys(value for value in result if str(value).strip()))


def _input_digest(values: list[str], tool: dict[str, Any]) -> str:
    material = json.dumps({"tool": tool["id"], "inputs": sorted(values)}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()


def _native_ct(tool_id: str, target: str, timeout: int) -> tuple[str, dict[str, Any]]:
    host = target_domain_seed(target)
    if not host:
        raise ValueError("certificate transparency methods require a DNS name")
    if tool_id == "crtsh":
        url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{host}", "output": "json"})
    elif tool_id == "certspotter":
        url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode({"domain": host, "include_subdomains": "true", "expand": "dns_names"})
    else:
        raise KeyError(tool_id)
    request = urllib.request.Request(url, headers={"User-Agent": "Ah-Puch/2.0", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=max(1, timeout)) as response:
        body = response.read(10_000_000).decode("utf-8", errors="replace")
        return body, {"url": url, "status_code": int(getattr(response, "status", 0) or 0)}


def _http_records(tool_id: str, invocation: Invocation, text: str, outputs: list[str], status: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records, rejected = normalize_text(text, outputs, tool_id, invocation.label, status)
    if tool_id not in {"wget", "curl"}:
        return records, rejected
    statuses = [int(value) for value in _HTTP_STATUS_RE.findall(text)]
    requested = invocation.command[-1]
    observed_200 = 200 in statuses
    if tool_id == "curl":
        for line in text.splitlines():
            fields = line.split("\t")
            if fields and fields[0].isdigit():
                observed_200 = int(fields[0]) == 200
                if len(fields) > 1 and fields[1].startswith(("http://", "https://")):
                    requested = fields[1]
    if observed_200:
        extra, extra_rejected = normalize_text(requested, outputs, tool_id, invocation.label, status)
        by_key = {(row["kind"], row["value"]): row for row in records + extra}
        for row in by_key.values():
            row.setdefault("attributes", {})["status_code"] = 200
        return sorted(by_key.values(), key=lambda row: (row["kind"], row["value"])), rejected + extra_rejected
    records = [row for row in records if row.get("kind") not in {"url", "origin", "path", "parameter"}]
    rejected.append({"tool_id": tool_id, "source": invocation.label, "candidate": requested, "reason": f"http-status-not-200:{statuses[-1] if statuses else 'unknown'}"})
    return records, rejected


class PipelineCoordinator:
    def __init__(self, run: Any):
        self.run = run
        self.root = Path(run.root)
        self.args = run.args
        self.store = ResultStore(self.root)
        self.fan_in = FanIn(self.store)
        self.cache: dict[str, tuple[str, MethodResult]] = {}
        self.dictionary_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.all_records: dict[tuple[str, str], dict[str, Any]] = {}
        self.capability_plan = execution_plan(getattr(self.args, "integrated_capabilities", ""))

    @property
    def profile(self) -> str:
        return "deep" if str(self.args.pipeline_mode) == "all" else str(self.args.profile)

    def _dictionary_resolution(self, dictionary_class: str = "directory") -> dict[str, Any]:
        tool_options = getattr(self.run, "tool_option_overrides", {})
        directory_options = tool_options.get("dirsearch", {}) if isinstance(tool_options, dict) else {}
        tier = str(
            (directory_options.get("tier", "") if isinstance(directory_options, dict) else "")
            or getattr(self.args, "wordlist_tier", "micro")
        ).strip().lower() or "micro"
        configured_path = str(
            directory_options.get("wordlist", "") if isinstance(directory_options, dict) else ""
        ).strip()
        if getattr(self.args, "no_dictionaries", False):
            return {
                "class": dictionary_class,
                "requested_tier": tier,
                "effective_tier": tier,
                "tier_exact": False,
                "path": "",
                "available": False,
                "source": "disabled",
                "provenance": "runtime-disabled",
            }
        key = (dictionary_class, tier, configured_path if dictionary_class == "directory" else "")
        if key not in self.dictionary_cache:
            try:
                if dictionary_class == "directory" and configured_path:
                    self.dictionary_cache[key] = explicit_info("directory", configured_path, tier=tier)
                else:
                    self.dictionary_cache[key] = resolve_info(dictionary_class, tier=tier)
            except Exception as exc:
                self.dictionary_cache[key] = {
                    "class": dictionary_class,
                    "requested_tier": tier,
                    "effective_tier": tier,
                    "tier_exact": False,
                    "path": "",
                    "available": False,
                    "source": "error",
                    "provenance": f"{type(exc).__name__}: {exc}",
                }
        return dict(self.dictionary_cache[key])

    def _dictionary_receipt(self, tool: dict[str, Any]) -> dict[str, Any]:
        if "wordlist" not in {str(value) for value in tool.get("inputs", [])}:
            return {}
        resolution = self._dictionary_resolution("directory")
        return {
            "dictionary_class": resolution.get("class", "directory"),
            "dictionary_tier": resolution.get("effective_tier", resolution.get("requested_tier", "")),
            "dictionary_source": resolution.get("source", ""),
            "dictionary_path": resolution.get("path", ""),
            "dictionary_available": bool(resolution.get("available")),
            "dictionary_resolution": resolution,
        }

    def _plan(self, tool: dict[str, Any], input_values: list[str], command: tuple[str, ...] = ()) -> MethodPlan:
        status, reason = "planned", "eligible"
        contact = str(tool["contact"])
        credential_env = str(tool.get("credential_env", ""))
        uses_dictionary = "wordlist" in {str(value) for value in tool.get("inputs", [])}
        if contact in {"active", "active-explicit"} and (not self.args.active or self.args.passive):
            status, reason = "skipped", "active contact is not enabled"
        elif contact == "active-explicit" and (tool["id"] in EXPLICIT_TOOLS) and not self.args.allow_intrusive_validation:
            status, reason = "skipped", "--allow-intrusive-validation is required"
        elif tool["id"] == "zap_full" and not self.args.zap_active:
            status, reason = "skipped", "--zap-active is required"
        elif credential_env and not _credentials_present(credential_env):
            status, reason = "skipped", "required credential environment is absent"
        elif tool["adapter"] == "local-only" and not self.args.local_run:
            status, reason = "not-applicable", "no --local-run artifact was selected"
        elif uses_dictionary and getattr(self.args, "no_dictionaries", False):
            status, reason = "skipped", "dictionary routing disabled"
        elif uses_dictionary and not self._dictionary_resolution("directory").get("available"):
            status, reason = "unavailable", "directory dictionary unavailable"
        elif not input_values and tool["adapter"] in {"native-crtsh", "native-certspotter"}:
            status, reason = "not-applicable", "no DNS-name input is available"
        elif not input_values and tool["adapter"] not in {"native", "local-only"}:
            status, reason = "not-applicable", "no typed input is available"
        elif self.args.dry_run:
            status, reason = "planned", "dry-run: binary admission and target contact deferred"
        elif not tool["binary"] and tool["adapter"] not in {"native-crtsh", "native-certspotter"}:
            status, reason = "planned", "delegated to canonical native component"
        elif tool["binary"]:
            runner = inspect_runner(str(tool["runner_id"]))
            if not runner.get("available") or not runner.get("contract_ok"):
                status, reason = "unavailable", str(runner.get("reason", "runner contract unavailable"))
        return MethodPlan(
            str(tool["id"]), str(tool["runner_id"]), str(tool["block"]), status, reason,
            tuple(str(value) for value in tool["inputs"]), tuple(str(value) for value in tool["outputs"]),
            str(tool["adapter"]), contact, command,
        )

    def _terminal_without_contact(self, plan: MethodPlan) -> MethodResult:
        status = plan.status
        if status == "planned" and not self.args.dry_run:
            status = "partial"
        return MethodResult(plan, status, reason=plan.reason)

    def _run_invocation(self, invocation: Invocation, directory: Path) -> tuple[dict[str, Any], str, list[Path]]:
        suffix = invocation.label.replace("/", "-")
        stdout = directory / f"raw-{suffix}.stdout.txt"
        stderr = directory / f"raw-{suffix}.stderr.txt"
        result = run_bounded(list(invocation.command), directory, stdout, stderr, self.args.module_timeout, stdin_path=invocation.stdin_path)
        text = _safe_read(stdout) + "\n" + _safe_read(stderr)
        artifacts = [path for path in (stdout, stderr, invocation.native_artifact) if path.is_file()]
        native_text = ""
        if invocation.native_artifact.is_file():
            native_text = _safe_read(invocation.native_artifact)
        if native_text:
            text += "\n" + native_text
        elif text.strip() and invocation.native_artifact not in {stdout, stderr}:
            _write(invocation.native_artifact, text.strip() + "\n")
            artifacts.append(invocation.native_artifact)
        return result, text, list(dict.fromkeys(artifacts))

    def _execute_tool(self, tool: dict[str, Any], input_values: list[str], round_number: int) -> MethodResult:
        digest = _input_digest(input_values, tool)
        cached = self.cache.get(str(tool["id"]))
        if cached and cached[0] == digest:
            previous = cached[1]
            return MethodResult(previous.plan, previous.status, reason="reused: typed input digest unchanged", records=list(previous.records), rejected=list(previous.rejected), receipt={"input_sha256": digest, "reused": True}, human_lines=list(previous.human_lines))
        plan = self._plan(tool, input_values)
        dictionary_receipt = self._dictionary_receipt(tool)
        local_dry_run_execution = self.args.dry_run and str(tool["id"]) == "native_target_boundary"
        if plan.status != "planned" or (self.args.dry_run and not local_dry_run_execution):
            result = self._terminal_without_contact(plan)
            result.receipt.update({"input_sha256": digest, "input_count": len(input_values), "commands": []})
            result.receipt.update(dictionary_receipt)
            self.cache[str(tool["id"])] = (digest, result)
            return result
        method_dir = self.store.method_directory(str(tool["block"]), str(tool["id"]), round_number)
        method_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        input_file = method_dir / "input.txt"
        _write(input_file, "\n".join(input_values) + ("\n" if input_values else ""))
        native_artifacts: list[Path] = [input_file]
        records: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        runs: list[dict[str, Any]] = []
        text_parts: list[str] = []
        if str(tool["adapter"]).startswith("native") and tool["adapter"] not in {"native-crtsh", "native-certspotter"}:
            try:
                native_result = execute_native(tool, self.run, input_values, method_dir)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                result = MethodResult(plan, "failed", reason=error, receipt={"input_sha256": digest, "native": True, "error": error, **dictionary_receipt}, human_lines=[error], native_artifacts=[input_file])
                self.cache[str(tool["id"])] = (digest, result)
                return result
            result = MethodResult(
                plan,
                "clean-negative" if native_result.status == "success" and not native_result.records else native_result.status,
                reason=native_result.reason,
                records=native_result.records,
                rejected=native_result.rejected,
                receipt={"input_sha256": digest, "native": True, **native_result.receipt, **dictionary_receipt},
                human_lines=native_result.text.splitlines()[:200],
                native_artifacts=list(dict.fromkeys([input_file, *native_result.artifacts])),
            )
            self.cache[str(tool["id"])] = (digest, result)
            return result
        if tool["adapter"] in {"native-crtsh", "native-certspotter"}:
            native = method_dir / "native.json"
            try:
                text, receipt = _native_ct(str(tool["id"]), input_values[0], self.args.module_timeout)
                _write(native, text.rstrip() + "\n")
                native_artifacts.append(native)
                runs.append({"exit_code": 0, "timed_out": False, **receipt})
                accepted, refused = normalize_text(text, tool["outputs"], str(tool["id"]), native.name, "success")
                records.extend(accepted)
                rejected.extend(refused)
            except Exception as exc:  # urllib transports expose several concrete exception families
                runs.append({"exit_code": 1, "timed_out": False, "error": f"{type(exc).__name__}: {exc}"})
        else:
            binary = admitted_path(str(tool["runner_id"]))
            resolver_file = self.store.pipeline_root / "resolvers.txt"
            _write(resolver_file, "1.1.1.1\n8.8.8.8\n9.9.9.9\n")
            dictionary_info = self._dictionary_resolution("directory")
            wordlist = Path(str(dictionary_info["path"])) if dictionary_info.get("available") else Path("")
            # The adapter consumes the current in-memory fan-in, not a stale bus snapshot.
            adapter_inputs = getattr(self, "_current_values", {})
            invocations = build_invocations(
                tool, binary, self.run.target, adapter_inputs, input_file, method_dir,
                timeout=self.args.module_timeout, threads=self.args.threads, wordlist=wordlist,
                resolver_file=resolver_file, ports=self.args.range_ports, rate=self.args.range_rate,
                input_limit=self.args.pipeline_input_limit,
                local_run=Path(self.args.local_run).expanduser().resolve() if self.args.local_run else None,
                tool_options=getattr(self.run, "tool_option_overrides", {}),
            )
            if not invocations:
                result = MethodResult(
                    plan, "not-applicable", reason="adapter produced no applicable invocation",
                    receipt={"input_sha256": digest, "input_count": len(input_values), "commands": [], **dictionary_receipt},
                )
                self.cache[str(tool["id"])] = (digest, result)
                return result
            command_lines = [" ".join(invocation.command) for invocation in invocations]
            workers = min(max(1, self.args.pipeline_workers), len(invocations))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._run_invocation, invocation, method_dir): invocation for invocation in invocations}
                for future in as_completed(futures):
                    invocation = futures[future]
                    try:
                        run_receipt, text, artifacts = future.result()
                    except Exception as exc:
                        run_receipt, text, artifacts = ({"exit_code": 1, "timed_out": False, "error": f"{type(exc).__name__}: {exc}"}, "", [])
                    runs.append({"label": invocation.label, "command": list(invocation.command), **run_receipt})
                    text_parts.append(text)
                    native_artifacts.extend(artifacts)
                    terminal = "success" if run_receipt.get("exit_code") == 0 else ("timeout" if run_receipt.get("timed_out") else "partial")
                    accepted, refused = _http_records(str(tool["id"]), invocation, text, list(tool["outputs"]), terminal)
                    records.extend(accepted)
                    rejected.extend(refused)
        exit_codes = [int(row.get("exit_code", 1)) for row in runs]
        timed_out = any(bool(row.get("timed_out")) for row in runs)
        if runs and all(code == 0 for code in exit_codes):
            status = "success" if records else "clean-negative"
        elif timed_out and all(code == 124 for code in exit_codes):
            status = "timeout"
        elif runs:
            status = "partial" if records or any(code == 0 for code in exit_codes) else "failed"
        else:
            status = "failed"
        by_key = {(str(row.get("kind", "")), str(row.get("value", ""))): row for row in records if row.get("kind") and row.get("value")}
        result = MethodResult(
            plan, status, reason="completed bounded adapter execution" if status == "success" else "one or more adapter invocations did not complete successfully",
            records=sorted(by_key.values(), key=lambda row: (row["kind"], row["value"])), rejected=rejected,
            receipt={
                "input_sha256": digest,
                "input_count": len(input_values),
                "commands": command_lines,
                "runs": sorted(runs, key=lambda row: str(row.get("label", ""))),
                **dictionary_receipt,
            },
            human_lines=[line for text in text_parts for line in text.splitlines()[:200]], native_artifacts=list(dict.fromkeys(native_artifacts)),
        )
        self.cache[str(tool["id"])] = (digest, result)
        return result

    def _publish_to_bus(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        bus = artifact_bus.ArtifactBus(self.root, self.run.target)
        count = 0
        for row in records:
            if not row.get("promotable", True):
                continue
            kind, value = str(row.get("kind", "")), str(row.get("value", ""))
            observations = row.get("observations", []) if isinstance(row.get("observations"), list) else [row]
            for observation in observations:
                producer = f"typed-pipeline/{observation.get('tool_id', row.get('tool_id', 'unknown'))}"
                source = str(observation.get("source", row.get("source", "typed-pipeline")))
                status = str(observation.get("status", row.get("status", "success")))
                if status not in {"success", "partial"}:
                    continue
                within_target = True
                if kind in {"host", "ip", "service", "origin", "url", "path"}:
                    within_target = bool(self.run._allowed(value))
                attributes = observation.get("attributes", row.get("attributes", {}))
                if not isinstance(attributes, dict):
                    attributes = {}
                if kind == "url":
                    bus.observe_url_components(value, producer=producer, source=source, status=status, within_target=within_target, attributes=attributes)
                elif kind in artifact_bus.ARTIFACT_KINDS and kind != "path":
                    if bus.observe(kind, value, producer=producer, source=source, status=status, within_target=within_target, attributes=attributes):
                        count += 1
        summary = bus.save()
        return {"observations_added": count, **summary}

    def _http_phase_candidates(self, values: dict[str, list[str]]) -> list[str]:
        candidates = [*values.get("url", []), *values.get("origin", [])]
        return sorted({
            canonical
            for value in candidates
            if (canonical := artifact_bus.canonical_url(str(value)))
        })

    def _merge_http_phase_values(self, values: dict[str, list[str]], phase: str) -> int:
        before = len(values.get("http_200_url", [])) + len(values.get("http_200_origin", []))
        rows = read_jsonl(self.root / "http-reverification" / f"{phase}.jsonl")
        for row in rows:
            try:
                status = int(row.get("status", 0) or 0)
            except (TypeError, ValueError):
                status = 0
            if status != 200:
                continue
            for key in ("final_url", "requested_url"):
                url = artifact_bus.canonical_url(str(row.get(key, "")))
                if not url or not self.run._allowed(url):
                    continue
                values.setdefault("http_200_url", []).append(url)
                origin = artifact_bus.canonical_origin(url)
                if origin:
                    values.setdefault("http_200_origin", []).append(origin)
        for key in ("http_200_url", "http_200_origin"):
            values[key] = sorted(set(values.get(key, [])))
        after = len(values.get("http_200_url", [])) + len(values.get("http_200_origin", []))
        return after - before

    def _run_http_phase(self, phase: str, values: dict[str, list[str]]) -> dict[str, Any]:
        candidates = self._http_phase_candidates(values)
        active = bool(getattr(self.args, "active", False)) and not bool(getattr(self.args, "passive", False)) and not bool(getattr(self.args, "dry_run", False))
        summary = http_reverification.run_phase(
            self.root,
            phase,
            candidates,
            active=active,
            timeout=int(getattr(self.args, "module_timeout", 30)),
            threads=int(getattr(self.args, "threads", 4)),
            limit=int(getattr(self.args, "pipeline_input_limit", 32)),
            allow_url=self.run._allowed,
            verifier=str(getattr(self.args, "http_verifier", "all")),
        )
        summary["promoted_http_200_records"] = self._merge_http_phase_values(values, phase)
        return summary

    def run_pipeline(self) -> dict[str, Any]:
        mode = str(self.args.pipeline_mode)
        if mode == "off":
            return {"status": "skipped", "reason": "--pipeline-mode off"}
        values = _values_from_bus(self.root)
        values.setdefault("host", []).extend(getattr(self.run, "seed_hosts", []))
        values.setdefault("url", []).extend(getattr(self.run, "seed_urls", []))
        host_seed = target_host_seed(self.run.target)
        if host_seed:
            values.setdefault("host", []).append(host_seed)
        ip_seed = target_ip_seed(self.run.target)
        if ip_seed:
            values.setdefault("ip", []).append(ip_seed)
        values.setdefault("url", []).extend(target_url_seeds(self.run.target))
        values.setdefault("service", []).extend(target_service_seeds(self.run.target))
        for kind in values:
            values[kind] = sorted(set(values[kind]))
        ledger = ConvergenceLedger(self.store, self.args.recon_max_rounds)
        rounds = 1 if self.args.dry_run else self.args.recon_max_rounds
        summaries: list[dict[str, Any]] = []
        http_phases: list[dict[str, Any]] = []
        for round_number in range(1, rounds + 1):
            round_records: list[dict[str, Any]] = []
            self._current_values = values
            for block in EXECUTION_BLOCKS:
                selected_blocks = set(self.capability_plan.get("runtime_blocks", []))
                if self.capability_plan.get("selected") and block not in selected_blocks:
                    summaries.append({
                        "round": round_number,
                        "block": block,
                        "status": "not-selected",
                        "reason": "outside the selected integrated capability plan",
                    })
                    continue
                tools = inventory_tools(self.profile, block)
                if str(self.args.http_verifier) != "all":
                    verifier = str(self.args.http_verifier)
                    selected_http_tools = HTTP_VERIFIER_TOOL_IDS.get(verifier, set())
                    tools = [tool for tool in tools if tool["id"] not in ALL_HTTP_VERIFIER_TOOL_IDS or tool["id"] in selected_http_tools]
                if mode == "inventory":
                    tools = [tool for tool in tools if tool["id"] in {"native_target_boundary", "native_dns", "dig", "native_network", "nmap", "native_http", "httpx", "wget", "curl"}]
                expected = [str(tool["id"]) for tool in tools]
                tool_inputs = [(tool, _input_values(tool, values, self.run.target)) for tool in tools]
                tool_results: dict[str, MethodResult] = {}
                try:
                    requested_workers = int(getattr(self.args, "pipeline_workers", 4) or 4)
                except (TypeError, ValueError):
                    requested_workers = 4
                workers = max(1, min(16, requested_workers, len(tool_inputs))) if tool_inputs else 1
                # Methods in one block consume the same immutable evidence
                # snapshot and write separate method directories.  Run them
                # concurrently; the fan-in and phase barrier remain ordered
                # after every method has reached a terminal state.
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {
                        pool.submit(self._execute_tool, tool, inputs, round_number): (tool, inputs)
                        for tool, inputs in tool_inputs
                    }
                    for future in as_completed(futures):
                        tool, inputs = futures[future]
                        try:
                            result = future.result()
                        except Exception as exc:  # preserve a terminal receipt for one broken method
                            result = MethodResult(
                                self._plan(tool, inputs),
                                "failed",
                                reason=f"{type(exc).__name__}: {exc}",
                            )
                        tool_results[str(tool["id"])] = result
                for tool, _inputs in tool_inputs:
                    self.store.write(tool_results[str(tool["id"])], round_number)
                fan = self.fan_in.build(block, round_number, expected)
                barrier = write_barrier(self.store, block, round_number, expected, continue_on_partial=self.args.continue_on_partial)
                promoted = read_jsonl(Path(fan["output"]) / "verified_records.jsonl")
                _merge_values(values, promoted)
                round_records.extend(promoted)
                summaries.append({"round": round_number, "block": block, "fan_in": fan, "barrier": barrier, "parallel_workers": workers, "parallel_methods": len(tool_inputs)})
                if block in HTTP_PHASE_AFTER_BLOCK:
                    phase_summary = self._run_http_phase(HTTP_PHASE_AFTER_BLOCK[block], values)
                    http_phases.append({"round": round_number, "after_block": block, **phase_summary})
                if self.args.phase_barrier and not barrier["proceed"]:
                    payload = {"status": "failed", "reason": f"phase barrier stopped at {block}", "rounds": round_number, "blocks": summaries}
                    _write(self.store.pipeline_root / "summary.json", json.dumps(payload, indent=2, sort_keys=True) + "\n")
                    return payload
            for row in round_records:
                self.all_records[(str(row.get("kind", "")), str(row.get("value", "")))] = row
            convergence = ledger.observe(round_number, self.all_records.values())
            if self.args.dry_run or convergence["converged"]:
                break
        bus_summary = self._publish_to_bus(list(self.all_records.values())) if not self.args.dry_run else {"observations_added": 0}
        payload = {
            "status": "planned" if self.args.dry_run else "success",
            "profile": self.profile, "mode": mode, "rounds": len(ledger.rows),
            "converged": bool(ledger.rows and ledger.rows[-1]["converged"]),
            "records": len(self.all_records), "bus": bus_summary, "blocks": summaries,
            "http_reverification": http_phases,
            "integrated_capabilities": list(self.capability_plan.get("selected", [])),
            "selected_runtime_blocks": list(self.capability_plan.get("runtime_blocks", [])),
        }
        _write(self.store.pipeline_root / "summary.json", json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        _write(self.store.pipeline_root / "summary.txt", f"Status: {payload['status']}\nProfile: {self.profile}\nMode: {mode}\nRounds: {payload['rounds']}\nConverged: {str(payload['converged']).lower()}\nRecords: {payload['records']}\n")
        return payload
