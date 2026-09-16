#!/usr/bin/env python3
"""Production Ah-Puch runtime composition.

This module composes the accepted catalog runner, architecture-v2 target graph
layer, validated TCP/UDP profiles, resumable device discovery, verified TLS
identity feedback, all-origin advanced consumer fan-out, normalized inventories
and execution receipts. Historical standalone workflows are not embedded; their
useful contracts are expressed through native Ah-Puch stages and runner IDs.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

try:
    from . import http_inventory as http_inventory_module
    from . import runner_v2 as v2
    from .advanced_consumers import run as run_advanced_consumers
    from .device_runtime import analyze as analyze_device_runtime
    from .inventory_runtime import build_inventory as build_normalized_inventory, build_receipts, build_run_index
    from .network_runtime import run as run_network_profile
    from .runner_registry import inspect_runner, snapshot as snapshot_runners
    from .tls_inventory import collect as collect_tls_inventory
    from .advisory_store import map_inventory as map_advisory_inventory
    from .integrated_capability_runtime import run_selected as run_integrated_capabilities
    from .auth_validation import validate_once, write_result as write_auth_result
    from .device_followup_runtime import run as run_device_followup
    from .runtime_hardening import write_budget_artifact
except ImportError:
    import http_inventory as http_inventory_module
    import runner_v2 as v2
    from advanced_consumers import run as run_advanced_consumers
    from device_runtime import analyze as analyze_device_runtime
    from inventory_runtime import build_inventory as build_normalized_inventory, build_receipts, build_run_index
    from network_runtime import run as run_network_profile
    from runner_registry import inspect_runner, snapshot as snapshot_runners
    from tls_inventory import collect as collect_tls_inventory
    from advisory_store import map_inventory as map_advisory_inventory
    from integrated_capability_runtime import run_selected as run_integrated_capabilities
    from auth_validation import validate_once, write_result as write_auth_result
    from device_followup_runtime import run as run_device_followup
    from runtime_hardening import write_budget_artifact

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_V2_PARSER = v2.base.parser
_ORIGINAL_HTTPX_ENRICHMENT = http_inventory_module._httpx_enrichment


def parser() -> argparse.ArgumentParser:
    p = _V2_PARSER()
    p.add_argument("-no", "--no-advanced-consumers", action="store_true", help="disable target-origin Nikto/TLS/template/Wapiti/proxy/parameter consumers")
    p.add_argument("-col", "--consumer-origin-limit", type=int, default=12, metavar="N", help="maximum final-200 origins passed to advanced consumers")
    p.add_argument("-con", "--consumer-timeout", type=int, default=3600, metavar="SECONDS", help="per advanced-consumer upper timeout")
    p.add_argument("-zi", "--zap-image", default=os.environ.get("AH_PUCH_ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable"), metavar="IMAGE", help="local ZAP image name; Ah-Puch never pulls it during a live run")
    p.add_argument("-za", "--zap-active", action="store_true", help="allow the active local ZAP consumer in an active target run")
    p.add_argument("-mpt", "--max-parameter-targets", type=int, default=50, metavar="N", help="maximum target parameterized URLs passed to the detection consumer")
    p.add_argument("-dncp", "--device-network-chunk-prefix", type=int, default=0, metavar="PREFIX", help="CIDR prefix used for resumable device chunks; 0 selects /24 IPv4 or /120 IPv6")
    p.add_argument("-dnc", "--device-network-chunks", type=int, default=256, metavar="N", help="maximum device CIDR chunks processed in one invocation before resume")
    p.add_argument("-nti", "--no-tls-inventory", action="store_true", help="disable verified peer-certificate inventory for target HTTPS final origins")
    p.add_argument("-lr", "--local-run", metavar="RUN_DIR", help="existing saved run used by an explicitly selected local-only adapter")
    p.add_argument("-la", "--local-action", choices=("normalize", "seal", "verify", "advisory"), help="local-only adapter action; normally inferred from the selected module")
    p.add_argument("-pm", "--pipeline-mode", choices=("off", "inventory", "auto", "all"), default="auto", help="typed block pipeline: off, inventory, automatic profile, or every applicable method")
    p.add_argument("-at", "--all-tools", dest="pipeline_mode", action="store_const", const="all", help="run every applicable independent inventory method")
    p.add_argument("-rnr", "--recon-max-rounds", type=int, default=2, metavar="N", help="maximum typed recon convergence rounds")
    p.add_argument("-pb", "--phase-barrier", dest="phase_barrier", action="store_true", default=True, help="require every applicable method to reach terminal state before the next block")
    p.add_argument("-npb", "--no-phase-barrier", dest="phase_barrier", action="store_false", help="record barriers without stopping on an incomplete block")
    p.add_argument("-cop", "--continue-on-partial", dest="continue_on_partial", action="store_true", default=True, help="allow the next block after terminal failures or partial results")
    p.add_argument("-sop", "--stop-on-partial", dest="continue_on_partial", action="store_false", help="stop the pipeline when a method fails or is partial")
    p.add_argument("-pw", "--pipeline-workers", type=int, default=4, metavar="N", help="bounded concurrent method invocations within one block")
    p.add_argument("-pil", "--pipeline-input-limit", type=int, default=32, metavar="N", help="maximum typed inputs per external method invocation set")
    p.add_argument("-hv", "--http-verifier", choices=("all", "native", "wget", "curl", "httpx"), default="all", help="HTTP verification methods retained in the typed cycle")
    p.add_argument("-aiv", "--allow-intrusive-validation", action="store_true", help="explicitly admit SQLi, SSRF, XSS and NoSQL validation methods")
    p.add_argument("-icap", "--integrated-capabilities", dest="integrated_capabilities", default="", help="Ah-Puch integrated capabilities: complete-assessment,complete-web-evidence,subdomain-infrastructure,range-http-verification,industrial-protocol-followup,device-inventory,ssh-credential-audit,dictionary-corpus,advisory-correlation,knowledge-index,intelligence-catalog,complete-recon")
    p.add_argument("-iw", "--integrated-workers", type=int, default=4, metavar="N", help="bounded parallel workers for independent integrated capability adapters")
    p.add_argument("-ihw", "--integrated-http-workers", type=int, default=4, metavar="N", help="bounded parallel HTTP evidence workers inside integrated adapters")
    p.add_argument("-ipw", "--integrated-probe-workers", type=int, default=4, metavar="N", help="bounded parallel service/protocol follow-up workers")
    p.add_argument("-mp", "--range-paths", dest="range_paths", default="", metavar="FILE", help="path dictionary; defaults to the bundled 82-path range list")
    p.add_argument("-mmr", "--range-max-requests", dest="range_max_requests", type=int, default=4096, metavar="N", help="maximum range HTTP path requests")
    p.add_argument("-ix", "--ics-max-urls", type=int, default=64, metavar="N", help="maximum industrial URL candidates")
    p.add_argument("-imf", "--ics-max-followups", type=int, default=32, metavar="N", help="maximum industrial Nmap follow-ups")
    p.add_argument("-it", "--ics-timeout", type=int, default=10, metavar="SECONDS", help="industrial Nmap follow-up timeout")
    p.add_argument("-ks", "--knowledge-source", dest="knowledge_source", default="", metavar="DIR", help="override the bundled private knowledge corpus; index is metadata-only")
    p.add_argument("-ca", "--credential-audit", action="store_true", help="optional: explicitly enable the bounded SSH candidate credential audit")
    p.add_argument("-sau", "--ssh-audit-users", default="", metavar="FILE", help="authorized SSH audit identity dictionary")
    p.add_argument("-sap", "--ssh-audit-passwords", default="", metavar="FILE", help="authorized SSH audit password dictionary")
    p.add_argument("-saw", "--ssh-audit-workers", type=int, default=16, metavar="N", help="maximum concurrent SSH audit attempts")
    p.add_argument("-sam", "--ssh-audit-max-attempts", type=int, default=5000, metavar="N", help="maximum SSH candidate credential attempts")
    p.add_argument("-av", "--auth-validate", action="store_true", help="optional: validate exactly one supplied service credential pair; never required by normal runs")
    p.add_argument("-avs", "--auth-service", choices=("ssh", "http-basic"), default="ssh", help="service used by exact credential validation")
    p.add_argument("-au", "--auth-username", default="", metavar="USER", help="username for exact credential validation")
    p.add_argument("-ape", "--auth-password-env", default="", metavar="ENV_NAME", help="environment variable containing the exact validation password")
    return p


v2.base.parser = parser
v2.base.CORE_ENGINE = v2.base.ROOT / "engines" / "recon_core_v3.py"


def _guarded_httpx_enrichment(destination: Path, origins: list[str], timeout: int, options: dict | None = None) -> dict[str, dict]:
    row = inspect_runner("http_probe")
    if not row.get("available") or not row.get("contract_ok"):
        return {}
    return _ORIGINAL_HTTPX_ENRICHMENT(destination, origins, timeout, options)


http_inventory_module._httpx_enrichment = _guarded_httpx_enrichment


def _offline_advisory_projection(root: Path, store: str) -> dict:
    if not store:
        return {"status": "disabled", "observations": 0, "matches": 0}
    products: list[dict[str, str]] = []
    for relative in ("inventory/services.jsonl", "inventory/devices.jsonl"):
        path = root / relative
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            vendor = str(row.get("vendor", "") or ((row.get("vendors") or [""])[0] if isinstance(row.get("vendors"), list) else ""))
            product = str(row.get("product", "") or ((row.get("models") or [""])[0] if isinstance(row.get("models"), list) else ""))
            version = str(row.get("version", "") or row.get("firmware", ""))
            if vendor and product and version:
                products.append({"vendor": vendor, "product": product, "version": version})
    matches = map_advisory_inventory(Path(store).expanduser(), products)
    destination = root / "10-intelligence" / "advisory-matches.jsonl"
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in matches),
        encoding="utf-8",
    )
    destination.chmod(0o600)
    return {
        "status": "success",
        "observations": len(products),
        "matches": len(matches),
        "artifact": str(destination.relative_to(root)),
    }


def _selected_local_capability(args: argparse.Namespace) -> str:
    """Resolve a single local-only selector without constructing a target run."""
    selected = {value.strip() for value in str(args.catalog_modules or "").split(",") if value.strip()}
    by_id = {
        str(item["id"]): str(item.get("native_capability", ""))
        for item in v2.base.load_modules()
        if item.get("native_capability")
    }
    capabilities = {by_id[value] for value in selected if value in by_id}
    local = capabilities & {"runner-doctor", "normalize-report", "integrity", "advisory-mapping"}
    if not local:
        return ""
    if len(selected) != 1 or len(local) != 1:
        raise ValueError("local-only adapters must be selected one at a time")
    return next(iter(local))


def _run_local_capability(args: argparse.Namespace, capability: str) -> int:
    """Execute an explicitly local selector without target parsing or network stages."""
    if capability == "runner-doctor":
        destination = Path(args.output).expanduser().resolve()
        rows = snapshot_runners(destination)
        print(json.dumps({"capability": capability, "runners": len(rows), "artifact": "runner-registry/runners.json"}, sort_keys=True))
        return 0

    if not args.local_run:
        raise ValueError(f"{capability} requires --local-run")
    root = Path(args.local_run).expanduser().resolve()
    if not (root / "manifest.json").is_file():
        raise ValueError("--local-run must contain manifest.json")
    expected = {
        "normalize-report": "normalize",
        "integrity": "seal",
        "advisory-mapping": "advisory",
    }[capability]
    action = args.local_action or expected
    if action not in ({"seal", "verify"} if capability == "integrity" else {expected}):
        raise ValueError(f"{capability} does not support local action {action!r}")
    if capability == "normalize-report":
        inventory = build_normalized_inventory(root)
        receipts = build_receipts(root, "saved-run")
        result = {"capability": capability, "status": "success", "inventory": inventory, "receipts": receipts}
        v2.base.reseal_saved_run(root)
        rc = 0
    elif capability == "integrity":
        if action == "seal":
            v2.base.reseal_saved_run(root)
            rc = 0
        else:
            rc = v2.base.verify_integrity_artifacts(root)
        result = {"capability": capability, "action": action, "status": "success" if rc == 0 else "failed"}
    else:
        if not args.advisory_store:
            raise ValueError("advisory-mapping requires --advisory-store")
        result = {"capability": capability, **_offline_advisory_projection(root, args.advisory_store)}
        v2.base.reseal_saved_run(root)
        rc = 0 if result.get("status") == "success" else 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return rc


def _collect_urls(root: Path) -> list[str]:
    found: set[str] = set()
    consumer_root = root / "advanced-consumers"
    if not consumer_root.is_dir():
        return []
    for path in consumer_root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 20_000_000:
            continue
        if path.suffix.lower() not in {".txt", ".log", ".json", ".jsonl", ".csv", ".html", ".har"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found.update(value.rstrip(".,;:)]}") for value in URL_RE.findall(text))
    return sorted(found)


def _host_kind(value: str) -> str:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return "ip"
    except ValueError:
        return "hostname"


def _aggregate_status(counts: dict[str, int], *, enabled: bool, disabled_status: str = "skipped") -> str:
    if not enabled:
        return disabled_status
    # An enabled stage that emitted no observations did not complete.  Treat
    # it as explicit no-work/skipped so callers cannot turn an empty reducer
    # input into a false success.
    if not counts:
        return "skipped"
    failures = int(counts.get("failed", 0)) + int(counts.get("timeout", 0))
    partials = int(counts.get("partial", 0))
    successes = int(counts.get("success", 0))
    if failures and not successes and not partials:
        return "failed"
    if failures or partials:
        return "partial"
    # A run that emitted only gated/no-work rows did not produce a successful
    # observation. Preserve the explicit terminal class instead of falling
    # through to success merely because the mapping was non-empty.
    if not successes:
        if counts.get("skipped", 0):
            return "skipped"
        if counts.get("planned", 0):
            return "planned"
        return "skipped"
    return "success"


_PROFILE_STAGE_ENGINES: dict[str, frozenset[str]] = {
    "recon-dns": frozenset({"recon_core", "recon_core_v2"}),
    "http-inventory": frozenset({"http_inventory"}),
    "web-fanout": frozenset({"web_fanout"}),
    "tls-inventory": frozenset({"tls_inventory"}),
    "network-profile": frozenset({"network_profile_runtime"}),
    "device": frozenset({"device_surface"}),
    "template-assessment": frozenset({"advanced_consumers"}),
    "web-server-assessment": frozenset({"advanced_consumers"}),
    "secondary-web-audit": frozenset({"advanced_consumers"}),
    "proxy-passive": frozenset({"advanced_consumers"}),
    "proxy-active": frozenset({"advanced_consumers"}),
    "parameter-validation": frozenset({"advanced_consumers"}),
}
_PROFILE_STAGE_RUNNERS: dict[str, frozenset[str]] = {
    "template-assessment": frozenset({"template-checks"}),
    "web-server-assessment": frozenset({"web-server-check"}),
    "secondary-web-audit": frozenset({"web-audit-secondary"}),
    "proxy-passive": frozenset({"web-proxy-passive"}),
    "proxy-active": frozenset({"web-proxy-active"}),
    "parameter-validation": frozenset({"parameter-validation"}),
}


class ProductionUnifiedRun(v2.EnhancedUnifiedRun):
    def _network_allowed(self, value: str) -> bool:
        if "/" in self.target and str(value).strip() == str(self.target).strip():
            return True
        return self._allowed(value)

    def _tls_feedback(self) -> None:
        if self.args.no_tls_inventory:
            self.event({"engine": "tls_inventory", "status": "skipped", "reason": "--no-tls-inventory"})
            return
        active = bool(not self.args.dry_run and self.args.active and not self.args.passive)
        rows = collect_tls_inventory(
            self.root,
            [origin for origin in self.http_final_200 if origin.startswith("https://")],
            active=active,
            timeout=max(1, self.args.module_timeout),
            max_origins=max(1, self.args.http_inventory_limit),
            allow_origin=self._allowed,
        )
        promoted_hosts: set[str] = set()
        promoted_urls: set[str] = set()
        verified = 0
        errors = 0
        quarantined = 0
        for row in rows:
            row_status = str(row.get("status", ""))
            if row_status == "error":
                errors += 1
            if row_status == "quarantined":
                quarantined += 1
            if row_status != "verified":
                continue
            verified += 1
            origin = str(row.get("origin", ""))
            cert_id = str(row.get("certificate_sha256", "") or row.get("serial_number", ""))
            if origin and cert_id:
                self.graph.add_edge("origin", origin, "certificate_for", "certificate", cert_id, source="tls-inventory", depth=3, within_target=True)
            peer = str(row.get("peer_address", ""))
            if cert_id and peer:
                peer_allowed = self._network_allowed(peer)
                self.graph.add_edge("certificate", cert_id, "certificate_peer", "ip", peer, source="tls-inventory", depth=3, within_target=peer_allowed)
                if peer_allowed:
                    promoted_hosts.add(peer)
            for san in row.get("subject_alt_name", []):
                if not isinstance(san, dict):
                    continue
                san_type = str(san.get("type", ""))
                value = str(san.get("value", "")).strip()
                if not value or not cert_id:
                    continue
                if san_type == "URI" and value.startswith(("http://", "https://")):
                    allowed = self._allowed(value)
                    self.graph.add_edge("certificate", cert_id, "cert_san", "url", value, source="tls-inventory", depth=3, within_target=allowed)
                    if allowed:
                        promoted_urls.add(value)
                else:
                    allowed = self._network_allowed(value)
                    self.graph.add_edge("certificate", cert_id, "cert_san", _host_kind(value), value, source="tls-inventory", depth=3, within_target=allowed)
                    if allowed:
                        promoted_hosts.add(value)
        if promoted_hosts:
            self.seed_hosts = sorted(set(self.seed_hosts) | promoted_hosts)[: self.args.range_host_limit]
        if promoted_urls:
            self.seed_urls = v2.base.merge_ordered(self.seed_urls, sorted(promoted_urls))
            self.observed_urls = v2.base.merge_ordered(self.observed_urls, sorted(promoted_urls))
        if not active:
            stage_status = "planned" if self.args.dry_run else "skipped"
        elif errors:
            stage_status = "partial" if verified else "failed"
        else:
            stage_status = "success"
        self.event({"engine": "tls_inventory", "status": stage_status, "rows": len(rows), "verified": verified, "errors": errors, "quarantined": quarantined, "promoted_hosts": len(promoted_hosts), "promoted_urls": len(promoted_urls)})

    def run_auth_validation(self) -> None:
        """Run one explicitly approved credential check inside the target boundary."""
        selected_auth = (
            bool(self.args.auth_validate)
            or "device-auth" in self.native_capabilities
            or "device-auth" in set(self.integrated_native_stages or ())
        )
        if not selected_auth:
            return
        if not self.native_stage_enabled("device-auth"):
            self.event({"engine": "auth_validation", "status": "skipped", "reason": "native capability selection"})
            return
        if self.args.dry_run:
            self.event({"engine": "auth_validation", "status": "planned", "service": self.args.auth_service, "reason": "--dry-run; no credential was read"})
            return
        if not self.args.auth_validate:
            self.event({"engine": "auth_validation", "status": "skipped", "reason": "--auth-validate is required"})
            return
        if not self.args.active or self.args.passive:
            self.event({"engine": "auth_validation", "status": "skipped", "reason": "active mode is required"})
            return
        username = str(self.args.auth_username or "")
        password_env = str(self.args.auth_password_env or "")
        password = os.environ.get(password_env, "") if password_env else ""
        if not username or not password_env or not password:
            self.event({"engine": "auth_validation", "status": "failed", "reason": "--auth-username and --auth-password-env with a populated environment variable are required"})
            return
        if self.args.auth_service == "ssh" and "/" in self.target:
            self.event({"engine": "auth_validation", "status": "failed", "reason": "SSH credential validation requires one host, not a CIDR target"})
            return
        target = self.target if self.args.auth_service == "http-basic" else v2.base.target_authority(self.target)
        host = v2.base.target_host(self.target)
        if not self._network_allowed(host):
            self.event({"engine": "auth_validation", "status": "failed", "reason": "target is outside the automatic network boundary"})
            return
        try:
            result = validate_once(self.args.auth_service, target, username, password, timeout=min(60, max(1, self.args.module_timeout)))
            result.update({"target": target, "username": username, "password_env": password_env})
            artifact = write_auth_result(self.root, result)
            self.event({"engine": "auth_validation", "status": "success" if result.get("success") else "failed", "service": self.args.auth_service, "result": result.get("status"), "artifact": str(artifact.relative_to(self.root))})
        except (OSError, ValueError, TypeError) as exc:
            self.event({"engine": "auth_validation", "status": "failed", "error": f"{type(exc).__name__}: {exc}"})

    def run_native(self) -> None:
        selected_mode = self.args.range_mode
        if selected_mode == "full-tcp-udp":
            self.args.range_mode = "full-tcp"
        try:
            super().run_native()
        finally:
            self.args.range_mode = selected_mode

        if self.native_stage_enabled("tls-inventory"):
            self._tls_feedback()
        else:
            self.event({"engine": "tls_inventory", "status": "skipped", "reason": "native capability selection"})

        network_selected = self.native_stage_enabled("network-profile")
        network_enabled = bool(
            network_selected
            and
            not self.args.dry_run
            and self.args.active
            and not self.args.passive
        )
        network = run_network_profile(
            self.root, self.target, dict(self.network_profile), active=network_enabled,
            rate=max(1, self.args.range_rate), host_limit=max(1, self.args.range_host_limit),
            timeout=max(60, self.args.native_timeout), allow_target=self._network_allowed,
            tool_options=self.tool_option_overrides,
        ) if network_selected else {"runs": 0, "statuses": {"skipped": 1}, "reason": "native capability selection"}
        self.event({"engine": "network_profile_runtime", "status": _aggregate_status(network.get("statuses", {}), enabled=network_enabled, disabled_status="planned" if network_selected else "skipped"), **network})

        advanced_selected = self.native_stage_enabled(
            "template-assessment", "web-server-assessment", "secondary-web-audit",
            "proxy-passive", "proxy-active", "parameter-validation",
        )
        enabled = bool(
            advanced_selected
            and
            not self.args.no_advanced_consumers
            and not self.args.dry_run
            and self.args.active
            and not self.args.passive
            and (
                self.args.profile in {"full", "deep"}
                or bool(self.native_capabilities & {
                    "template-assessment", "web-server-assessment", "secondary-web-audit",
                    "proxy-passive", "proxy-active", "parameter-validation",
                })
            )
        )
        result = run_advanced_consumers(
            self.root,
            list(self.http_final_200),
            enabled=enabled,
            profile=self.args.profile,
            timeout=max(1, min(self.args.consumer_timeout, self.args.native_timeout)),
            max_origins=max(1, self.args.consumer_origin_limit),
            zap_image=self.args.zap_image,
            zap_active=bool(self.args.zap_active),
            max_sqlmap_targets=max(0, self.args.max_parameter_targets),
            allow_origin=self._allowed,
            tool_options=self.tool_option_overrides,
            selected_consumers=self.selected_advanced_consumers(),
        ) if advanced_selected else {"origins": 0, "runs": 0, "statuses": {"skipped": 1}, "reason": "native capability selection"}
        self.event({"engine": "advanced_consumers", "status": _aggregate_status(result.get("statuses", {}), enabled=enabled), **result})
        if enabled:
            promoted = [url for url in _collect_urls(self.root) if self._allowed(url)]
            if promoted:
                self.seed_urls = v2.base.merge_ordered(self.seed_urls, promoted)
                self.observed_urls = v2.base.merge_ordered(self.observed_urls, promoted)
                for url in promoted:
                    self.graph.ingest_url(url, "advanced-consumers", depth=3)
        self.run_auth_validation()

    def run_camera_surface(self) -> None:
        if self.args.no_camera:
            self.event({"engine": "device_surface", "status": "skipped", "reason": "--no-camera-analysis"})
            return
        if self.args.dry_run:
            self.event({
                "engine": "device_surface",
                "status": "planned",
                "reason": "--dry-run",
                "port_profile": self.args.device_port_profile,
                "model_filter": self.args.device_model,
                "network_chunks": max(1, self.args.device_network_chunks),
            })
            return
        try:
            selected = self.native_capabilities
            if "device-resume" in selected and not self.args.device_resume:
                self.event({"engine": "device_surface", "status": "failed", "reason": "device-resume requires a checkpoint"})
                return
            probe_mode = "web" if selected == {"device-web"} else ("stream" if selected == {"device-stream"} else "all")
            port_profile = self.args.device_port_profile
            custom_ports = self.args.device_custom_ports
            if probe_mode == "web":
                port_profile, custom_ports = "custom", "80,443,8000,8080,8081,8443"
            elif probe_mode == "stream":
                port_profile, custom_ports = "custom", "322,554,7441,8322,8554"
            active_device = bool(self.args.active and not self.args.passive and "device-report" not in selected)
            technology = bool(not self.args.no_device_tech and (not selected or "device" in selected or "device-technology" in selected or selected & {"profile-full", "profile-deep"}))
            resume = Path(self.args.device_resume).expanduser().resolve() if self.args.device_resume else None
            result = analyze_device_runtime(
                self.root,
                self.target,
                active=active_device,
                timeout=self.args.module_timeout,
                max_hosts=self.args.range_host_limit,
                port_profile=port_profile,
                custom_ports=custom_ports,
                model_filter=self.args.device_model,
                vendor_filter=self.args.device_vendor,
                resume_state=resume,
                technology_enrichment=technology,
                workers=self.args.device_workers,
                allow_target=self._network_allowed,
                scan_rate=max(1, self.args.range_rate),
                chunk_prefix=self.args.device_network_chunk_prefix,
                chunk_limit=max(1, self.args.device_network_chunks),
                connect_timeout=self.args.device_connect_timeout,
                session_timeout=self.args.device_session_timeout,
                retries=self.args.device_retries,
                run_tags=[value.strip() for value in self.args.device_run_tags.split(",") if value.strip()],
                export_mode=self.args.device_export_mode,
                egress_label=self.args.device_egress_label,
                device_data_path=Path(self.args.device_data).expanduser() if self.args.device_data else None,
                probe_mode=probe_mode,
            )
            self.seed_urls = v2.base.merge_ordered(self.seed_urls, [url for url in result.get("urls", []) if self._allowed(url)])
            self.seed_hosts = sorted(set(self.seed_hosts + [host for host in result.get("hosts", []) if self._network_allowed(host)]))[: self.args.range_host_limit]
            self.integrate_camera_queue(result.get("endpoints", []))
            for host in result.get("hosts", []):
                if self._network_allowed(host):
                    self.graph.ingest_host(host, "device-surface", depth=2)
            for url in result.get("urls", []):
                if self._allowed(url):
                    self.graph.ingest_url(url, "device-surface", depth=2)
            for row in result.get("inventory", []):
                host = str(row.get("host", ""))
                port = row.get("port")
                if host and port and self._network_allowed(host):
                    host_kind = "ip" if v2._is_ip(host) else "hostname"
                    service = f"{host}:{port}/{row.get('protocol', 'tcp')}"
                    self.graph.add_edge(host_kind, host, "service_on", "service", service, source="device-surface", depth=3)
                    for model in row.get("models", []):
                        self.graph.add_edge("service", service, "device_fingerprint", "device", str(model), source="device-surface", depth=3)
            summary = result.get("summary", {})
            status = "partial" if summary.get("device_network_complete") is False else "success"
            self.event({"engine": "device_surface", "status": status, **summary})
            device_followup = run_device_followup(
                self.root,
                self.target,
                result,
                active=active_device,
                dry_run=bool(self.args.dry_run),
                timeout=self.args.module_timeout,
                allow_target=self._network_allowed,
                max_targets=self.args.range_host_limit,
            )
            self.event({"engine": "device_followup", "status": device_followup.get("status", "failed"), "fingerprint_evidence": device_followup.get("fingerprint_evidence", 0), "eligible_endpoints": len(device_followup.get("eligible_endpoints", [])), "probed_endpoints": device_followup.get("probed_endpoints", 0), "artifact": "device-followup/summary.json"})
        except Exception as exc:
            self.event({"engine": "device_surface", "status": "failed", "error": f"{type(exc).__name__}: {exc}"})

    def _emit_profile_stage_terminals(self) -> None:
        """Record one terminal status for every stage declared by a profile."""
        priority = {"failed": 6, "timeout": 5, "partial": 4, "skipped": 3, "planned": 2, "success": 1}
        profile_capabilities = {"profile-baseline", "profile-full", "profile-deep"}
        for capability in sorted(self.native_capabilities & profile_capabilities):
            stages = v2.base.PROFILE_STAGE_MATRIX.get(capability, frozenset())
            for stage in sorted(stages):
                engines = _PROFILE_STAGE_ENGINES.get(stage, frozenset())
                statuses: list[str] = []
                runner_ids = _PROFILE_STAGE_RUNNERS.get(stage, frozenset())
                if runner_ids:
                    ledger = self.root / "advanced-consumers" / "runs.jsonl"
                    try:
                        for line in ledger.read_text(encoding="utf-8").splitlines():
                            row = json.loads(line)
                            if str(row.get("runner", "")) in runner_ids:
                                statuses.append(str(row.get("status", "unknown")))
                    except (OSError, json.JSONDecodeError):
                        statuses = []
                if not statuses:
                    statuses = [
                        str(row.get("status", "unknown"))
                        for row in self.events
                        if engines and row.get("engine") in engines
                    ]
                status = max(statuses, key=lambda value: priority.get(value, 7)) if statuses else "skipped"
                self.event({
                    "engine": "profile_stage_terminal",
                    "profile": capability,
                    "stage": stage,
                    "status": status,
                    "evidence_engines": sorted(engines),
                    "evidence_events": len(statuses),
                })

    def finish(self) -> int:
        integrated = run_integrated_capabilities(self)
        if integrated.get("status") != "not-selected":
            self.event({"engine": "integrated_capabilities", **integrated, "artifact": "integrated-capabilities/summary.json"})
        terminal_engines = {
            "device": {"device_surface"}, "device-fingerprint": {"device_surface"},
            "device-resume": {"device_surface"}, "device-web": {"device_surface"},
            "device-stream": {"device_surface"}, "device-technology": {"device_surface"},
            "device-report": {"device_surface"},
            "device-auth": {"auth_validation"},
            "recon-dns": {"recon_core_v2", "recon_core"},
            "http-inventory": {"http_inventory"}, "web-fanout": {"web_fanout"},
            "network-profile": {"network_profile_runtime"}, "tls-inventory": {"tls_inventory"},
            "template-assessment": {"advanced_consumers"},
            "web-server-assessment": {"advanced_consumers"},
            "secondary-web-audit": {"advanced_consumers"}, "proxy-passive": {"advanced_consumers"},
            "proxy-active": {"advanced_consumers"}, "parameter-validation": {"advanced_consumers"},
            "profile-baseline": {"recon_core_v2", "http_inventory", "web_fanout", "tls_inventory"},
            "profile-full": {"recon_core_v2", "http_inventory", "web_fanout", "tls_inventory", "network_profile_runtime", "device_surface", "advanced_consumers"},
            "profile-deep": {"recon_core_v2", "http_inventory", "web_fanout", "tls_inventory", "network_profile_runtime", "device_surface", "advanced_consumers"},
        }
        priority = {"failed": 6, "timeout": 5, "partial": 4, "skipped": 3, "planned": 2, "success": 1}
        for capability in sorted(self.native_capabilities):
            engines = terminal_engines.get(capability)
            if not engines:
                continue
            statuses = [str(row.get("status", "unknown")) for row in self.events if row.get("engine") in engines]
            status = max(statuses, key=lambda value: priority.get(value, 7)) if statuses else "failed"
            self.event({
                "engine": "native_capability_terminal", "capability": capability,
                "component": v2.base.native_capability_component(capability), "status": status,
                "evidence_engines": sorted(engines), "evidence_events": len(statuses),
            })
        self._emit_profile_stage_terminals()
        rc = super().finish()
        inventory = build_normalized_inventory(self.root)
        try:
            advisory = _offline_advisory_projection(self.root, self.args.advisory_store)
        except (OSError, ValueError) as exc:
            advisory = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            rc = max(rc, 1)
        receipts = build_receipts(self.root, self.target)
        self.event({"engine": "normalized_inventory", "status": "success", **inventory})
        self.event({"engine": "advisory_mapping", **advisory})
        self.event({"engine": "execution_receipts", "status": "success", **receipts})
        run_index = build_run_index(self.root, self.target)
        self.event({"engine": "run_index", "status": "success", **run_index})
        budget_path = write_budget_artifact(self.root, self.execution_budget, phase="post-finish")
        budget = self.execution_budget.snapshot()
        self.event({
            "engine": "execution_budget",
            "status": "success" if budget["status"] == "ok" else "partial",
            "limits": budget["limits"],
            "counts": budget["counts"],
            "exhausted_by": budget["exhausted_by"],
            "artifact": str(budget_path.relative_to(self.root)),
        })
        v2.base.reseal_saved_run(self.root)
        return rc


v2.base.UnifiedRun = ProductionUnifiedRun


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        parsed = parser().parse_args(raw)
        local_capability = _selected_local_capability(parsed)
        if local_capability:
            return _run_local_capability(parsed, local_capability)
    except ValueError as exc:
        parser().error(str(exc))
    return v2.main(raw)


if __name__ == "__main__":
    raise SystemExit(main())
