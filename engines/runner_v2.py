#!/usr/bin/env python3
"""Ah-Puch architecture-v2 integration layer.

The stable runner remains the catalog/CLI base. This layer adds typed asset
feedback, canonical HTTP status routing, all-origin content fan-out, device
checkpoint/inventory behavior, auxiliary runner contracts and protected
sensitive evidence without duplicating the accepted catalog implementation. The
operator target is the complete execution boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from . import runner as base
    from .asset_graph import AssetGraph, host_within_target, url_within_target
    from .cdn_origin import collect_candidates as collect_origin_candidates, validate_target_candidates as validate_origin_candidates
    from .device_surface_v2 import analyze as analyze_device_surface
    from .http_inventory import build_inventory
    from .range_profiles import DEFAULT_UDP, plan as network_plan, write_plan as write_network_plan
    from .reverse_feedback import build as build_reverse_feedback
    from .runner_registry import admitted_path, inventory_snapshot, planned_snapshot, run_bounded, snapshot as snapshot_runners
    from .sensitive_evidence import collect as collect_sensitive
    from .storage_guard import write_report as storage_report
    from .web_fanout import run_all_origins
except ImportError:
    import runner as base
    from asset_graph import AssetGraph, host_within_target, url_within_target
    from cdn_origin import collect_candidates as collect_origin_candidates, validate_target_candidates as validate_origin_candidates
    from device_surface_v2 import analyze as analyze_device_surface
    from http_inventory import build_inventory
    from range_profiles import DEFAULT_UDP, plan as network_plan, write_plan as write_network_plan
    from reverse_feedback import build as build_reverse_feedback
    from runner_registry import admitted_path, inventory_snapshot, planned_snapshot, run_bounded, snapshot as snapshot_runners
    from sensitive_evidence import collect as collect_sensitive
    from storage_guard import write_report as storage_report
    from web_fanout import run_all_origins

_ORIGINAL_PARSER = base.parser
base.CORE_ENGINE = base.ROOT / "engines" / "recon_core_v2.py"


def parser() -> argparse.ArgumentParser:
    p = _ORIGINAL_PARSER()
    p.add_argument(
        "-am",
        "--authorization-manifest",
        default="",
        metavar="JSON",
        help="optional hash-bound scope policy; not required for a target-only run and can only narrow the automatic boundary",
    )
    p.add_argument("-hil", "--http-inventory-limit", type=int, default=128, metavar="N", help="maximum candidate origins in the canonical HTTP inventory")
    p.add_argument("-wfl", "--web-fanout-limit", type=int, default=32, metavar="N", help="maximum final-200 origins passed to all-origin content runners")
    p.add_argument("-hrl", "--http-reverify-limit", type=int, default=200, metavar="N", help="maximum discovered URLs re-observed per post-crawl and post-content phase")
    p.add_argument("-nwf", "--no-web-fanout", action="store_true", help="disable architecture-v2 all-origin crawl/directory/technology fan-out")
    p.add_argument("-dpp", "--device-port-profile", choices=("quick", "standard", "comprehensive", "all", "custom"), default="quick")
    p.add_argument("-dcp", "--device-custom-ports", default="", metavar="PORTS", help="comma/range expression used with --device-port-profile custom")
    p.add_argument("-dm", "--device-model", default="", metavar="MODEL", help="retain normalized device inventory rows matching this model substring")
    p.add_argument("-dv", "--device-vendor", default="", metavar="VENDOR", help="retain normalized device inventory rows matching this vendor substring")
    p.add_argument("-dr", "--device-resume", default="", metavar="STATE_OR_RUN", help="resume device probing from a prior Ah-Puch device state/run")
    p.add_argument("-dw", "--device-workers", type=int, default=24, metavar="N", help="bounded device probe worker count")
    p.add_argument("-dct", "--device-connect-timeout", type=float, default=3.0, metavar="SECONDS", help="per-attempt device connection/probe timeout")
    p.add_argument("-dst", "--device-session-timeout", type=int, default=900, metavar="SECONDS", help="total device workflow deadline")
    p.add_argument("-de", "--device-retries", type=int, default=1, metavar="N", help="bounded retry count per device endpoint")
    p.add_argument("-drt", "--device-run-tags", default="", metavar="TAG[,TAG]", help="non-secret operator metadata stored with device checkpoints")
    p.add_argument("-dem", "--device-export-mode", choices=("redacted", "evidence"), default="redacted", help="redacted omits raw device bodies/headers; evidence keeps private 0600 probe evidence")
    p.add_argument("-del", "--device-egress-label", default="", metavar="LABEL", help="metadata-only egress profile label; never changes networking")
    p.add_argument("-dd", "--device-data", default="", metavar="NORMALIZED_JSON", help="private normalized fingerprint/port/path data produced by the native importer")
    p.add_argument("-idd", "--import-device-data", action="append", default=[], metavar="JSON|JSONL|TSV", help="import local device rule/data; repeat for multiple sources, then exit")
    p.add_argument("-ddo", "--device-data-output", default="", metavar="NORMALIZED_JSON", help="destination used with --import-device-data")
    p.add_argument("-ddp", "--device-data-provenance", default="", metavar="LABEL", help="logical non-path provenance label for imported device data")
    p.add_argument("-ia", "--import-advisories", default="", metavar="JSON|JSONL", help="import a local advisory corpus into an offline store, then exit")
    p.add_argument("-as", "--advisory-store", default="", metavar="DIRECTORY", help="offline advisory store used for import or passive version mapping")
    p.add_argument("-ndt", "--no-device-tech", action="store_true", help="disable optional device technology enrichment")
    p.add_argument("-rm", "--range-mode", choices=("quick", "standard", "full-tcp", "full-tcp-udp", "custom"), default="quick")
    p.add_argument("-rcp", "--range-custom-ports", default="", metavar="PORTS", help="TCP expression for --range-mode custom")
    p.add_argument("-rup", "--range-udp-ports", default=DEFAULT_UDP, metavar="PORTS", help="explicit bounded UDP expression used by full-tcp-udp")
    p.add_argument("-rd", "--runner-doctor", action="store_true", help="record registered auxiliary runner path/version/hash/help contracts and exit")
    p.add_argument("-nrf", "--no-reverse-feedback", action="store_true", help="disable bounded PTR feedback for explicitly eligible IP observations")
    p.add_argument("-noc", "--no-origin-candidates", action="store_true", help="disable passive CDN/fronting origin candidate collection")
    return p


base.parser = parser


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _run_udp_profile(run: "EnhancedUnifiedRun") -> dict[str, Any]:
    if run.args.range_mode != "full-tcp-udp":
        return {"status": "not-selected"}
    if not run.args.active or run.args.passive:
        return {"status": "skipped", "reason": "active mode required"}
    nmap = admitted_path("network_service")
    if not nmap:
        return {"status": "skipped", "reason": "nmap unavailable"}
    destination = run.root / "network-udp"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = destination / "udp.grep.txt"
    command = [nmap, "-Pn", "-n", "-sU", "--open", "-p", run.args.range_udp_ports, "-oG", str(output), run.target]
    result = run_bounded(command, destination, destination / "console.txt", destination / "stderr.txt", min(run.args.native_timeout, 900))
    return {
        "status": "success" if result["exit_code"] == 0 else ("timeout" if result["timed_out"] else "partial"),
        **result,
        "artifact": str(output.relative_to(run.root)) if output.exists() else "",
    }


def _load_sensitive_values(root: Path) -> list[tuple[str, str]]:
    path = root / "sensitive" / "findings.jsonl"
    values: list[tuple[str, str]] = []
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        value = str(row.get("value", ""))
        digest = str(row.get("sha256", ""))
        if value:
            values.append((value, digest or hashlib.sha256(value.encode()).hexdigest()))
    return sorted(set(values), key=lambda item: len(item[0]), reverse=True)


def _redact_general_outputs(root: Path) -> int:
    values = _load_sensitive_values(root)
    if not values:
        return 0
    changed = 0
    candidates: set[Path] = set()
    candidates.update(root.rglob("*.combined.txt"))
    candidates.update(root.rglob("*.console.txt"))
    candidates.update(root.rglob("*.stdout.txt"))
    candidates.update(root.rglob("*.stderr.txt"))
    candidates.update(root.glob("*.summary.txt"))
    candidates.update(root.glob("*.summary.json"))
    candidates.update(root.glob("*.txt-index.tsv"))
    candidates.update({root / "module_status.json", root / "module_status.jsonl", root / "manifest.json"})
    for path in sorted(candidates):
        if not path.is_file() or "sensitive" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        redacted = text
        for value, digest in values:
            redacted = redacted.replace(value, f"[REDACTED:{digest[:12]}]")
        if redacted != text:
            path.write_text(redacted, encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass
            changed += 1
    return changed


class EnhancedUnifiedRun(base.UnifiedRun):
    def __init__(self, target: str, args: argparse.Namespace):
        self.network_profile = network_plan(args.range_mode, args.range_custom_ports, args.range_udp_ports)
        args.range_ports = str(self.network_profile["tcp_ports"])
        super().__init__(target, args)
        # Internal target filtering is automatic. Hostnames include their
        # subdomains, IPs remain exact, and CIDRs remain inside their network.
        self.boundary_mode = "domain"
        self.graph = AssetGraph(self.target, boundary_mode=self.boundary_mode, max_depth=6, max_nodes=max(1000, args.range_host_limit * 20))
        self.observed_urls: list[str] = list(self.seed_urls)
        self.http_final_200: list[str] = []
        self.graph.ingest_host(base.target_host(self.target), "operator-target", depth=0)
        for value in self.seed_urls:
            self.graph.ingest_url(value, "operator-target", depth=0)
        write_network_plan(self.root, self.network_profile)

    def _allowed(self, value: str) -> bool:
        if value.startswith(("http://", "https://")):
            return url_within_target(value, self.target, self.boundary_mode)
        return host_within_target(value, self.target, self.boundary_mode)

    def _filter_promoted_assets(self) -> None:
        self.seed_hosts = sorted({host for host in self.seed_hosts if self._allowed(host)})[: self.args.range_host_limit]
        self.seed_urls = base.merge_ordered([], [url for url in self.seed_urls if self._allowed(url)])

    def execute(self) -> int:
        return super().execute()

    def _reverse_feedback(self) -> None:
        if self.args.no_reverse_feedback:
            return
        ips = [host for host in self.seed_hosts if _is_ip(host)]
        rows = build_reverse_feedback(
            self.root,
            ips,
            active=not self.args.dry_run,
            allow_ip=self._allowed,
            allow_name=self._allowed,
            timeout=min(2.0, float(self.args.module_timeout)),
            limit=min(self.args.range_host_limit, 128),
        )
        promoted: set[str] = set()
        for row in rows:
            ip = str(row.get("ip", ""))
            for name in row.get("ptr", []):
                allowed = self._allowed(str(name))
                self.graph.add_edge("ip", ip, "ptr_to", "hostname", str(name), source="reverse-feedback", depth=2, within_target=allowed)
            promoted.update(str(name) for name in row.get("promoted", []))
        if promoted:
            self.seed_hosts = sorted(set(self.seed_hosts) | promoted)[: self.args.range_host_limit]
        self.event({"engine": "reverse_feedback", "status": "success", "ips": len(ips), "rows": len(rows), "promoted": len(promoted)})

    def _origin_feedback(self) -> None:
        if self.args.no_origin_candidates:
            return
        candidates = collect_origin_candidates(self.root, self.target, [host for host in self.seed_hosts if _is_ip(host)])
        root_host = base.target_host(self.target)
        root_kind = "ip" if _is_ip(root_host) else "hostname"
        for candidate in candidates:
            ip = str(candidate.get("ip", ""))
            if ip:
                self.graph.add_edge(
                    root_kind,
                    root_host,
                    "origin_candidate",
                    "cdn-origin-candidate",
                    ip,
                    source="cdn-origin",
                    depth=2,
                    within_target=self._allowed(ip),
                )
        validation = validate_origin_candidates(
            self.root,
            self.target,
            candidates,
            active=bool(self.args.active and not self.args.passive),
            allow_ip=self._allowed,
            timeout=min(3.0, float(self.args.module_timeout)),
            limit=10,
        )
        confirmed = {
            str(row.get("ip"))
            for row in validation
            if row.get("validated") and self._allowed(str(row.get("ip", "")))
        }
        if confirmed:
            self.seed_hosts = sorted(set(self.seed_hosts) | confirmed)[: self.args.range_host_limit]
        self.event(
            {
                "engine": "cdn_origin",
                "status": "success",
                "candidates": len(candidates),
                "validated": len([row for row in validation if row.get("validated")]),
                "promoted": len(confirmed),
            }
        )

    def run_native(self) -> None:
        if self.native_stage_enabled("recon-dns"):
            super().run_native()
        else:
            self.event({"engine": "recon_core", "status": "skipped", "reason": "native capability selection"})
        self._filter_promoted_assets()
        for host in self.seed_hosts:
            self.graph.ingest_host(host, "core", depth=1)
        for url in self.seed_urls:
            self.graph.ingest_url(url, "core", depth=1)
        if self.native_stage_enabled("recon-dns"):
            self._reverse_feedback()
            self._origin_feedback()
        self._filter_promoted_assets()
        self.observed_urls = base.merge_ordered(self.observed_urls, list(self.seed_urls))
        if self.args.dry_run:
            return
        inventory_enabled = self.native_stage_enabled(
            "http-inventory", "web-fanout", "template-assessment", "web-server-assessment",
            "secondary-web-audit", "proxy-passive", "proxy-active", "parameter-validation",
        )
        if not inventory_enabled:
            self.event({"engine": "http_inventory", "status": "skipped", "reason": "native capability selection"})
            inventory = {"rows": [], "origins": [], "final_200": [], "httpx_enriched": 0}
        else:
            inventory = build_inventory(
            self.root,
            self.target,
            self.seed_hosts,
            self.observed_urls,
            active=bool(self.args.active and not self.args.passive),
            timeout=self.args.module_timeout,
            boundary_mode=self.boundary_mode,
            max_origins=max(1, self.args.http_inventory_limit),
            allow_target=self._allowed,
            tool_options=self.tool_option_overrides,
            )
        for row in inventory["rows"]:
            origin = str(row.get("origin", ""))
            final_url = str(row.get("final_url", ""))
            if origin:
                self.graph.ingest_url(origin, "http-inventory", depth=2)
            if final_url:
                self.graph.ingest_url(final_url, "http-inventory", depth=2)
                if final_url != origin:
                    self.graph.add_edge("url", origin, "redirects_to", "url", final_url, source="http-inventory", depth=2)
            host_ip = str(row.get("host_ip", ""))
            if host_ip and self._allowed(host_ip):
                origin_host = urlsplit(origin).hostname or "" if origin else ""
                if origin_host:
                    self.graph.add_edge("hostname", origin_host, "resolves_to", "ip", host_ip, source="http-inventory", depth=2)
            for technology in row.get("technologies", []) if isinstance(row.get("technologies"), list) else []:
                if origin:
                    self.graph.add_edge("url", origin, "technology", "technology", str(technology), source="http-inventory", depth=2)
        self.http_final_200 = [url for url in inventory["final_200"] if self._allowed(url)]
        if inventory_enabled:
            self.event(
                {
                    "engine": "http_inventory",
                    "status": "success",
                    "origins": len(inventory["origins"]),
                    "final_200": len(self.http_final_200),
                    "observed": len(inventory["rows"]),
                    "httpx_enriched": int(inventory.get("httpx_enriched", 0)),
                }
            )
        if self.http_final_200:
            self.seed_urls = list(self.http_final_200)
        if not self.args.no_web_fanout and self.native_stage_enabled("web-fanout"):
            result = run_all_origins(
                self.root,
                self.http_final_200,
                active=bool(self.args.active and not self.args.passive),
                tier=self.args.wordlist_tier,
                timeout=self.args.module_timeout,
                threads=self.args.threads,
                max_origins=max(1, self.args.web_fanout_limit),
                max_verify_urls=max(0, self.args.http_reverify_limit),
                tool_options=self.tool_option_overrides,
                use_dictionaries=not getattr(self.args, "no_dictionaries", False),
            )
            fanout_crawl = self.root / "web-fanout" / "crawl.urls.txt"
            promoted_urls: list[str] = []
            if fanout_crawl.is_file():
                promoted_urls = [
                    line.strip()
                    for line in fanout_crawl.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip() and self._allowed(line.strip())
                ]
                self.observed_urls = base.merge_ordered(self.observed_urls, promoted_urls)
                self.seed_urls = base.merge_ordered(self.seed_urls, promoted_urls)
                for url in promoted_urls:
                    self.graph.ingest_url(url, "web-fanout", depth=3)
            self.event(
                {
                    "engine": "web_fanout",
                    "status": "success" if result.get("runs", 0) or not self.args.active else "skipped",
                    **result,
                    "promoted_urls": len(promoted_urls),
                }
            )
        udp = _run_udp_profile(self)
        if udp.get("status") != "not-selected":
            self.event({"engine": "network_udp", **udp})

    def run_camera_surface(self) -> None:
        if self.args.no_camera:
            self.event({"engine": "device_surface", "status": "skipped", "reason": "--no-camera-analysis"})
            return
        if self.args.dry_run:
            self.event(
                {
                    "engine": "device_surface",
                    "status": "planned",
                    "reason": "--dry-run",
                    "port_profile": self.args.device_port_profile,
                    "model_filter": self.args.device_model,
                }
            )
            return
        try:
            resume = Path(self.args.device_resume).expanduser().resolve() if self.args.device_resume else None
            result = analyze_device_surface(
                self.root,
                self.target,
                active=bool(self.args.active and not self.args.passive),
                timeout=self.args.module_timeout,
                max_hosts=self.args.range_host_limit,
                port_profile=self.args.device_port_profile,
                custom_ports=self.args.device_custom_ports,
                model_filter=self.args.device_model,
                vendor_filter=self.args.device_vendor,
                resume_state=resume,
                technology_enrichment=not self.args.no_device_tech,
                workers=self.args.device_workers,
                allow_target=self._allowed,
                scan_rate=self.args.range_rate,
                connect_timeout=self.args.device_connect_timeout,
                session_timeout=self.args.device_session_timeout,
                retries=self.args.device_retries,
                run_tags=[value.strip() for value in self.args.device_run_tags.split(",") if value.strip()],
                export_mode=self.args.device_export_mode,
                egress_label=self.args.device_egress_label,
                device_data_path=Path(self.args.device_data).expanduser() if self.args.device_data else None,
                wordlist_tier=self.args.wordlist_tier,
                use_dictionaries=not getattr(self.args, "no_dictionaries", False),
            )
            self.seed_urls = base.merge_ordered(self.seed_urls, [url for url in result.get("urls", []) if self._allowed(url)])
            self.seed_hosts = sorted(set(self.seed_hosts + [host for host in result.get("hosts", []) if self._allowed(host)]))
            self.integrate_camera_queue(result.get("endpoints", []))
            for host in result.get("hosts", []):
                if self._allowed(host):
                    self.graph.ingest_host(host, "device-surface", depth=2)
            for url in result.get("urls", []):
                if self._allowed(url):
                    self.graph.ingest_url(url, "device-surface", depth=2)
            for row in result.get("inventory", []):
                host = str(row.get("host", ""))
                port = row.get("port")
                if host and port and self._allowed(host):
                    host_kind = "ip" if _is_ip(host) else "hostname"
                    service = f"{host}:{port}/{row.get('protocol', 'tcp')}"
                    self.graph.add_edge(host_kind, host, "service_on", "service", service, source="device-surface", depth=3)
                    for model in row.get("models", []):
                        self.graph.add_edge("service", service, "device_fingerprint", "device", str(model), source="device-surface", depth=3)
            self.event({"engine": "device_surface", "status": "success", **result.get("summary", {})})
        except Exception as exc:
            self.event({"engine": "device_surface", "status": "failed", "error": f"{type(exc).__name__}: {exc}"})

    def finish(self) -> int:
        for host in self.seed_hosts:
            if self._allowed(host):
                self.graph.ingest_host(host, "final", depth=2)
        for url in base.merge_ordered(self.observed_urls, self.seed_urls):
            if self._allowed(url):
                self.graph.ingest_url(url, "final", depth=2)
        graph_summary = self.graph.save(self.root)
        self.event({"engine": "asset_graph", "status": "success", **graph_summary})
        # A target run must not pay the full runner-doctor cost during
        # finalization.  The full snapshot probes every external binary for
        # identity/help/version contracts and is intentionally reserved for the
        # explicit --runner-doctor diagnostic entry point.  Normal executions
        # still record the complete registered inventory, but without launching
        # 80+ tools after recon has already completed.
        runners = planned_snapshot(self.root) if self.args.dry_run else inventory_snapshot(self.root)
        probed = [row for row in runners if row.get("available") is not None]
        self.event(
            {
                "engine": "runner_registry",
                "status": "success",
                "registered": len(runners),
                "available": sum(1 for row in probed if row.get("available")),
                "availability_deferred": len(runners) - len(probed),
                "contract_failures": sum(1 for row in probed if row.get("path") and not row.get("contract_ok")),
            }
        )
        sensitive = collect_sensitive(self.root)
        self.event({"engine": "sensitive_evidence", "status": "success", **sensitive})
        pre_storage = storage_report(self.root)
        self.event({"engine": "storage_guard", "status": "success" if pre_storage["ok"] else "failed", **pre_storage})
        rc = super().finish()
        redacted_files = _redact_general_outputs(self.root)
        post_storage = storage_report(self.root)
        if redacted_files or not post_storage["ok"]:
            self.event(
                {
                    "engine": "final_sanitization",
                    "status": "success" if post_storage["ok"] else "failed",
                    "redacted_files": redacted_files,
                    "storage_errors": post_storage["errors"],
                }
            )
        base.reseal_saved_run(self.root)
        return max(rc, 10 if not post_storage["ok"] else 0)


base.UnifiedRun = EnhancedUnifiedRun


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw == ["--runner-doctor"]:
        output = Path("ah-puch-runner-doctor").resolve()
        rows = snapshot_runners(output)
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    return base.main(raw)


if __name__ == "__main__":
    raise SystemExit(main())
