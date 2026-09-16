#!/usr/bin/env python3
"""SRC07 canonical industrial follow-up orchestration.

The core industrial stage is passive evidence only. This layer is the single
active follow-up owner: it derives explicit protocol endpoints from the passive
protocol ledger, re-checks the target boundary before every dispatch and
passes one exact port to the existing TCP/UDP catalog samplers.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from . import catalog_endpoint_scope_runtime as endpoint_scope
    from .industrial_routing import IndustrialRoute, routes_from_record
except ImportError:
    import catalog_endpoint_scope_runtime as endpoint_scope
    from industrial_routing import IndustrialRoute, routes_from_record


def _value_allowed(run: Any, value: str) -> bool:
    text = str(value).strip()
    if text.startswith(("http://", "https://")):
        return bool(run._allowed(text))
    allow_network = getattr(run, "_network_allowed", run._allowed)
    return bool(allow_network(text))


def _operator_requested_port(run: Any, port: int) -> bool:
    overrides = getattr(run, "option_overrides", {})
    if "ports" not in overrides:
        return True
    try:
        return int(port) in endpoint_scope._parse_ports(overrides["ports"])
    except (TypeError, ValueError):
        return False


def _protocol_map(core_root: Path) -> dict[str, set[str]]:
    stage = core_root / "09-ics"
    mapping: dict[str, set[str]] = {}
    if not stage.is_dir():
        return mapping
    paths = sorted(path for path in stage.glob("*.protocols.txt") if path.is_file() and not path.is_symlink())
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines[1:]:
            fields = line.split("\t", 2)
            if len(fields) < 2:
                continue
            label = fields[0].strip().lower()
            candidate = fields[1].strip()
            if label and candidate:
                mapping.setdefault(candidate, set()).add(label)
    return mapping


def _candidate_values(run: Any, base: Any) -> tuple[list[str], list[str]]:
    camera_file = run.queue_root / f"{base.slug(run.target)}.camera.candidates.txt"
    ics_file = run.core_root / "09-ics" / f"{base.slug(run.target)}.ics-candidates.txt"
    camera_values = [
        line.strip()
        for line in camera_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ] if camera_file.is_file() and not camera_file.is_symlink() else []
    ics_values = [
        line.strip()
        for line in ics_file.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ] if ics_file.is_file() and not ics_file.is_symlink() else []
    return camera_values, ics_values


def _observed_routes(root: Path) -> list[IndustrialRoute]:
    """Read only concrete service observations from the canonical bus."""
    source = root / "artifacts" / "queues" / "services.jsonl"
    if not source.is_file() or source.is_symlink():
        return []
    routes: dict[tuple[str, str], IndustrialRoute] = {}
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        for route in routes_from_record(row):
            routes[(route.endpoint.uri, route.protocol)] = route
    return [routes[key] for key in sorted(routes)]


def _route_allowed(run: Any, route: IndustrialRoute) -> bool:
    return bool(
        _operator_requested_port(run, route.endpoint.port)
        and endpoint_scope.endpoint_allowed(run, route.endpoint.host, route.endpoint.port)
    )


def _dispatch_exact_port(run: Any, item: dict[str, Any], value: str, index: int, port: int) -> None:
    effective = dict(item)
    effective["options"] = list(dict.fromkeys([*item.get("options", []), "ports"]))
    previous = run.option_overrides.get("ports")
    had_previous = "ports" in run.option_overrides
    run.option_overrides["ports"] = str(int(port))
    try:
        run.run_catalog_module(effective, value, index)
    finally:
        if had_previous:
            run.option_overrides["ports"] = previous
        else:
            run.option_overrides.pop("ports", None)


def install(base: Any) -> Any:
    """Replace mixed legacy follow-up dispatch with one exact endpoint planner."""
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_industrial_followup", False):
        return base

    class IndustrialFollowupUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_industrial_followup = True

        def dispatch_followups(self) -> None:
            if self.args.dry_run:
                self.event({"engine": "follow_up", "status": "planned", "reason": "--dry-run"})
                return
            if not self.args.follow_up or self.args.follow_up_rounds < 1:
                self.event({"engine": "follow_up", "status": "skipped", "reason": "follow-up disabled"})
                return

            modules = {str(item.get("name")): item for item in base.load_modules()}
            camera_names = (
                "Server Info", "HTTP Headers", "HTTP/2 and HTTP/3 Support Checker", "TLS Security Configuration",
            )
            context_names = ("Server Info", "IP Info")
            tcp_item = modules.get("Open Ports Scan")
            udp_item = modules.get("UDP Service Sampler")
            plan = self.root / "queues" / f"{base.slug(self.target)}.follow-up-plan.jsonl"
            plan.parent.mkdir(parents=True, exist_ok=True)
            rounds = max(1, min(int(self.args.follow_up_rounds), 3))
            active_endpoint_dispatch = bool(getattr(self.args, "active", False)) and not bool(getattr(self.args, "passive", False))
            dispatched = 0
            quarantined = 0
            active_endpoint_skipped = 0
            rounds_executed = 0
            observed_units: set[tuple[str, str, int]] = set()
            visited: set[tuple[str, str, str, int]] = set()
            seen_camera: set[str] = set()
            seen_ics: set[str] = set()

            with plan.open("w", encoding="utf-8") as handle:
                for round_number in range(1, rounds + 1):
                    rounds_executed = round_number
                    # Re-read queues every round so newly produced evidence can
                    # advance, but never re-dispatch an unchanged unit.
                    camera_values, ics_values = _candidate_values(self, base)
                    protocol_routes = _observed_routes(self.root)
                    seen_camera.update(camera_values)
                    seen_ics.update(ics_values)
                    seen_ics.update(route.endpoint.uri for route in protocol_routes)
                    round_dispatched = 0

                    for value in camera_values[: self.args.range_host_limit]:
                        if not value.startswith(("http://", "https://")):
                            continue
                        for name in camera_names:
                            item = modules.get(name)
                            key = ("camera", name, value, 0)
                            if not item or key in visited:
                                continue
                            visited.add(key)
                            handle.write(json.dumps({
                                "round": round_number,
                                "kind": "camera",
                                "module": name,
                                "input": value,
                            }, ensure_ascii=False, sort_keys=True) + "\n")
                            self.run_catalog_module(item, value, dispatched + 1)
                            dispatched += 1
                            round_dispatched += 1

                    for value in ics_values[: self.args.range_host_limit]:
                        # Contextual modules may only use the exact passive
                        # candidate; the target boundary is checked at every edge.
                        for name in context_names:
                            item = modules.get(name)
                            key = ("ics-context", name, value, 0)
                            if not item or key in visited:
                                continue
                            visited.add(key)
                            if not _value_allowed(self, value):
                                quarantined += 1
                                self.event({
                                    "engine": "industrial_followup_boundary",
                                    "status": "quarantined",
                                    "reason": "candidate outside target boundary before context dispatch",
                                    "module": name,
                                    "input": value,
                                    "probe_count": 0,
                                })
                                continue
                            handle.write(json.dumps({
                                "round": round_number,
                                "kind": "ics-context",
                                "module": name,
                                "input": value,
                            }, ensure_ascii=False, sort_keys=True) + "\n")
                            self.run_catalog_module(item, value, dispatched + 1)
                            dispatched += 1
                            round_dispatched += 1

                    for route in protocol_routes[: self.args.range_host_limit]:
                        endpoint = route.endpoint
                        observed_units.add((endpoint.uri, route.protocol, endpoint.port))
                        item = tcp_item if endpoint.protocol == "tcp" else udp_item
                        module_name = str(item.get("name", "")) if item else ""
                        key = ("ics-endpoint", module_name, endpoint.uri, endpoint.port)
                        if not item or key in visited:
                            continue
                        visited.add(key)
                        if not active_endpoint_dispatch:
                            active_endpoint_skipped += 1
                            self.event({
                                "engine": "industrial_followup",
                                "status": "skipped",
                                "reason": "active industrial protocol follow-up requires --active",
                                "input": endpoint.uri,
                                "protocol": endpoint.protocol,
                                "port": endpoint.port,
                                "industrial_protocol": route.protocol,
                                "evidence": list(route.evidence),
                                "probe_count": 0,
                            })
                            continue
                        if not _route_allowed(self, route):
                            quarantined += 1
                            self.event({
                                "engine": "industrial_followup",
                                "status": "quarantined",
                                "reason": "observed endpoint excluded by target or operator port selection",
                                "input": endpoint.uri,
                                "protocol": endpoint.protocol,
                                "port": endpoint.port,
                                "industrial_protocol": route.protocol,
                                "evidence": list(route.evidence),
                                "probe_count": 0,
                            })
                            continue
                        # Re-check immediately before the exact endpoint edge.
                        if not endpoint_scope.endpoint_allowed(self, endpoint.host, endpoint.port):
                            quarantined += 1
                            self.event({
                                "engine": "industrial_followup",
                                "status": "quarantined",
                                "reason": "observed endpoint excluded immediately before dispatch",
                                "input": endpoint.uri,
                                "protocol": endpoint.protocol,
                                "port": endpoint.port,
                                "industrial_protocol": route.protocol,
                                "evidence": list(route.evidence),
                                "probe_count": 0,
                            })
                            continue
                        handle.write(json.dumps({
                            "round": round_number,
                            "kind": "industrial-endpoint",
                            "module": module_name,
                            "input": endpoint.host,
                            "service": endpoint.uri,
                            "protocol": endpoint.protocol,
                            "port": endpoint.port,
                            "industrial_protocol": route.protocol,
                            "evidence": list(route.evidence),
                        }, ensure_ascii=False, sort_keys=True) + "\n")
                        _dispatch_exact_port(self, item, endpoint.host, dispatched + 1, endpoint.port)
                        dispatched += 1
                        round_dispatched += 1

                    if round_number > 1 and round_dispatched == 0:
                        break

            try:
                plan.chmod(0o600)
            except OSError:
                pass
            status = "partial" if quarantined else "success"
            self.event({
                "engine": "follow_up",
                "status": status,
                "rounds_requested": rounds,
                "rounds_executed": rounds_executed,
                "camera_inputs": len(seen_camera),
                "ics_inputs": len(seen_ics),
                "observed_industrial_endpoints": len(observed_units),
                "active_endpoint_dispatch_enabled": active_endpoint_dispatch,
                "active_endpoint_skipped": active_endpoint_skipped,
                "quarantined": quarantined,
                "dispatched": dispatched,
                "unique_dispatch_units": dispatched,
                "plan": str(plan.relative_to(self.root)),
            })

    IndustrialFollowupUnifiedRun.__name__ = "IndustrialFollowupUnifiedRun"
    IndustrialFollowupUnifiedRun.__qualname__ = "IndustrialFollowupUnifiedRun"
    base.UnifiedRun = IndustrialFollowupUnifiedRun
    return base
