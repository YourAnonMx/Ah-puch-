#!/usr/bin/env python3
"""Structured SRC02 handoff and target-endpoint enforcement for catalog module 42."""
from __future__ import annotations

from typing import Any

try:
    from .artifact_bus import ArtifactBus, canonical_host, canonical_ip
    from .catalog_artifact_runtime import _embedded_json, _result_path
except ImportError:
    from artifact_bus import ArtifactBus, canonical_host, canonical_ip
    from catalog_artifact_runtime import _embedded_json, _result_path

PARTIAL_EXIT_CODE = 3
_PARTIAL_EXIT_MODULES = frozenset({"1", "2", "3", "5", "6", "7", "42"})
_DEFAULT_PORTSPEC = "22"
_MAX_PORTS = 128


def _parse_ports(value: object) -> list[int]:
    text = str(value or "").strip() or _DEFAULT_PORTSPEC
    ports: set[int] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            raise ValueError("empty port token")
        if "-" in token:
            left, separator, right = token.partition("-")
            if not separator or not left.isdigit() or not right.isdigit():
                raise ValueError(f"invalid port range: {token}")
            start, end = int(left), int(right)
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"invalid port range: {token}")
            if len(ports) + (end - start + 1) > _MAX_PORTS:
                raise ValueError(f"port selection exceeds limit {_MAX_PORTS}")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"invalid port: {token}")
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {token}")
            ports.add(port)
        if len(ports) > _MAX_PORTS:
            raise ValueError(f"port selection exceeds limit {_MAX_PORTS}")
    return sorted(ports)


def _format_ports(values: list[int]) -> str:
    ports = sorted(set(int(value) for value in values if 1 <= int(value) <= 65535))
    if not ports:
        return ""
    groups: list[str] = []
    start = previous = ports[0]
    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue
        groups.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    groups.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(groups)


def _effective_ports(run: Any, input_value: str) -> tuple[str, str]:
    requested_spec = str(getattr(run, "option_overrides", {}).get("ports", _DEFAULT_PORTSPEC) or _DEFAULT_PORTSPEC)
    try:
        requested = _parse_ports(requested_spec)
    except (TypeError, ValueError) as exc:
        return "", f"invalid requested SSH port expression: {exc}"

    return _format_ports(requested), ""


def _endpoint_within_target(run: Any, input_value: str, host: str, port: int) -> bool:
    endpoint_allowed = getattr(run, "_endpoint_allowed_current", None) or getattr(run, "_endpoint_allowed", None)
    if callable(endpoint_allowed):
        return bool(endpoint_allowed(host, port, "ssh", "tcp"))
    allow_network = getattr(run, "_network_allowed", run._allowed)
    return bool(allow_network(host))


def _write_gate(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int, reason: str) -> None:
    module_id = str(item.get("id", "42"))
    name = str(item.get("name", "SSH Banner & Key Fingerprinter"))
    destination = run.module_root / f"{module_id}-{base.slug(name)}" / str(index)
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    run.write_module_text(
        destination,
        {
            "engine": "ahpuch_modules",
            "module_id": module_id,
            "module": name,
            "script": str(item.get("script", "ssh_banner_key_fingerprinter.py")),
            "class": base.module_class(item),
            "input": input_value,
            "reason": reason,
        },
        "gated",
        "SSH fingerprinting was not started because the requested endpoint was rejected.\n",
    )


def _ssh_payload(path: Any) -> dict[str, Any]:
    payload = _embedded_json(path, "ssh_fingerprints.json")
    if not isinstance(payload, dict):
        return {}
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return {}
    return payload


def _project_module_42(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int) -> None:
    result = _result_path(base, run, item, index)
    payload = _ssh_payload(result)
    if not payload:
        return

    bus = ArtifactBus(run.root, run.target)
    graph = getattr(run, "graph", None)
    source = str(result.relative_to(run.root))
    producer = "catalog-module:42-ssh-fingerprint"

    observed_services = promoted_services = 0
    observed_fingerprints = promoted_fingerprints = 0
    observed_hosts = promoted_hosts = 0

    for row in payload.get("rows", []):
        if not isinstance(row, dict) or row.get("ssh_verified") is not True:
            continue
        state = str(row.get("state", "")).strip().lower()
        if state not in {"success", "partial"}:
            continue
        host = canonical_host(str(row.get("host", "")))
        try:
            port = int(row.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        if not host or not (1 <= port <= 65535):
            continue

        within_target = _endpoint_within_target(run, input_value, host, port)
        host_kind = "ip" if canonical_ip(host) else "host"
        graph_host_kind = "ip" if canonical_ip(host) else "hostname"
        bus_status = "verified" if state == "success" else "partial"

        if bus.observe(
            host_kind,
            host,
            producer=producer,
            source=source,
            status=bus_status,
            within_target=within_target,
            attributes={"ssh_verified": True, "target_input": input_value},
        ):
            observed_hosts += 1
            promoted_hosts += int(within_target)

        if bus.observe(
            "service",
            "",
            producer=producer,
            source=source,
            status=bus_status,
            within_target=within_target,
            attributes={
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service": "ssh",
                "target_input": input_value,
            },
        ):
            observed_services += 1
            promoted_services += int(within_target)

        if graph is not None:
            display_host = f"[{host}]" if ":" in host else host
            graph.add_edge(
                graph_host_kind,
                host,
                "service_on",
                "service",
                f"tcp://{display_host}:{port}",
                source=producer,
                depth=2,
                within_target=within_target,
            )

        fingerprints = (
            ("ssh-banner", str(row.get("banner", "")).strip()),
            ("ssh-hostkey-type", str(row.get("key_type", "")).strip()),
            ("ssh-hostkey-md5", str(row.get("key_md5", "")).strip()),
            ("ssh-hostkey-sha256", str(row.get("key_sha256", "")).strip()),
        )
        for namespace, value in fingerprints:
            if not value:
                continue
            if namespace == "ssh-banner" and not value.startswith("SSH-"):
                continue
            if bus.observe(
                "fingerprint",
                value,
                producer=producer,
                source=source,
                status=bus_status,
                within_target=within_target,
                attributes={
                    "namespace": namespace,
                    "host": host,
                    "port": port,
                    "service": "ssh",
                    "key_source": str(row.get("key_source", "")),
                    "target_input": input_value,
                },
            ):
                observed_fingerprints += 1
                promoted_fingerprints += int(within_target)

    if observed_hosts or observed_services or observed_fingerprints:
        bus.save()
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    handoff_status = "partial" if int(summary.get("partial", 0) or 0) or int(summary.get("errors", 0) or 0) else "success"
    run.event(
        {
            "engine": "catalog_artifact_handoff",
            "module_id": "42",
            "module": str(item.get("name", "SSH Banner & Key Fingerprinter")),
            "status": handoff_status,
            "observed_hosts": observed_hosts,
            "promoted_hosts": promoted_hosts,
            "observed_services": observed_services,
            "promoted_services": promoted_services,
            "observed_fingerprints": observed_fingerprints,
            "promoted_fingerprints": promoted_fingerprints,
            "quarantined_services": observed_services - promoted_services,
        }
    )


def install(base: Any) -> Any:
    # SSH fingerprinting opens TCP sessions and negotiates SSH transport, so it
    # is never an automatic-passive catalog action.
    if hasattr(base, "ACTIVE_NAMES"):
        base.ACTIVE_NAMES.add("ssh_banner_key_fingerprinter.py")

    current = base.UnifiedRun
    if getattr(current, "_ah_puch_catalog_ssh", False):
        return base

    class CatalogSshUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_catalog_ssh = True

        def write_module_text(self, destination: Any, event: dict[str, Any], status: str, body: str) -> None:
            module_id = str(event.get("module_id", ""))
            try:
                exit_code = int(event.get("exit_code", -1))
            except (TypeError, ValueError):
                exit_code = -1
            if status == "failed" and exit_code == PARTIAL_EXIT_CODE and module_id in _PARTIAL_EXIT_MODULES:
                event = {
                    **event,
                    "terminal_reconciled": True,
                    "raw_exit_status": "failed",
                    "partial_exit_code": PARTIAL_EXIT_CODE,
                }
                status = "partial"
            super().write_module_text(destination, event, status, body)

        def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
            if str(item.get("id", "")) != "42":
                super().run_catalog_module(item, input_value, index)
                return

            effective_ports, reason = _effective_ports(self, input_value)
            if reason:
                _write_gate(base, self, item, input_value, index, reason)
                return

            effective_item = dict(item)
            effective_item["options"] = list(dict.fromkeys([*item.get("options", []), "ports"]))
            previous = self.option_overrides.get("ports", None)
            had_previous = "ports" in self.option_overrides
            self.option_overrides["ports"] = effective_ports
            try:
                super().run_catalog_module(effective_item, input_value, index)
            finally:
                if had_previous:
                    self.option_overrides["ports"] = previous
                else:
                    self.option_overrides.pop("ports", None)
            _project_module_42(base, self, effective_item, input_value, index)

    CatalogSshUnifiedRun.__name__ = "CatalogSshUnifiedRun"
    CatalogSshUnifiedRun.__qualname__ = "CatalogSshUnifiedRun"
    base.UnifiedRun = CatalogSshUnifiedRun
    return base
