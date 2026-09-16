#!/usr/bin/env python3
"""Canonical public entry point for Ah-Puch.

The production runtime is composed first. Catalog/menu semantics, legacy
capability and runner parity, strict target input, automatic target boundary,
SRC01 evidence/TLS projections, SRC04 DNS/PTR attribution, SRC05 typed local
dictionary routing, SRC06 offline advisory mapping, SRC07 passive industrial
evidence plus exact endpoint follow-up, SRC09 exact device endpoint/resume
contracts, SRC10 exact orchestration terminal attribution, Phase-5 URL/content
handoffs, Phase-6 network/device handoffs, SRC03 endpoint-boundary and normalized-
service hardening, structured catalog handoffs including SRC02 SSH, the
normalized artifact bus and per-target evidence are installed over the same
shared base runner; no parallel parser or execution engine exists.
"""
from __future__ import annotations

import sys

try:
    from . import advisory_runtime, artifact_bus_runtime, catalog_artifact_runtime, catalog_endpoint_scope_runtime, catalog_frontend, catalog_ip_info_runtime, catalog_open_ports_runtime, catalog_server_info_runtime, catalog_ssh_runtime, device_boundary_runtime, device_contract_runtime, dictionary_broker, dictionary_runtime, dns_ptr_runtime, industrial_followup_runtime, legacy_parity_runtime, legacy_runner_runtime, network_device_runtime, network_inventory_runtime, network_scope_runtime, orchestration_terminal_runtime, pipeline_runtime, projection_runtime, runtime, target_boundary_runtime, target_contract, target_runtime
except ImportError:
    import advisory_runtime
    import artifact_bus_runtime
    import catalog_artifact_runtime
    import catalog_endpoint_scope_runtime
    import catalog_frontend
    import catalog_ip_info_runtime
    import catalog_open_ports_runtime
    import catalog_server_info_runtime
    import catalog_ssh_runtime
    import device_boundary_runtime
    import device_contract_runtime
    import dictionary_broker
    import dictionary_runtime
    import dns_ptr_runtime
    import industrial_followup_runtime
    import legacy_parity_runtime
    import legacy_runner_runtime
    import network_device_runtime
    import network_inventory_runtime
    import network_scope_runtime
    import target_boundary_runtime
    import orchestration_terminal_runtime
    import pipeline_runtime
    import projection_runtime
    import runtime
    import target_contract
    import target_runtime

base = catalog_frontend.install(runtime.v2.base)
base = legacy_parity_runtime.install(base, catalog_frontend)
# SRC05 makes menu/resource reporting use the exact broker consumed by web and
# production core stages. This changes no target execution by itself.
base = dictionary_broker.install_frontend(base)
base = target_contract.install(base)
base = target_boundary_runtime.install(base, runtime.v2, runtime)
# SRC04 extends the target only with concrete A/AAAA transport
# identities proven by the core attribution ledger. PTR names remain subject to
# the original hostname boundary before they can re-enter later stages.
base = dns_ptr_runtime.install(base)
# SRC06 replaces the historical networked advisory mapper with one offline
# store/projection implementation. Local selector aliases and automatic
# post-inventory advisory projection resolve through the same function.
advisory_runtime.install(runtime)

# Install legacy runner capabilities before composing the canonical web bus.
# SRC05 then normalizes the effective directory tier across the canonical and
# legacy sibling consumers before web_chain_runtime captures the function.
legacy_runner_runtime.install(runtime.v2, runtime)
dictionary_runtime.install(runtime.v2)
try:
    from . import web_chain_runtime
except ImportError:
    import web_chain_runtime
web_chain_runtime._ORIGINAL_WEB_FANOUT = runtime.v2.run_all_origins
web_chain_runtime.install(runtime)

# SRC01 producer artifacts are normalized through the shared bus before the
# network/device composite captures its base sync function. Rebind explicitly
# as well so test/import order cannot bypass the projection wrapper.
projection_sync = projection_runtime.install()
network_device_runtime._ORIGINAL_SYNC = projection_sync
network_device_runtime.install(runtime)
# SRC09 wraps the already-composed device adapter. It adds no scanner: every
# existing device contact is filtered by the same concrete endpoint contract,
# and resume requires a matching SRC09 sidecar plus inventory digest.
device_contract_runtime.install(runtime)
# File/resume inputs and device bus promotion share the same SRC09 boundary:
# regular non-symlink artifacts only, and service/fingerprint promotion only
# after concrete host:port scope succeeds.
device_boundary_runtime.install()
# SRC03 narrows the existing network adapter in place. It must install after
# network_device_runtime so it can constrain that adapter's captured raw runner
# and replace discovery-as-service ingestion without creating another engine.
network_scope_runtime.install(runtime)
# The normalized inventory may retain useful Nmap product/version metadata, but
# raw XML cannot bypass the canonical service queue. Bind inventory projection
# to promotable bus endpoints before the lifecycle wrapper calls finish().
network_inventory_runtime.install(runtime)

base = catalog_artifact_runtime.install(base)
base = catalog_ip_info_runtime.install(base)
base = catalog_open_ports_runtime.install(base)
base = catalog_server_info_runtime.install(base)
base = catalog_ssh_runtime.install(base)
# SRC07 applies one endpoint guard to the active TCP/UDP catalog samplers, then
# makes the outer follow-up planner the only active industrial dispatcher.
base = catalog_endpoint_scope_runtime.install(base)
base = industrial_followup_runtime.install(base)
# artifact_bus_runtime imported sync_sources by value; bind the Phase-6/SRC03
# composite explicitly before installing its lifecycle wrapper.
artifact_bus_runtime.sync_sources = network_device_runtime._sync_sources_with_network
base = artifact_bus_runtime.install(base)
# The typed pipeline runs inside the same lifecycle after the canonical bus has
# promoted native evidence, so every external method uses the same scope and
# target boundary and its output can feed the catalog/device stages.
base = pipeline_runtime.install(base)
# SRC10 sits outside all execution producers and reconciles only terminal
# attribution. A runner-backed capability can never inherit a sibling runner's
# aggregate success from the generic advanced-consumers event.
base = orchestration_terminal_runtime.install(base)
base = target_runtime.install(base)
parser = runtime.parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    target_runtime.begin()
    rc = 2
    try:
        while True:
            try:
                rc = runtime.main(raw)
                break
            except catalog_frontend.InteractiveCLIRequest as request:
                raw = list(request.argv)
            except target_contract.TargetInputError as exc:
                parser().error(str(exc))
        return rc
    finally:
        target_runtime.finish(rc)


if __name__ == "__main__":
    raise SystemExit(main())
