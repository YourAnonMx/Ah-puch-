#!/usr/bin/env python3
"""SRC04 DNS/PTR attribution and feedback integration.

A DNS answer is not a free-standing scope expansion. A concrete IP becomes an
eligible transport identity only when the core recorded it as a verified
A/AAAA result of a hostname already inside the target. PTR names are retained
as evidence, but only names satisfying the original target boundary may re-enter
later stages.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

try:
    from . import reverse_feedback
except ImportError:
    import reverse_feedback


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return rows
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


def _ip(value: object) -> str:
    text = str(value or "").strip().strip("[]").split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def install(base: Any) -> Any:
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_dns_ptr", False):
        return base

    class DnsPtrUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_dns_ptr = True

        def __init__(self, *args: Any, **kwargs: Any):
            # Initialize the compatibility cache before parent constructors in
            # case a future parent starts consulting _allowed during __init__.
            self._dns_attribution_signature: tuple[int, int] | None = None
            self._dns_derived: dict[str, set[str]] = {}
            super().__init__(*args, **kwargs)

        @property
        def _dns_attribution_path(self) -> Path:
            return self.core_root / "dns-attribution.jsonl"

        def _refresh_dns_attribution(self) -> dict[str, set[str]]:
            path = self._dns_attribution_path
            try:
                metadata = path.stat()
                signature = (int(metadata.st_mtime_ns), int(metadata.st_size))
            except OSError:
                return self._dns_derived
            if self._dns_attribution_signature == signature:
                return self._dns_derived

            derived: dict[str, set[str]] = {}
            parent_allowed = super()._allowed
            for row in _jsonl(path):
                if str(row.get("status", "")) != "verified" or row.get("source_within_target") is not True:
                    continue
                source = str(row.get("source_host", "")).strip().lower().rstrip(".")
                address = _ip(row.get("address", ""))
                if not source or not address or not parent_allowed(source):
                    continue
                derived.setdefault(address, set()).add(source)
            self._dns_derived = derived
            self._dns_attribution_signature = signature
            return self._dns_derived

        def _allowed(self, value: str) -> bool:
            if super()._allowed(value):
                return True
            # URL scope is never widened to an IP URL merely because the
            # hostname resolved there. Only the plain transport identity gains
            # derived eligibility; scheme/authority checks remain independent.
            address = _ip(value)
            if not address:
                return False
            return address in self._refresh_dns_attribution()

        def _ingest_dns_graph(self) -> int:
            derived = self._refresh_dns_attribution()
            edges = 0
            for address, sources in sorted(derived.items()):
                self.graph.add_node("ip", address, source="dns-attribution", depth=1, within_target=True)
                for source in sorted(sources):
                    if self.graph.add_edge(
                        "hostname",
                        source,
                        "resolves_to",
                        "ip",
                        address,
                        source="dns-attribution",
                        depth=1,
                        within_target=True,
                    ):
                        edges += 1
            return edges

        def _reverse_feedback(self) -> None:
            dns_edges = self._ingest_dns_graph()
            if self.args.no_reverse_feedback:
                self.event({
                    "engine": "reverse_feedback",
                    "status": "skipped",
                    "reason": "--no-reverse-feedback",
                    "dns_attribution_edges": dns_edges,
                })
                return

            ips = sorted({host for host in self.seed_hosts if _ip(host)})
            rows = reverse_feedback.build(
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
                ip_value = _ip(row.get("ip", ""))
                if ip_value and self._allowed(ip_value):
                    self.graph.add_node("ip", ip_value, source="reverse-feedback", depth=1, within_target=True)
                for name in row.get("ptr", []) if isinstance(row.get("ptr"), list) else []:
                    clean = str(name).strip().lower().rstrip(".")
                    if not clean or not ip_value:
                        continue
                    allowed = self._allowed(clean)
                    self.graph.add_edge(
                        "ip",
                        ip_value,
                        "ptr_to",
                        "hostname",
                        clean,
                        source="reverse-feedback",
                        depth=2,
                        within_target=allowed,
                    )
                if str(row.get("status", "")) == "success":
                    promoted.update(
                        str(name).strip().lower().rstrip(".")
                        for name in row.get("promoted", [])
                        if str(name).strip() and self._allowed(str(name))
                    )
            if promoted:
                self.seed_hosts = sorted(set(self.seed_hosts) | promoted)[: self.args.range_host_limit]

            statuses = [str(row.get("status", "unknown")) for row in rows]
            errors = sum(status in {"timeout", "resolver-error", "invalid-input"} for status in statuses)
            completed = sum(status in {"success", "no-ptr"} for status in statuses)
            if not ips:
                terminal = "skipped"
            elif errors and completed:
                terminal = "partial"
            elif errors:
                terminal = "failed"
            elif completed:
                terminal = "success"
            elif statuses and all(status == "not-probed" for status in statuses):
                terminal = "planned" if self.args.dry_run else "skipped"
            else:
                terminal = "skipped"
            self.event({
                "engine": "reverse_feedback",
                "status": terminal,
                "ips": len(ips),
                "rows": len(rows),
                "promoted": len(promoted),
                "errors": errors,
                "clean_negative": sum(status == "no-ptr" for status in statuses),
                "dns_attribution_edges": dns_edges,
            })

        def run_native(self) -> None:
            super().run_native()
            # Reverse feedback normally ingests these edges during the inherited
            # run. Keep the graph correct when reverse feedback is disabled or a
            # native selection bypasses that method.
            self._ingest_dns_graph()

    DnsPtrUnifiedRun.__name__ = "DnsPtrUnifiedRun"
    DnsPtrUnifiedRun.__qualname__ = "DnsPtrUnifiedRun"
    base.UnifiedRun = DnsPtrUnifiedRun
    return base
