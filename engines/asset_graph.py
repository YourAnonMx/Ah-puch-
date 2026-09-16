#!/usr/bin/env python3
"""Typed asset/work graph for Ah-Puch orchestration.

The graph records what was observed, how it was related, and which
(asset, capability) pairs have already been processed so discovery can feed
later stages without loops.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

NODE_KINDS = {
    "domain", "hostname", "ip", "cidr", "url", "origin", "service",
    "certificate", "technology", "device", "sensitive", "cdn-origin-candidate",
}
EDGE_KINDS = {
    "resolves_to", "ptr_to", "reverse_host", "crawled_to", "hosted_on",
    "cert_san", "certificate_for", "certificate_peer", "service_on",
    "technology", "device_fingerprint", "origin_candidate", "redirects_to",
    "observed_as",
}
_HOST_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def _slug(value: str) -> str:
    return value.strip().strip("'\";,()")


def target_host(target: str) -> str:
    raw = _slug(target)
    if raw.startswith(("http://", "https://")):
        return (urlsplit(raw).hostname or "").lower().rstrip(".")
    if "/" in raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            pass
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")].lower()
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        return raw.rsplit(":", 1)[0].lower().rstrip(".")
    return raw.strip("[]").lower().rstrip(".")


def targetable_host(value: str) -> str:
    """Normalize one concrete host identity suitable for network dispatch.

    Certificate wildcards, email identities, paths and malformed DNS labels can
    be preserved elsewhere as evidence, but they are not executable host
    identities and therefore never satisfy target-boundary checks. ``localhost`` remains
    an explicit loopback identity for deterministic fixtures/local operation.
    """
    candidate = str(value).strip().strip("[]").lower().rstrip(".")
    if not candidate or any(character in candidate for character in ("*", "?", "@", "/", "\\")):
        return ""
    if candidate == "localhost":
        return candidate
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        labels = candidate.split(".")
        if len(labels) < 2 or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
            return ""
        return candidate


def host_within_target(host: str, target: str, mode: str = "domain") -> bool:
    candidate = targetable_host(host)
    if not candidate:
        return False
    raw = _slug(target)
    if "/" in raw and not raw.startswith(("http://", "https://")):
        try:
            return ipaddress.ip_address(candidate) in ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return False
    base = targetable_host(target_host(raw))
    if not base:
        return False
    try:
        return ipaddress.ip_address(candidate) == ipaddress.ip_address(base)
    except ValueError:
        if mode in {"authority", "host"}:
            return candidate == base
        return candidate == base or candidate.endswith("." + base)


def url_within_target(value: str, target: str, mode: str = "domain") -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    if mode == "authority" and target.startswith(("http://", "https://")):
        wanted = urlsplit(target)
        if parsed.scheme.lower() != wanted.scheme.lower():
            return False
        if parsed.hostname.lower().rstrip(".") != (wanted.hostname or "").lower().rstrip("."):
            return False
        return (parsed.port or (443 if parsed.scheme == "https" else 80)) == (
            wanted.port or (443 if wanted.scheme == "https" else 80)
        )
    return host_within_target(parsed.hostname, target, mode)


def canonical_origin(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower().rstrip(".")
    display = f"[{host}]" if ":" in host else host
    port = parsed.port
    default = 443 if parsed.scheme == "https" else 80
    netloc = display if not port or port == default else f"{display}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))


@dataclass
class AssetGraph:
    target: str
    boundary_mode: str = "domain"
    max_depth: int = 6
    max_nodes: int = 10000
    nodes: dict[tuple[str, str], dict] = field(default_factory=dict)
    edges: set[tuple[str, str, str, str, str, str]] = field(default_factory=set)
    visited: set[tuple[str, str, str]] = field(default_factory=set)

    def _allowed_kind(self, kind: str) -> None:
        if kind not in NODE_KINDS:
            raise ValueError(f"unsupported graph node kind: {kind}")

    def add_node(self, kind: str, value: str, *, source: str = "", depth: int = 0, within_target: bool | None = None) -> bool:
        self._allowed_kind(kind)
        clean = str(value).strip()
        if not clean or depth < 0 or depth > self.max_depth:
            return False
        key = (kind, clean)
        if key not in self.nodes and len(self.nodes) >= self.max_nodes:
            return False
        if within_target is None:
            if kind in {"hostname", "domain", "ip"}:
                within_target = host_within_target(clean, self.target, self.boundary_mode)
            elif kind in {"url", "origin"}:
                within_target = url_within_target(clean, self.target, self.boundary_mode)
            else:
                within_target = True
        elif kind in {"hostname", "domain", "ip"} and not targetable_host(clean):
            # A producer cannot turn a wildcard/pattern or
            # non-host certificate identity into a concrete network target.
            within_target = False
        row = self.nodes.setdefault(key, {"kind": kind, "value": clean, "depth": depth, "within_target": bool(within_target), "sources": []})
        row["depth"] = min(int(row.get("depth", depth)), depth)
        row["within_target"] = bool(row.get("within_target", False) or within_target)
        if source and source not in row["sources"]:
            row["sources"].append(source)
        return True

    def add_edge(self, src_kind: str, src_value: str, relation: str, dst_kind: str, dst_value: str, *, source: str = "", depth: int = 0, within_target: bool | None = None) -> bool:
        if relation not in EDGE_KINDS:
            raise ValueError(f"unsupported graph edge kind: {relation}")
        if not self.add_node(src_kind, src_value, source=source, depth=max(0, depth - 1)):
            return False
        if not self.add_node(dst_kind, dst_value, source=source, depth=depth, within_target=within_target):
            return False
        self.edges.add((src_kind, src_value, relation, dst_kind, dst_value, source))
        return True

    def mark_visited(self, kind: str, value: str, capability: str) -> bool:
        key = (kind, str(value), str(capability))
        if key in self.visited:
            return False
        self.visited.add(key)
        return True

    def ingest_host(self, host: str, source: str, depth: int = 1) -> None:
        kind = "ip"
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            kind = "hostname"
        self.add_node(kind, host, source=source, depth=depth)

    def ingest_url(self, url: str, source: str, depth: int = 1) -> None:
        if not self.add_node("url", url, source=source, depth=depth):
            return
        origin = canonical_origin(url)
        if origin:
            self.add_edge("url", url, "observed_as", "origin", origin, source=source, depth=depth)
            parsed = urlsplit(origin)
            if parsed.hostname:
                self.add_edge("origin", origin, "hosted_on", "hostname", parsed.hostname, source=source, depth=depth)

    def target_values(self, kinds: set[str]) -> list[str]:
        return sorted(row["value"] for row in self.nodes.values() if row["kind"] in kinds and row.get("within_target"))

    def save(self, root: Path) -> dict[str, int]:
        graph_dir = root / "graph"
        graph_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        nodes = sorted(self.nodes.values(), key=lambda r: (r["kind"], r["value"]))
        edges = [{"src_kind": a, "src": b, "relation": c, "dst_kind": d, "dst": e, "source": f} for a, b, c, d, e, f in sorted(self.edges)]
        visited = [{"kind": a, "value": b, "capability": c} for a, b, c in sorted(self.visited)]
        for name, rows in (("assets.jsonl", nodes), ("edges.jsonl", edges), ("visited.jsonl", visited)):
            path = graph_dir / name
            path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
            path.chmod(0o600)
        summary = {"nodes": len(nodes), "edges": len(edges), "visited": len(visited)}
        summary_path = graph_dir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        summary_path.chmod(0o600)
        return summary
