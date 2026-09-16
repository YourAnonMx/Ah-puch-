#!/usr/bin/env python3
"""Deterministic normalized artifact bus for Ah-Puch.

The bus is deliberately additive during migration: existing stage artifacts stay
in place while producers project stable target-aware records here. Later phases
consume the promoted queues and can retire ad-hoc handoffs only after parity is
proved.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SCHEMA_VERSION = 1
ARTIFACT_KINDS = (
    "host",
    "ip",
    "service",
    "origin",
    "url",
    "path",
    "parameter",
    "technology",
    "fingerprint",
    "finding",
)
PROMOTABLE_STATUSES = frozenset({"success", "verified", "partial", "http-200", "operator"})
SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pass", "token", "secret", "authorization", "credential",
    "credentials", "api_key", "api-key", "apikey", "client_secret", "client-secret",
    "cookie", "set-cookie",
})
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_PLURALS = {
    "host": "hosts", "ip": "ips", "service": "services", "origin": "origins",
    "url": "urls", "path": "paths", "parameter": "parameters",
    "technology": "technologies", "fingerprint": "fingerprints", "finding": "findings",
}


def _safe_text(value: Any, *, limit: int = 8192) -> str:
    text = str(value or "").replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return text[:limit]


def _sanitize(value: Any, key: str = "") -> Any:
    normalized = key.casefold().replace("-", "_")
    if normalized in {item.replace("-", "_") for item in SENSITIVE_KEYS}:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _sanitize(v, str(k)) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple, set)):
        sanitized = [_sanitize(item) for item in value]
        try:
            return sorted(sanitized, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        except TypeError:
            return sanitized
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return _safe_text(value)


def canonical_host(value: str) -> str:
    raw = _safe_text(value).lower().rstrip(".")
    if raw.startswith(("http://", "https://")):
        try:
            raw = (urlsplit(raw).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        raw = raw.rsplit(":", 1)[0]
    return raw.strip("[]").rstrip(".")


def canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(canonical_host(value)))
    except ValueError:
        return ""


def canonical_origin(value: str) -> str:
    try:
        parsed = urlsplit(_safe_text(value))
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    display = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        return ""
    default = 443 if parsed.scheme.lower() == "https" else 80
    netloc = display if not port or port == default else f"{display}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))


def canonical_url(value: str) -> str:
    """Normalize an HTTP(S) URL while retaining query names, never values."""
    raw = _safe_text(value)
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    origin = canonical_origin(raw)
    if not origin:
        return ""
    root = urlsplit(origin)
    path = parsed.path or "/"
    names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    query = urlencode([(name, "") for name in names])
    return urlunsplit((root.scheme, root.netloc, path, query, ""))


def _url_components(value: str) -> tuple[str, str, list[str]]:
    canonical = canonical_url(value)
    if not canonical:
        return "", "", []
    parsed = urlsplit(canonical)
    origin = canonical_origin(canonical)
    names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return origin, parsed.path or "/", names


def _canonical(kind: str, value: str, attributes: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    if kind not in ARTIFACT_KINDS:
        raise ValueError(f"unsupported artifact kind: {kind}")
    attrs = _sanitize(attributes)
    if kind == "host":
        canonical = canonical_host(value)
        if not canonical or canonical_ip(canonical):
            return "", "", attrs
        return canonical, canonical, attrs
    if kind == "ip":
        canonical = canonical_ip(value)
        return (canonical, canonical, attrs) if canonical else ("", "", attrs)
    if kind == "origin":
        canonical = canonical_origin(value)
        return (canonical, canonical, attrs) if canonical else ("", "", attrs)
    if kind == "url":
        canonical = canonical_url(value)
        return (canonical, canonical, attrs) if canonical else ("", "", attrs)
    if kind == "path":
        origin = canonical_origin(str(attrs.get("origin", "")))
        path = _safe_text(value)
        if not origin or not path.startswith("/"):
            return "", "", attrs
        attrs["origin"] = origin
        canonical = f"{origin.rstrip('/')}{path}"
        return canonical, canonical, attrs
    if kind == "parameter":
        name = _safe_text(attrs.get("name", value), limit=512)
        location = _safe_text(attrs.get("location", "query"), limit=32).lower() or "query"
        url = canonical_url(str(attrs.get("url", "")))
        if not name or not url:
            return "", "", attrs
        attrs.update({"name": name, "location": location, "url": url})
        canonical = f"{location}:{name}@{urlsplit(url)._replace(query='').geturl()}"
        return canonical, canonical, attrs
    if kind == "service":
        host = canonical_host(str(attrs.get("host", "")))
        protocol = _safe_text(attrs.get("protocol", "tcp"), limit=16).lower() or "tcp"
        try:
            port = int(attrs.get("port", 0))
        except (TypeError, ValueError):
            port = 0
        if host and 1 <= port <= 65535:
            display = f"[{host}]" if ":" in host else host
            canonical = f"{protocol}://{display}:{port}"
            attrs.update({"host": host, "protocol": protocol, "port": port})
            return canonical, canonical, attrs
        fallback = _safe_text(value).lower()
        return (fallback, fallback, attrs) if fallback else ("", "", attrs)
    if kind == "technology":
        canonical = _safe_text(value, limit=1024).casefold()
        return (canonical, canonical, attrs) if canonical else ("", "", attrs)
    if kind == "fingerprint":
        namespace = _safe_text(attrs.get("namespace", "generic"), limit=128).casefold() or "generic"
        display = _safe_text(value, limit=2048)
        if not display:
            return "", "", attrs
        attrs["namespace"] = namespace
        key = f"{namespace}:{display.casefold()}"
        return display, key, attrs
    display = _safe_text(value, limit=2048)
    if not display:
        return "", "", attrs
    material = json.dumps({"value": display, "attributes": attrs}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    key = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return display, key, attrs


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)
    path.chmod(0o600)


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


class ArtifactBus:
    def __init__(self, root: Path, target: str):
        self.root = Path(root)
        self.target = _safe_text(target)
        self.rows: dict[tuple[str, str], dict[str, Any]] = {}
        self._load()

    @property
    def directory(self) -> Path:
        return self.root / "artifacts"

    def _load(self) -> None:
        for row in _jsonl(self.directory / "bus.jsonl"):
            kind = str(row.get("kind", ""))
            key = str(row.get("key", ""))
            if kind in ARTIFACT_KINDS and key:
                self.rows[(kind, key)] = row

    def observe(
        self,
        kind: str,
        value: str,
        *,
        producer: str,
        source: str,
        status: str,
        within_target: bool,
        observed: bool = True,
        attributes: dict[str, Any] | None = None,
    ) -> bool:
        canonical, key, attrs = _canonical(kind, value, attributes or {})
        producer = _safe_text(producer, limit=256)
        source = _safe_text(source, limit=1024)
        status = _safe_text(status, limit=64).lower()
        if not canonical or not key or not producer or not source or not status:
            return False
        observation = {
            "producer": producer,
            "source": source,
            "status": status,
            "within_target": bool(within_target),
            "observed": bool(observed),
            "attributes": attrs,
        }
        row = self.rows.setdefault(
            (kind, key),
            {
                "schema_version": SCHEMA_VERSION,
                "kind": kind,
                "key": key,
                "value": canonical,
                "observations": [],
            },
        )
        encoded = json.dumps(observation, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        existing = {
            json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            for item in row.get("observations", [])
            if isinstance(item, dict)
        }
        if encoded not in existing:
            row.setdefault("observations", []).append(observation)
        return True

    def observe_url_components(
        self,
        value: str,
        *,
        producer: str,
        source: str,
        status: str,
        within_target: bool,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        canonical = canonical_url(value)
        if not canonical:
            return
        attrs = attributes if isinstance(attributes, dict) else {}
        self.observe("url", canonical, producer=producer, source=source, status=status, within_target=within_target, attributes=attrs)
        origin, path, names = _url_components(canonical)
        if origin:
            self.observe("origin", origin, producer=producer, source=source, status=status, within_target=within_target, attributes=attrs)
        if origin and path:
            path_attrs = {**attrs, "origin": origin}
            self.observe("path", path, producer=producer, source=source, status=status, within_target=within_target, attributes=path_attrs)
        for name in names:
            self.observe(
                "parameter", name, producer=producer, source=source, status=status,
                within_target=within_target, attributes={"name": name, "location": "query", "url": canonical},
            )

    @staticmethod
    def _render(row: dict[str, Any]) -> dict[str, Any]:
        observations = sorted(
            [item for item in row.get("observations", []) if isinstance(item, dict)],
            key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
        )
        promotable = any(
            item.get("within_target") and item.get("observed") and item.get("status") in PROMOTABLE_STATUSES
            for item in observations
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": row["kind"],
            "key": row["key"],
            "value": row["value"],
            "within_target": any(bool(item.get("within_target")) for item in observations),
            "promotable": bool(promotable),
            "statuses": sorted({str(item.get("status", "")) for item in observations if item.get("status")}),
            "observations": observations,
        }

    def records(self, kind: str | None = None, *, promotable_only: bool = False) -> list[dict[str, Any]]:
        rows = [self._render(row) for row in self.rows.values() if kind is None or row.get("kind") == kind]
        if promotable_only:
            rows = [row for row in rows if row["promotable"]]
        return sorted(rows, key=lambda row: (str(row["kind"]), str(row["key"])))

    def save(self) -> dict[str, Any]:
        directory = self.directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        records = self.records()
        _atomic_write(directory / "bus.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in records))
        provenance: list[dict[str, Any]] = []
        for row in records:
            for observation in row["observations"]:
                provenance.append({"kind": row["kind"], "key": row["key"], "value": row["value"], **observation})
        provenance.sort(key=lambda row: json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
        _atomic_write(directory / "provenance.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in provenance))
        queue_dir = directory / "queues"
        queue_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        counts: dict[str, int] = {}
        promoted: dict[str, int] = {}
        for kind in ARTIFACT_KINDS:
            kind_rows = self.records(kind)
            promoted_rows = [row for row in kind_rows if row["promotable"]]
            counts[kind] = len(kind_rows)
            promoted[kind] = len(promoted_rows)
            name = _PLURALS[kind]
            _atomic_write(directory / f"{name}.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in kind_rows))
            _atomic_write(queue_dir / f"{name}.jsonl", "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in promoted_rows))
        schema = {
            "schema_version": SCHEMA_VERSION,
            "kinds": list(ARTIFACT_KINDS),
            "record_fields": ["schema_version", "kind", "key", "value", "within_target", "promotable", "statuses", "observations"],
            "observation_fields": ["producer", "source", "status", "within_target", "observed", "attributes"],
            "promotable_statuses": sorted(PROMOTABLE_STATUSES),
            "rules": [
                "dedupe uses (kind,key) and never discards observation provenance",
                "promotable requires at least one within_target completed observation",
                "failed/timeout/skipped/planned/gated/candidate observations never become positive merely by existing",
                "URL query values are not persisted in canonical records; parameter names are modeled separately",
            ],
        }
        _atomic_write(directory / "schema.json", json.dumps(schema, indent=2, sort_keys=True) + "\n")
        summary = {
            "schema_version": SCHEMA_VERSION,
            "records": len(records),
            "observations": len(provenance),
            "counts": counts,
            "promotable": promoted,
        }
        _atomic_write(directory / "summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")
        return summary


def ingest_graph(bus: ArtifactBus, graph: Any) -> int:
    count = 0
    if graph is None:
        return count
    rows = list(getattr(graph, "nodes", {}).values())
    mapping = {
        "domain": "host", "hostname": "host", "ip": "ip", "url": "url", "origin": "origin",
        "service": "service", "technology": "technology", "certificate": "fingerprint", "device": "fingerprint",
    }
    for row in rows:
        source_kind = str(row.get("kind", ""))
        kind = mapping.get(source_kind)
        if not kind:
            continue
        within_target = bool(row.get("within_target", False))
        status = "success" if within_target else "candidate"
        attributes: dict[str, Any] = {"graph_kind": source_kind, "depth": int(row.get("depth", 0) or 0)}
        if source_kind in {"certificate", "device"}:
            attributes["namespace"] = source_kind
        producers = row.get("sources", []) if isinstance(row.get("sources"), list) else []
        if not producers:
            producers = ["asset-graph"]
        for producer in producers:
            if bus.observe(
                kind, str(row.get("value", "")), producer=str(producer) or "asset-graph",
                source="graph/assets.jsonl", status=status, within_target=within_target,
                attributes=attributes,
            ):
                count += 1
        if source_kind == "url" and within_target:
            bus.observe_url_components(
                str(row.get("value", "")), producer="asset-graph", source="graph/assets.jsonl",
                status="success", within_target=True,
            )
    return count


def ingest_http_inventory(bus: ArtifactBus, root: Path, allow: Callable[[str], bool]) -> int:
    count = 0
    path = root / "http-inventory" / "observed.jsonl"
    for row in _jsonl(path):
        origin = str(row.get("origin", ""))
        final_url = str(row.get("final_url", ""))
        try:
            code = int(row.get("status") or 0)
        except (TypeError, ValueError):
            code = 0
        status = "http-200" if code == 200 and not row.get("error") else ("http-observed" if code else "failed")
        for value in (origin, final_url):
            if not value:
                continue
            within_target = bool(allow(value))
            bus.observe_url_components(
                value,
                producer="http-inventory",
                source="http-inventory/observed.jsonl",
                status=status,
                within_target=within_target,
                attributes={"status_code": code},
            )
            count += 1
        host_ip = str(row.get("host_ip", ""))
        if host_ip:
            bus.observe("ip", host_ip, producer="http-inventory", source="http-inventory/observed.jsonl", status=status, within_target=bool(allow(host_ip)))
        technologies = row.get("technologies", [])
        if isinstance(technologies, list) and code == 200:
            for technology in technologies:
                bus.observe(
                    "technology", str(technology), producer="http-inventory", source="http-inventory/observed.jsonl",
                    status="success", within_target=bool(allow(origin or final_url)), attributes={"origin": canonical_origin(origin or final_url)},
                )
        body_hash = str(row.get("body_sha256", ""))
        if body_hash and code == 200:
            bus.observe(
                "fingerprint", body_hash, producer="http-inventory", source="http-inventory/observed.jsonl",
                status="success", within_target=bool(allow(origin or final_url)), attributes={"namespace": "http-body-sha256", "origin": canonical_origin(origin or final_url)},
            )
    return count


def ingest_web_fanout(bus: ArtifactBus, root: Path, allow: Callable[[str], bool]) -> int:
    destination = root / "web-fanout"
    if not destination.is_dir():
        return 0
    files = sorted({*destination.rglob("crawl*.txt"), *destination.rglob("directory-*.txt")})
    count = 0
    seen: set[tuple[str, str]] = set()
    for path in files:
        if not path.is_file() or path.stat().st_size > 20_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(root))
        for raw in URL_RE.findall(text):
            value = raw.rstrip(".,;:)]}")
            canonical = canonical_url(value)
            if not canonical or (relative, canonical) in seen:
                continue
            seen.add((relative, canonical))
            within_target = bool(allow(value))
            bus.observe_url_components(
                value, producer="web-fanout", source=relative,
                status="success" if within_target else "outside-target", within_target=within_target,
            )
            count += 1
    return count


def ingest_device_inventory(bus: ArtifactBus, root: Path, allow: Callable[[str], bool]) -> int:
    count = 0
    paths = [path for path in root.rglob("device-inventory.jsonl") if "artifacts" not in path.parts and "inventory" not in path.parts]
    for path in sorted(set(paths)):
        relative = str(path.relative_to(root))
        for row in _jsonl(path):
            host = str(row.get("host", ""))
            within_target = bool(host and allow(host))
            if host:
                kind = "ip" if canonical_ip(host) else "host"
                bus.observe(kind, host, producer="device-surface", source=relative, status="success", within_target=within_target, attributes={"device": True})
            port = row.get("port")
            if host and port:
                bus.observe(
                    "service", "", producer="device-surface", source=relative, status="success", within_target=within_target,
                    attributes={"host": host, "port": port, "protocol": row.get("protocol", "tcp"), "service": "device-surface"},
                )
            for model in row.get("models", []) if isinstance(row.get("models"), list) else []:
                bus.observe(
                    "fingerprint", str(model), producer="device-surface", source=relative, status="success", within_target=within_target,
                    attributes={"namespace": "device-model", "host": canonical_host(host)},
                )
            for key, namespace in (("vendor", "device-vendor"), ("technology", "device-technology")):
                value = row.get(key)
                values = value if isinstance(value, list) else [value] if value else []
                for item in values:
                    bus.observe(
                        "fingerprint" if key == "vendor" else "technology", str(item), producer="device-surface", source=relative,
                        status="success", within_target=within_target,
                        attributes={"namespace": namespace, "host": canonical_host(host)} if key == "vendor" else {"host": canonical_host(host)},
                    )
            count += 1
    return count


def ingest_advanced_consumers(bus: ArtifactBus, root: Path, allow: Callable[[str], bool]) -> int:
    path = root / "advanced-consumers" / "runs.jsonl"
    count = 0
    for row in _jsonl(path):
        runner = _safe_text(row.get("runner", "unknown"), limit=128) or "unknown"
        origin = str(row.get("origin", ""))
        status = _safe_text(row.get("status", "unknown"), limit=64).lower() or "unknown"
        within_target = bool(origin and allow(origin))
        artifacts = row.get("artifacts", []) if isinstance(row.get("artifacts"), list) else []
        safe_artifacts = []
        for artifact in artifacts:
            if isinstance(artifact, dict):
                safe_artifacts.append({key: artifact.get(key) for key in ("path", "exists", "size", "sha256") if key in artifact})
            elif artifact:
                safe_artifacts.append(_safe_text(artifact, limit=512))
        bus.observe(
            "finding", f"consumer-run:{runner}:{canonical_origin(origin) or origin}", producer=runner,
            source="advanced-consumers/runs.jsonl", status=status, within_target=within_target,
            observed=status in {"success", "partial", "failed", "timeout"},
            attributes={"finding_type": "consumer-execution", "origin": canonical_origin(origin), "exit_code": row.get("exit_code"), "artifacts": safe_artifacts},
        )
        count += 1
    return count


def _safe_allow(allow: Callable[[str], bool], value: str) -> bool:
    try:
        return bool(allow(value))
    except (TypeError, ValueError, OSError):
        return False


def _typed_record_allowed(
    row: dict[str, Any],
    allow: Callable[[str], bool],
    network_allow: Callable[[str], bool],
) -> bool:
    kind = str(row.get("kind", ""))
    value = str(row.get("value", ""))
    attributes = row.get("attributes", {})
    if not isinstance(attributes, dict):
        attributes = {}
    if kind in {"host", "ip"}:
        return _safe_allow(network_allow, value)
    if kind == "service":
        host = canonical_host(str(attributes.get("host") or value))
        return bool(host and _safe_allow(network_allow, host))
    if kind in {"origin", "url", "path", "parameter"}:
        for candidate in (
            value,
            str(attributes.get("url", "")),
            str(attributes.get("origin", "")),
        ):
            if candidate and _safe_allow(allow, candidate):
                return True
        return False
    if isinstance(row.get("within_target"), bool):
        return bool(row.get("within_target"))
    for key in ("url", "origin", "host", "ip", "service"):
        candidate = str(attributes.get(key, ""))
        if not candidate:
            continue
        if _safe_allow(allow, candidate) or _safe_allow(network_allow, candidate):
            return True
    return False


def ingest_typed_pipeline(bus: ArtifactBus, root: Path, allow: Callable[[str], bool], allow_network: Callable[[str], bool] | None = None) -> int:
    """Ingest normalized typed-pipeline records into the canonical run bus.

    The typed pipeline already writes one ``records.jsonl`` per method. This
    adapter is intentionally generic: it trusts only supported artifact kinds,
    re-runs target-boundary checks before promotion, and uses the evidence file
    path as provenance so downstream stages can consume the same bus without
    bespoke handoff glue.
    """
    network_allow = allow_network or allow
    count = 0
    pipeline_root = root / "typed-pipeline"
    if not pipeline_root.is_dir():
        return 0
    for record_file in sorted(pipeline_root.rglob("records.jsonl")):
        try:
            source = str(record_file.relative_to(root))
        except ValueError:
            source = str(record_file)
        for row in _jsonl(record_file):
            if row.get("promotable") is False:
                continue
            kind = str(row.get("kind", ""))
            if kind not in ARTIFACT_KINDS:
                continue
            value = str(row.get("value", ""))
            status = str(row.get("status", "success")).strip().lower() or "success"
            attributes = row.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
            producer = f"typed-pipeline/{row.get('tool_id', 'unknown')}"
            within_target = _typed_record_allowed(row, allow, network_allow)
            if kind == "url":
                before = len(bus.records())
                bus.observe_url_components(
                    value,
                    producer=producer,
                    source=source,
                    status=status,
                    within_target=within_target,
                    attributes=attributes,
                )
                if len(bus.records()) > before or within_target:
                    count += 1
            elif kind == "path" and canonical_url(value):
                before = len(bus.records())
                bus.observe_url_components(
                    value,
                    producer=producer,
                    source=source,
                    status=status,
                    within_target=within_target,
                    attributes=attributes,
                )
                if len(bus.records()) > before or within_target:
                    count += 1
            elif bus.observe(
                kind,
                value,
                producer=producer,
                source=source,
                status=status,
                within_target=within_target,
                attributes=attributes,
            ):
                count += 1
    return count


def sync_sources(bus: ArtifactBus, root: Path, graph: Any, allow: Callable[[str], bool], allow_network: Callable[[str], bool] | None = None) -> dict[str, int]:
    network_allow = allow_network or allow
    counts = {
        "graph": ingest_graph(bus, graph),
        "typed_pipeline": ingest_typed_pipeline(bus, root, allow, network_allow),
        "http": ingest_http_inventory(bus, root, allow),
        "web": ingest_web_fanout(bus, root, allow),
        "device": ingest_device_inventory(bus, root, network_allow),
        "advanced": ingest_advanced_consumers(bus, root, allow),
    }
    return counts
