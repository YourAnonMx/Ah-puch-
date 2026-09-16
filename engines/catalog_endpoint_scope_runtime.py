#!/usr/bin/env python3
"""Exact target-boundary guard for active catalog network samplers.

SRC07 uses the catalog Open Ports (9) and UDP Service Sampler (44) as bounded
follow-up consumers. It validates target membership and concrete ports before
the existing catalog modules build a subprocess.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

try:
    from . import catalog_open_ports_runtime
except ImportError:
    import catalog_open_ports_runtime

_TCP_ID = "9"
_UDP_ID = "44"
_DEFAULTS = {
    _TCP_ID: "1-1024",
    _UDP_ID: "53,123,161,500,514,69",
}


def _parse_ports(value: object) -> list[int]:
    text = str(value or "").strip()
    if not text:
        raise ValueError("port expression is empty")
    ports: set[int] = set()
    for raw in text.split(","):
        token = raw.strip()
        if not token:
            raise ValueError("empty port token")
        if "-" in token:
            fields = token.split("-")
            if len(fields) != 2 or not all(field.isdigit() for field in fields):
                raise ValueError(f"invalid port range: {token}")
            start, end = (int(field) for field in fields)
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"invalid port: {token}")
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"port outside 1-65535: {token}")
            ports.add(port)
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


def _target_allows(run: Any, value: str) -> bool:
    """Check one host or URL against the automatic target boundary."""
    checker = getattr(run, "_target_boundary_allows", None)
    if callable(checker):
        return bool(checker(value))
    if str(value).startswith(("http://", "https://")):
        return bool(run._allowed(value))
    allow_network = getattr(run, "_network_allowed", run._allowed)
    return bool(allow_network(value))


def endpoint_allowed(run: Any, input_value: str, port: int) -> bool:
    """Re-check one concrete endpoint at the immediate execution boundary."""
    try:
        number = int(port)
    except (TypeError, ValueError):
        return False
    if not 1 <= number <= 65535:
        return False

    text = str(input_value).strip()
    if not _target_allows(run, text):
        return False
    if text.startswith(("http://", "https://")):
        try:
            host = urlsplit(text).hostname or ""
        except ValueError:
            return False
    else:
        host = text

    return bool(host)


def _effective_ports(run: Any, module_id: str, input_value: str) -> tuple[str, str]:
    requested_spec = str(getattr(run, "option_overrides", {}).get("ports", _DEFAULTS[module_id]) or _DEFAULTS[module_id])
    try:
        requested = _parse_ports(requested_spec)
    except (TypeError, ValueError) as exc:
        return "", f"invalid requested port expression: {exc}"

    allowed = requested if _target_allows(run, input_value) else []
    if not allowed:
        protocol = "TCP" if module_id == _TCP_ID else "UDP"
        return "", f"target boundary rejects the requested {protocol} endpoint"
    return _format_ports(allowed), ""


def _udp_control_error(run: Any) -> str:
    overrides = getattr(run, "option_overrides", {})
    checks = (
        ("retries", 1, 5),
        ("max_hosts", 1, 65536),
    )
    for key, minimum, maximum in checks:
        if key not in overrides:
            continue
        raw = overrides[key]
        if isinstance(raw, bool):
            return f"{key} must be an integer from {minimum} through {maximum}"
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return f"{key} must be an integer from {minimum} through {maximum}"
        if not minimum <= value <= maximum:
            return f"{key} must be an integer from {minimum} through {maximum}"
    return ""


def _write_gate(base: Any, run: Any, item: dict[str, Any], input_value: str, index: int, reason: str) -> None:
    module_id = str(item.get("id", ""))
    name = str(item.get("name", item.get("script", "module")))
    destination = run.module_root / f"{module_id}-{base.slug(name)}" / str(index)
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    run.write_module_text(
        destination,
        {
            "engine": "catalog_endpoint_scope",
            "module_id": module_id,
            "module": name,
            "script": str(item.get("script", "")),
            "class": base.module_class(item),
            "input": input_value,
            "reason": reason,
        },
        "gated",
        "Catalog network sampler was not started because endpoint controls or the target boundary rejected the dispatch.\n",
    )


def install(base: Any) -> Any:
    """Install exact-port filtering over modules 9 and 44 exactly once."""
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_catalog_endpoint_scope", False):
        return base

    class CatalogEndpointScopeUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_catalog_endpoint_scope = True

        def run_catalog_module(self, item: dict[str, Any], input_value: str, index: int) -> None:
            module_id = str(item.get("id", ""))
            if module_id not in {_TCP_ID, _UDP_ID}:
                super().run_catalog_module(item, input_value, index)
                return

            if module_id == _UDP_ID:
                control_error = _udp_control_error(self)
                if control_error:
                    _write_gate(base, self, item, input_value, index, control_error)
                    return

            effective_ports, reason = _effective_ports(self, module_id, input_value)
            if reason:
                _write_gate(base, self, item, input_value, index, reason)
                return

            effective_item = dict(item)
            additions = ["ports"] + (["retries", "max_hosts"] if module_id == _UDP_ID else [])
            effective_item["options"] = list(dict.fromkeys([*item.get("options", []), *additions]))
            previous = self.option_overrides.get("ports")
            had_previous = "ports" in self.option_overrides
            self.option_overrides["ports"] = effective_ports
            try:
                super().run_catalog_module(effective_item, input_value, index)
            finally:
                if had_previous:
                    self.option_overrides["ports"] = previous
                else:
                    self.option_overrides.pop("ports", None)

    CatalogEndpointScopeUnifiedRun.__name__ = "CatalogEndpointScopeUnifiedRun"
    CatalogEndpointScopeUnifiedRun.__qualname__ = "CatalogEndpointScopeUnifiedRun"
    base.UnifiedRun = CatalogEndpointScopeUnifiedRun
    return base
