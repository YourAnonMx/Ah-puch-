#!/usr/bin/env python3
"""Canonical public target and selector-input contract for Ah-Puch.

This layer reuses the existing runner parser/normalizer but removes ambiguous
input behavior from the public entry: target-file rows are never silently
truncated or discarded, duplicates are deterministic, malformed rows fail with
line-level diagnostics, and contradictory native profile selectors fail before
any target execution starts.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
HTTP_SCHEME_RE = re.compile(r"^(https?)://", re.I)
_PROFILE_CAPABILITIES = {"profile-baseline", "profile-full", "profile-deep"}


class TargetInputError(ValueError):
    """Invalid public target/selector input; safe to render as a CLI parser error."""


@dataclass(frozen=True)
class TargetRow:
    line: int
    raw_sha256: str
    canonical: str
    kind: str
    duplicate: bool
    error: str


@dataclass(frozen=True)
class TargetFileReport:
    path: Path
    rows: tuple[TargetRow, ...]

    @property
    def targets(self) -> list[str]:
        return [row.canonical for row in self.rows if row.canonical and not row.duplicate and not row.error]

    @property
    def invalid(self) -> list[TargetRow]:
        return [row for row in self.rows if row.error]

    @property
    def duplicates(self) -> list[TargetRow]:
        return [row for row in self.rows if row.duplicate]


def target_kind(value: str) -> str:
    raw = str(value).strip()
    if JWT_RE.fullmatch(raw):
        return "token"
    if HTTP_SCHEME_RE.match(raw):
        return "url"
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return "ipv6-cidr" if network.version == 6 else "ipv4-cidr"
        except ValueError:
            pass
    host = raw
    port_qualified = False
    if raw.startswith("[") and "]" in raw:
        end = raw.index("]")
        host = raw[1:end]
        suffix = raw[end + 1:]
        port_qualified = bool(suffix.startswith(":") and suffix[1:].isdigit())
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host = raw.rsplit(":", 1)[0]
        port_qualified = True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        kind = "ipv6" if address.version == 6 else "ipv4"
        return f"{kind}-port" if port_qualified else kind
    except ValueError:
        return "hostname-port" if port_qualified else "hostname"


def target_sha256(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _seed_host(value: str) -> tuple[str, int | None, str]:
    """Return canonical host, optional port, and input kind for executable seeds."""
    raw = str(value).strip()
    kind = target_kind(raw)
    if kind == "token" or kind.endswith("-cidr"):
        return "", None, kind
    if HTTP_SCHEME_RE.match(raw):
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
    elif raw.startswith("[") and "]" in raw:
        end = raw.index("]")
        host = raw[1:end]
        suffix = raw[end + 1:]
        port = int(suffix[1:]) if suffix.startswith(":") and suffix[1:].isdigit() else None
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, port_text = raw.rsplit(":", 1)
        port = int(port_text)
    else:
        host, port = raw.strip("[]"), None
    host = host.strip().strip("[]").rstrip(".")
    if not host:
        return "", None, kind
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").casefold()
        except UnicodeError:
            return "", None, kind
    return host, port, kind


def _http_authority(host: str, port: int | None = None) -> str:
    display = f"[{host}]" if ":" in host else host
    return display if port is None else f"{display}:{port}"


def target_host_seed(value: str) -> str:
    """Return the concrete host/IP seed for scanners, excluding CIDR and tokens."""
    host, _port, _kind = _seed_host(value)
    return host


def target_domain_seed(value: str) -> str:
    """Return a DNS-name seed, excluding IP literals, CIDR ranges and tokens."""
    host = target_host_seed(value)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        return host


def target_ip_seed(value: str) -> str:
    """Return an IP literal seed, excluding DNS names, CIDR ranges and tokens."""
    host = target_host_seed(value)
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


def target_network_seeds(value: str) -> list[str]:
    """Return values suitable for network/range tools without host:port leakage."""
    raw = str(value).strip()
    kind = target_kind(raw)
    if kind.endswith("-cidr"):
        try:
            return [str(ipaddress.ip_network(raw, strict=False))]
        except ValueError:
            return []
    host = target_host_seed(raw)
    return [host] if host else []


def target_http_origin_seeds(value: str) -> list[str]:
    """Return initial HTTP(S) origins only for URL, host, IP, or host:port targets."""
    raw = str(value).strip()
    if HTTP_SCHEME_RE.match(raw):
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return []
        host = parsed.hostname.lower().rstrip(".")
        authority = _http_authority(host, parsed.port)
        return [urlunsplit((parsed.scheme.lower(), authority, "/", "", ""))]
    host, port, kind = _seed_host(raw)
    if not host or kind == "token" or kind.endswith("-cidr"):
        return []
    authority = _http_authority(host, port)
    return [f"https://{authority}/", f"http://{authority}/"]


def target_url_seeds(value: str) -> list[str]:
    """Return executable URL seeds, preserving a supplied URL path/query."""
    raw = str(value).strip()
    if HTTP_SCHEME_RE.match(raw):
        return [raw]
    return target_http_origin_seeds(raw)


def target_parameter_url_seeds(value: str) -> list[str]:
    raw = str(value).strip()
    if not HTTP_SCHEME_RE.match(raw):
        return []
    try:
        return [raw] if urlsplit(raw).query else []
    except ValueError:
        return []


def target_service_seeds(value: str) -> list[str]:
    """Return concrete TCP service seeds implied by a URL scheme or host:port."""
    raw = str(value).strip()
    if HTTP_SCHEME_RE.match(raw):
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return []
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return [f"tcp://{_http_authority(host, port)}"]
    host, port, kind = _seed_host(raw)
    if not host or port is None or kind == "token" or kind.endswith("-cidr"):
        return []
    return [f"tcp://{_http_authority(host, port)}"]


def target_seed_ports(value: str) -> list[int]:
    ports: list[int] = []
    for service in target_service_seeds(value):
        try:
            port = int(urlsplit(service).port or 0)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def public_target(value: str) -> str:
    """Return a non-secret display target suitable for receipts and filenames."""
    raw = str(value).strip()
    if JWT_RE.fullmatch(raw):
        return f"[TOKEN:{target_sha256(raw)[:12]}]"
    match = HTTP_SCHEME_RE.match(raw)
    if not match:
        return raw
    raw = match.group(1).lower() + "://" + raw[match.end():]
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return "[INVALID-TARGET]"
    if not parsed.hostname:
        return "[INVALID-TARGET]"
    host = parsed.hostname.lower().rstrip(".")
    display = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        port = None
    default = 443 if parsed.scheme.lower() == "https" else 80
    netloc = display if not port or port == default else f"{display}:{port}"
    names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    query = urlencode([(name, "") for name in names])
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))


def _canonicalize_validated(value: str) -> str:
    """Collapse equivalent validated target identities deterministically."""
    raw = str(value).strip()
    if JWT_RE.fullmatch(raw):
        return raw
    if HTTP_SCHEME_RE.match(raw):
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        display = f"[{host}]" if ":" in host else host
        port = parsed.port
        default = 443 if parsed.scheme.lower() == "https" else 80
        netloc = display if not port or port == default else f"{display}:{port}"
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    if "/" in raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            return raw
    if raw.startswith("[") and "]" in raw:
        end = raw.index("]")
        address = str(ipaddress.ip_address(raw[1:end]))
        suffix = raw[end + 1:]
        return f"[{address}]{suffix}"
    if raw.count(":") > 1:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return raw.lower()
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        try:
            normalized_host = str(ipaddress.ip_address(host))
        except ValueError:
            normalized_host = host.lower().rstrip(".")
        return f"{normalized_host}:{port}"
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw.lower().rstrip(".")


def strict_clean_target(value: str, normalizer: Callable[[str], str]) -> str:
    raw = str(value).strip()
    if not raw:
        raise TargetInputError("target is empty")
    if any(character.isspace() for character in raw):
        raise TargetInputError("target contains whitespace; encode URL characters and keep one target per row")
    match = HTTP_SCHEME_RE.match(raw)
    if match:
        raw = match.group(1).lower() + "://" + raw[match.end():]
    try:
        canonical = normalizer(raw)
    except ValueError as exc:
        raise TargetInputError(str(exc)) from exc
    if not canonical:
        raise TargetInputError("target normalized to an empty value")
    return _canonicalize_validated(canonical)


def parse_targets_file(path: Path, normalizer: Callable[[str], str]) -> TargetFileReport:
    path = Path(path).expanduser()
    if not path.is_file() or path.is_symlink():
        raise TargetInputError(f"target file is not a regular file: {path}")
    rows: list[TargetRow] = []
    seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise TargetInputError(f"target file is not valid UTF-8: {path}") from exc
    for number, raw_line in enumerate(lines, 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        digest = target_sha256(stripped)
        try:
            canonical = strict_clean_target(stripped, normalizer)
        except TargetInputError as exc:
            rows.append(TargetRow(number, digest, "", "invalid", False, str(exc)))
            continue
        duplicate = canonical in seen
        seen.add(canonical)
        rows.append(TargetRow(number, digest, canonical, target_kind(canonical), duplicate, ""))
    return TargetFileReport(path=path.resolve(), rows=tuple(rows))


def strict_read_raw_targets(path: Path, normalizer: Callable[[str], str]) -> list[str]:
    report = parse_targets_file(path, normalizer)
    if report.invalid:
        details = "; ".join(f"line {row.line}: {row.error}" for row in report.invalid[:20])
        if len(report.invalid) > 20:
            details += f"; plus {len(report.invalid) - 20} more invalid rows"
        raise TargetInputError(f"target file contains {len(report.invalid)} invalid row(s): {details}")
    targets = report.targets
    if not targets:
        raise TargetInputError("target file contains no executable targets")
    return targets


def validate_selector_selection(args: Any, rows: list[dict[str, Any]]) -> set[str]:
    """Validate mutually exclusive native selector choices before run construction."""
    chosen = {value.strip() for value in str(getattr(args, "catalog_modules", "") or "").split(",") if value.strip()}
    if not chosen:
        return set()
    by_id = {str(row.get("id", "")): row for row in rows}
    capabilities = {
        str(by_id[module_id].get("native_capability", "")).strip()
        for module_id in chosen
        if module_id in by_id and by_id[module_id].get("native_capability")
    }
    profiles = sorted(capabilities & _PROFILE_CAPABILITIES)
    if len(profiles) > 1:
        raise TargetInputError("choose exactly one native profile selector: baseline, full, or deep")
    return capabilities


def install(base: Any) -> Any:
    """Install strict input behavior over the existing canonical normalizer."""
    if getattr(base, "_ah_puch_target_contract", False):
        return base
    original_clean = base.clean_target
    original_slug = base.slug
    current = base.UnifiedRun

    def clean_target(value: str) -> str:
        return strict_clean_target(value, original_clean)

    def read_raw_targets(path: Path) -> list[str]:
        return strict_read_raw_targets(path, original_clean)

    def safe_slug(value: str, limit: int = 120) -> str:
        raw = str(value)
        if JWT_RE.fullmatch(raw):
            raw = f"token-{target_sha256(raw)[:16]}"
        elif HTTP_SCHEME_RE.match(raw):
            display = public_target(raw)
            raw = f"{display}-{target_sha256(raw)[:12]}"
        return original_slug(raw)[:max(1, int(limit))]

    class TargetInputUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_target_input = True

        def __init__(self, target: str, args: Any):
            validate_selector_selection(args, base.load_modules())
            super().__init__(target, args)

    TargetInputUnifiedRun.__name__ = "TargetInputUnifiedRun"
    TargetInputUnifiedRun.__qualname__ = "TargetInputUnifiedRun"

    base.clean_target = clean_target
    base.read_raw_targets = read_raw_targets
    base.slug = safe_slug
    base.UnifiedRun = TargetInputUnifiedRun
    base._ah_puch_target_contract = True
    return base
