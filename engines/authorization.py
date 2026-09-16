#!/usr/bin/env python3
"""Machine-verifiable Ah-Puch authorization manifest reader.

The human Rules of Engagement remains the source of authority. This module only
narrows runtime eligibility; it never infers authorization from reachability or
discovery. A live manifest is bound to the exact owner-approved source corpus
by SHA-256 and may narrow hosts, ports, paths, services and actions per row.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

AUTHORIZATION_REFERENCE = "AH-PUCH-AUTH-CONVERGE-2026-001"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_sha256(path: Path) -> str:
    """Hash either one source file or a deterministic regular-file directory tree.

    Directory hashing binds relative path + file digest for every regular file
    in lexical order. Symlinks and non-regular entries are rejected so changing
    the corpus layout cannot silently redirect the authorization source.
    """
    if path.is_file() and not path.is_symlink():
        return _file_sha256(path)
    if not path.is_dir() or path.is_symlink():
        raise ValueError("authorization source_path must be a regular file or directory")
    digest = hashlib.sha256()
    regular_files: list[Path] = []
    for item in path.rglob("*"):
        if item.is_symlink():
            raise ValueError(f"authorization source corpus contains symlink: {item.relative_to(path)}")
        if item.is_file():
            regular_files.append(item)
        elif not item.is_dir():
            raise ValueError(f"authorization source corpus contains non-regular entry: {item.relative_to(path)}")
    for item in sorted(regular_files, key=lambda value: value.relative_to(path).as_posix()):
        relative = item.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_file_sha256(item)))
    return digest.hexdigest()


def _host(value: str) -> str:
    raw = str(value).strip()
    if raw.startswith(("http://", "https://")):
        try:
            return (urlsplit(raw).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    if raw.startswith("[") and "]" in raw:
        return raw[1 : raw.index("]")].lower().rstrip(".")
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        return raw.rsplit(":", 1)[0].lower().rstrip(".")
    return raw.strip("[]").lower().rstrip(".")


def _candidate_port(value: str) -> int | None:
    raw = str(value).strip()
    if raw.startswith(("http://", "https://")):
        try:
            parsed = urlsplit(raw)
            return parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return None
    if raw.startswith("[") and "]" in raw:
        suffix = raw[raw.index("]") + 1 :]
        if suffix.startswith(":") and suffix[1:].isdigit():
            return int(suffix[1:])
        return None
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        return int(raw.rsplit(":", 1)[1])
    return None


def _authority_with_port(value: str, port: int) -> str:
    """Return a host:port authority suitable for exact manifest checks."""
    host = _host(value)
    if not host or not 1 <= int(port) <= 65535:
        return ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{int(port)}"
    return f"[{address}]:{int(port)}" if address.version == 6 else f"{address}:{int(port)}"


def _candidate_path(value: str) -> str:
    raw = str(value).strip()
    if not raw.startswith(("http://", "https://")):
        return ""
    try:
        path = unquote(urlsplit(raw).path or "/")
    except ValueError:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    return path


def _normal_path(value: str) -> str:
    raw = unquote(str(value).strip() or "/")
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw.rstrip("/") or "/"


def _path_allowed(candidate: str, roots: set[str]) -> bool:
    if not roots:
        return True
    path = _normal_path(candidate)
    for root in roots:
        normalized = _normal_path(root)
        if normalized == "/" or path == normalized or path.startswith(normalized + "/"):
            return True
    return False


def _same_target(candidate: str, allowed: str) -> bool:
    c = str(candidate).strip()
    a = str(allowed).strip()
    try:
        allowed_net = ipaddress.ip_network(a, strict=False)
        try:
            candidate_net = ipaddress.ip_network(c, strict=False) if "/" in c else None
        except ValueError:
            candidate_net = None
        if candidate_net is not None:
            return candidate_net.version == allowed_net.version and candidate_net.subnet_of(allowed_net)
        return ipaddress.ip_address(_host(c)) in allowed_net
    except ValueError:
        pass

    if a.startswith(("http://", "https://")):
        # URL scope is exact authority and scheme. A path in the target row
        # narrows the URL subtree rather than authorizing the whole host.
        if not c.startswith(("http://", "https://")):
            return False
        try:
            ca, aa = urlsplit(c), urlsplit(a)
            cp = ca.port or (443 if ca.scheme == "https" else 80)
            ap = aa.port or (443 if aa.scheme == "https" else 80)
            same_authority = (
                ca.scheme.lower() == aa.scheme.lower()
                and (ca.hostname or "").lower().rstrip(".") == (aa.hostname or "").lower().rstrip(".")
                and cp == ap
            )
            if not same_authority:
                return False
            allowed_path = _normal_path(aa.path or "/")
            candidate_path = _normal_path(ca.path or "/")
            return allowed_path == "/" or candidate_path == allowed_path or candidate_path.startswith(allowed_path + "/")
        except ValueError:
            return False

    # A host:port row narrows the port as well as the host.
    if _host(c) != _host(a):
        return False
    allowed_port = _candidate_port(a)
    return allowed_port is None or _candidate_port(c) == allowed_port


def _int_set(values: object, field: str) -> set[int]:
    if values in (None, []):
        return set()
    if not isinstance(values, list):
        raise ValueError(f"{field} must be a list")
    result: set[int] = set()
    for value in values:
        if isinstance(value, bool):
            raise ValueError(f"{field} contains an invalid port")
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} contains an invalid port") from exc
        if not 1 <= number <= 65535:
            raise ValueError(f"{field} port outside 1-65535")
        result.add(number)
    return result


@dataclass(frozen=True)
class AuthorizationManifest:
    path: Path
    source_path: Path
    source_sha256: str
    rows: tuple[dict, ...]

    @classmethod
    def load(cls, path: Path) -> "AuthorizationManifest":
        raw = json.loads(path.read_text(encoding="utf-8"))
        reference = str(raw.get("authorization_reference", ""))
        if reference != AUTHORIZATION_REFERENCE:
            raise ValueError("authorization reference mismatch")
        source_sha = str(raw.get("source_sha256", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", source_sha):
            raise ValueError("manifest source_sha256 must be a 64-character SHA-256")
        source_value = str(raw.get("source_path", "")).strip()
        if not source_value:
            raise ValueError("manifest source_path is required for machine-verifiable authorization")
        source_path = Path(source_value).expanduser().resolve()
        if not source_path.exists():
            raise ValueError("manifest source_path does not exist")
        actual_sha = _source_sha256(source_path)
        if actual_sha != source_sha:
            raise ValueError("authorization source corpus SHA-256 mismatch")

        targets = raw.get("targets", [])
        if not isinstance(targets, list) or not targets:
            raise ValueError("manifest targets must be a non-empty list")
        rows: list[dict] = []
        for item in targets:
            if not isinstance(item, dict) or not str(item.get("target", "")).strip():
                raise ValueError("every manifest target row requires target")
            actions = item.get("allowed_actions", [])
            if not isinstance(actions, list) or any(not isinstance(value, str) for value in actions):
                raise ValueError("allowed_actions must be a list of strings")
            _int_set(item.get("ports", []), "ports")
            paths = item.get("paths", [])
            if paths not in (None, []) and (not isinstance(paths, list) or any(not isinstance(value, str) for value in paths)):
                raise ValueError("paths must be a list of strings")
            services = item.get("services", [])
            if services not in (None, []) and (not isinstance(services, list) or any(not isinstance(value, str) for value in services)):
                raise ValueError("services must be a list of strings")
            rows.append(dict(item))
        return cls(path=path.resolve(), source_path=source_path, source_sha256=source_sha, rows=tuple(rows))

    def allows(self, target: str, action: str = "assessment", service: str = "") -> bool:
        for row in self.rows:
            if not _same_target(target, str(row.get("target", ""))):
                continue
            actions = {str(value) for value in row.get("allowed_actions", [])}
            if action not in actions and "all-assessment" not in actions:
                continue
            services = {str(value) for value in row.get("services", [])}
            if service and services and service not in services:
                continue
            ports = _int_set(row.get("ports", []), "ports")
            candidate_port = _candidate_port(target)
            if ports and candidate_port is not None and candidate_port not in ports:
                continue
            paths = {_normal_path(value) for value in row.get("paths", [])}
            if paths and target.startswith(("http://", "https://")) and not _path_allowed(_candidate_path(target), paths):
                continue
            return True
        return False

    def allows_port(self, target: str, port: int, action: str = "assessment", service: str = "") -> bool:
        """Check one exact TCP/UDP endpoint without widening host authorization."""
        if isinstance(port, bool):
            return False
        try:
            number = int(port)
        except (TypeError, ValueError):
            return False
        authority = _authority_with_port(target, number)
        return bool(authority and self.allows(authority, action, service))

    def filter_ports(self, target: str, ports: list[int] | tuple[int, ...] | set[int], action: str = "assessment", service: str = "") -> list[int]:
        """Return only requested ports independently authorized for target."""
        allowed: set[int] = set()
        for raw in ports:
            if isinstance(raw, bool):
                continue
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and self.allows_port(target, port, action, service):
                allowed.add(port)
        return sorted(allowed)

    def allows_auth_validation(self, target: str, service: str) -> bool:
        return self.allows(target, "auth-validation", service)
