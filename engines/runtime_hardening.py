#!/usr/bin/env python3
"""Shared safety, privacy, evidence and recovery controls for Ah-Puch.

The public runner and its adapters deliberately remain separate modules, but
their resource limits and durable-state rules must be one policy.  This module
has no target-contact code; it is safe to import from offline tools and tests.
"""
from __future__ import annotations

import contextlib
import contextvars
import datetime as dt
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "runtime_limits.json"
SCHEMA_VERSION = 1
RECEIPT_SCHEMA_VERSION = 1
SECRET_NAMES = frozenset({
    "api-key", "api_key", "apikey", "api-secret", "api_secret", "authorization",
    "auth", "auth-header", "auth_header", "bearer", "client-secret", "client_secret",
    "credential", "credentials", "key", "pass", "passwd", "password", "secret",
    "token", "vt-key", "vt_key",
})
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>\b(?:api[_-]?key|api[_-]?secret|authorization|auth(?:orization)?[_-]?header|"
    r"client[_-]?secret|credential|password|passwd|secret|token|vt[_-]?key)\b)"
    r"(?P<sep>\s*[:=]\s*)(?P<value>[^\s,;&]+)"
)
AUTH_VALUE = re.compile(r"(?i)\b(?:basic|bearer)\s+[^\s,;&]+")


def _load_policy() -> dict[str, Any]:
    try:
        value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid runtime policy {POLICY_PATH}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("runtime policy must be a schema-version 1 object")
    defaults = value.get("defaults")
    caps = value.get("hard_caps")
    if not isinstance(defaults, dict) or not isinstance(caps, dict):
        raise RuntimeError("runtime policy must define defaults and hard_caps")
    for key, default in defaults.items():
        if key not in caps or type(default) is not int or type(caps[key]) is not int:
            raise RuntimeError(f"runtime policy limit is not an integer: {key}")
        if default < 1 or caps[key] < default:
            raise RuntimeError(f"runtime policy limit has invalid range: {key}")
    return value


POLICY = _load_policy()
DEFAULT_LIMITS: dict[str, int] = {
    str(key): int(value) for key, value in POLICY["defaults"].items()
}
HARD_CAPS: dict[str, int] = {
    str(key): int(value) for key, value in POLICY["hard_caps"].items()
}


def _clamp_limit(name: str, value: Any) -> int:
    default = DEFAULT_LIMITS[name]
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(HARD_CAPS[name], parsed))


def validate_namespace_limits(namespace: Any) -> list[str]:
    """Return CLI limit errors instead of silently accepting unsafe values."""
    errors: list[str] = []
    for name in DEFAULT_LIMITS:
        value = getattr(namespace, name, DEFAULT_LIMITS[name])
        if type(value) is not int or value < 1:
            errors.append(f"{name} must be a positive integer")
        elif value > HARD_CAPS[name]:
            errors.append(f"{name} exceeds hard cap {HARD_CAPS[name]}")
    return errors


@dataclass
class ExecutionBudget:
    """Thread-safe per-invocation accounting for requests and evidence.

    A budget exhaustion is a controlled terminal condition.  It never turns a
    missing observation into a success; callers record the reason and continue
    producing truthful partial/skipped evidence where the stage permits it.
    """

    limits: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_LIMITS))
    started_at: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat())
    _started_monotonic: float = field(default_factory=time.monotonic, repr=False)
    _requests: int = field(default=0, init=False, repr=False)
    _results: int = field(default=0, init=False, repr=False)
    _response_bytes: int = field(default=0, init=False, repr=False)
    _executions: int = field(default=0, init=False, repr=False)
    _exhausted: set[str] = field(default_factory=set, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @classmethod
    def from_namespace(cls, namespace: Any) -> "ExecutionBudget":
        limits = {
            name: _clamp_limit(name, getattr(namespace, name, DEFAULT_LIMITS[name]))
            for name in DEFAULT_LIMITS
        }
        return cls(limits=limits)

    def _reserve(self, counter: str, amount: int, label: str) -> bool:
        if amount < 0:
            raise ValueError("budget increments must be non-negative")
        with self._lock:
            if time.monotonic() - self._started_monotonic > self.limits["max_elapsed_seconds"]:
                self._exhausted.add("max_elapsed_seconds")
                return False
            current = int(getattr(self, counter))
            limit_name = {
                "_requests": "max_requests",
                "_results": "max_results",
                "_response_bytes": "max_response_bytes",
                "_executions": "max_executions",
            }[counter]
            if current + amount > self.limits[limit_name]:
                self._exhausted.add(label or limit_name)
                return False
            setattr(self, counter, current + amount)
            return True

    def reserve_request(self, label: str = "request") -> bool:
        return self._reserve("_requests", 1, label)

    def reserve_execution(self, label: str = "execution") -> bool:
        return self._reserve("_executions", 1, label)

    def record_result(self, amount: int = 1, label: str = "result") -> bool:
        return self._reserve("_results", max(0, int(amount)), label)

    def record_response(self, amount: int, label: str = "response-bytes") -> bool:
        return self._reserve("_response_bytes", max(0, int(amount)), label)

    def remaining(self, limit_name: str) -> int:
        counter = {
            "max_requests": "_requests",
            "max_results": "_results",
            "max_response_bytes": "_response_bytes",
            "max_executions": "_executions",
        }.get(limit_name)
        if counter is None:
            raise KeyError(limit_name)
        with self._lock:
            return max(0, self.limits[limit_name] - int(getattr(self, counter)))

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return bool(self._exhausted)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            exhausted = sorted(self._exhausted)
            counts = {
                "requests": self._requests,
                "results": self._results,
                "response_bytes": self._response_bytes,
                "executions": self._executions,
            }
        elapsed = max(0.0, time.monotonic() - self._started_monotonic)
        deadline = self.limits["max_elapsed_seconds"]
        if elapsed > deadline:
            exhausted = sorted(set(exhausted) | {"max_elapsed_seconds"})
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "exhausted" if exhausted else "ok",
            "started_at": self.started_at,
            "elapsed_seconds": round(elapsed, 3),
            "limits": dict(self.limits),
            "counts": counts,
            "remaining": {
                "requests": max(0, self.limits["max_requests"] - counts["requests"]),
                "results": max(0, self.limits["max_results"] - counts["results"]),
                "response_bytes": max(0, self.limits["max_response_bytes"] - counts["response_bytes"]),
                "executions": max(0, self.limits["max_executions"] - counts["executions"]),
            },
            "exhausted_by": exhausted,
        }


_CURRENT_BUDGET: contextvars.ContextVar[ExecutionBudget | None] = contextvars.ContextVar(
    "ah_puch_execution_budget", default=None,
)
_GLOBAL_BUDGET: ExecutionBudget | None = None
_GLOBAL_BUDGET_LOCK = threading.Lock()


def activate_budget(budget: ExecutionBudget) -> tuple[contextvars.Token, ExecutionBudget | None]:
    """Make a budget visible to the current thread and worker threads."""
    global _GLOBAL_BUDGET
    token = _CURRENT_BUDGET.set(budget)
    with _GLOBAL_BUDGET_LOCK:
        previous = _GLOBAL_BUDGET
        _GLOBAL_BUDGET = budget
    return token, previous


def deactivate_budget(state: tuple[contextvars.Token, ExecutionBudget | None]) -> None:
    global _GLOBAL_BUDGET
    token, previous = state
    _CURRENT_BUDGET.reset(token)
    with _GLOBAL_BUDGET_LOCK:
        _GLOBAL_BUDGET = previous


def current_budget() -> ExecutionBudget | None:
    budget = _CURRENT_BUDGET.get()
    if budget is not None:
        return budget
    with _GLOBAL_BUDGET_LOCK:
        return _GLOBAL_BUDGET


@contextlib.contextmanager
def budget_context(budget: ExecutionBudget) -> Iterator[ExecutionBudget]:
    state = activate_budget(budget)
    try:
        yield budget
    finally:
        deactivate_budget(state)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_write(path: Path, value: str | bytes, *, mode: int = 0o600) -> None:
    """Durably replace one private regular artifact without partial writes."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"refusing to overwrite symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    payload = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    fd: int | None = None
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0), mode)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Filesystems without directory fsync still get atomic replacement.
            pass
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode=mode)


def cap_file(path: Path, maximum: int) -> bool:
    """Bound an already captured process stream and leave a clear marker."""
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        return False
    try:
        size = path.stat().st_size
        if size <= maximum:
            return False
        marker = f"\n[AH-PUCH OUTPUT TRUNCATED at {maximum} bytes]\n".encode("utf-8")
        keep = max(0, int(maximum) - len(marker))
        with path.open("r+b") as handle:
            handle.truncate(keep)
        with path.open("ab") as handle:
            handle.write(marker[: max(0, int(maximum) - keep)])
        path.chmod(0o600)
        return True
    except OSError:
        return False


def safe_target(value: Any) -> str:
    """Return a target reference with credentials/query values removed."""
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
            host = parsed.hostname.lower().rstrip(".")
            display = f"[{host}]" if ":" in host else host
            port = parsed.port
            default = 443 if parsed.scheme.lower() == "https" else 80
            netloc = display if port in {None, default} else f"{display}:{port}"
            names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name})
            query = urlencode([(name, "") for name in names])
            return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))
    except ValueError:
        return ""
    return raw[:512]


def _secret_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().casefold()).strip("-")


def is_secret_name(value: Any) -> bool:
    return _secret_name(value) in {_secret_name(item) for item in SECRET_NAMES}


def redact_argv(command: Iterable[Any]) -> list[str]:
    result: list[str] = []
    redact_next = False
    for raw in command:
        token = str(raw).replace("\x00", "")[:8192]
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        if "=" in token:
            key, _value = token.split("=", 1)
            if is_secret_name(key.lstrip("-")):
                result.append(f"{key}=[REDACTED]")
                continue
        if is_secret_name(token.lstrip("-")):
            result.append(token)
            redact_next = True
            continue
        if token.casefold().startswith(("basic ", "bearer ")):
            result.append("[REDACTED-AUTHORIZATION]")
            continue
        result.append(token)
    return result


def redact_text(value: Any, *, maximum: int = 10000) -> str:
    text = str(value or "").replace("\x00", "")
    text = SECRET_ASSIGNMENT.sub(lambda match: f"{match.group('key')}{match.group('sep')}[REDACTED]", text)
    text = AUTH_VALUE.sub("[REDACTED-AUTHORIZATION]", text)
    return text[:maximum]


def evidence_refs(root: Path, paths: Iterable[Path], *, maximum: int = 256) -> list[dict[str, Any]]:
    root = Path(root).resolve()
    rows: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for raw in paths:
        path = Path(raw)
        try:
            resolved = path.resolve()
            relative = resolved.relative_to(root)
            if resolved in seen or path.is_symlink() or not resolved.is_file():
                continue
            metadata = resolved.stat()
        except (OSError, ValueError):
            continue
        seen.add(resolved)
        digest = hashlib.sha256()
        try:
            with resolved.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
        except OSError:
            continue
        rows.append({"path": str(relative), "bytes": metadata.st_size, "sha256": digest.hexdigest()})
        if len(rows) >= maximum:
            break
    return rows


def make_evidence_receipt(
    root: Path,
    target: str,
    *,
    producer: str,
    status: str,
    started_at: str | None = None,
    finished_at: str | None = None,
    artifacts: Iterable[Path] = (),
    command: Iterable[Any] = (),
    scope: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    safe_reference = safe_target(target)
    safe_command = redact_argv(command)
    command_text = json.dumps(safe_command, ensure_ascii=False, separators=(",", ":"))
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_type": "execution-evidence",
        "producer": str(producer),
        "producer_version": "2.0.0",
        "target_ref": safe_reference,
        # Hash the redacted reference as well. A hash of a credential-bearing
        # URL would still be a stable secret-derived identifier in evidence.
        "target_sha256": hashlib.sha256(safe_reference.encode("utf-8")).hexdigest(),
        "status": str(status),
        "started_at": started_at or utc_now(),
        "finished_at": finished_at or utc_now(),
        "scope": {"mode": "automatic", "contact": "target-bound", **(scope or {})},
        "privacy": {"command_redacted": True, "target_query_values_removed": True},
        "command": safe_command,
        "command_sha256": hashlib.sha256(command_text.encode("utf-8")).hexdigest() if safe_command else "",
        "artifacts": evidence_refs(root, artifacts),
    }
    if metadata:
        receipt.update({str(key): value for key, value in metadata.items() if str(key) not in {"command", "target"}})
    return receipt


def validate_evidence_receipt(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return ["receipt is not an object"]
    required = ("schema_version", "receipt_type", "producer", "producer_version", "target_sha256", "status", "started_at", "finished_at", "scope", "privacy", "artifacts")
    errors = [f"missing:{key}" for key in required if key not in value]
    if value.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        errors.append("schema_version")
    if value.get("receipt_type") != "execution-evidence":
        errors.append("receipt_type")
    if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("target_sha256", ""))):
        errors.append("target_sha256")
    if not isinstance(value.get("scope"), dict) or value.get("scope", {}).get("mode") != "automatic":
        errors.append("scope")
    if not isinstance(value.get("privacy"), dict) or value.get("privacy", {}).get("command_redacted") is not True:
        errors.append("privacy")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("artifacts")
    else:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str) or not re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))):
                errors.append(f"artifacts[{index}]")
    return errors


def write_budget_artifact(root: Path, budget: ExecutionBudget, *, phase: str = "runtime") -> Path:
    destination = Path(root) / "runtime"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = budget.snapshot()
    payload["phase"] = str(phase)
    path = destination / "budget.json"
    atomic_json(path, payload)
    return path


def write_recovery_artifact(root: Path, *, stage: str, status: str, error: BaseException | None = None, metadata: dict[str, Any] | None = None) -> Path:
    destination = Path(root) / "runtime"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "recovery_status": str(status),
        "stage": str(stage),
        "updated": utc_now(),
        "resume_advice": "inspect with --saved-run RUN --saved-operation resume before rebuilding or rerunning",
    }
    if error is not None:
        payload["error_type"] = type(error).__name__
        payload["error"] = redact_text(str(error), maximum=1000)
    if metadata:
        payload.update({str(key): value for key, value in metadata.items() if str(key) not in {"password", "token", "secret", "command"}})
    path = destination / "recovery.json"
    atomic_json(path, payload)
    return path


def validate_saved_run_contract(root: Path) -> list[str]:
    """Validate local evidence/recovery metadata without contacting a target."""
    root = Path(root)
    errors: list[str] = []
    manifest = root / "manifest.json"
    if not root.is_dir() or root.is_symlink() or not manifest.is_file() or manifest.is_symlink():
        return ["missing-or-unsafe-manifest"]
    receipts = root / "receipts" / "executions.jsonl"
    if receipts.is_file() and not receipts.is_symlink():
        for line_number, line in enumerate(receipts.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"receipt:{line_number}:invalid-json")
                continue
            errors.extend(f"receipt:{line_number}:{item}" for item in validate_evidence_receipt(row))
    budget_path = root / "runtime" / "budget.json"
    if budget_path.is_file() and not budget_path.is_symlink():
        try:
            budget = json.loads(budget_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            budget = {}
            errors.append("budget:invalid-json")
        if not isinstance(budget, dict) or budget.get("schema_version") != SCHEMA_VERSION:
            errors.append("budget:schema")
        else:
            limits = budget.get("limits", {})
            counts = budget.get("counts", {})
            for counter, limit in (("requests", "max_requests"), ("results", "max_results"), ("response_bytes", "max_response_bytes"), ("executions", "max_executions")):
                if not isinstance(limits, dict) or not isinstance(counts, dict) or type(limits.get(limit)) is not int or type(counts.get(counter)) is not int or counts[counter] < 0 or counts[counter] > limits[limit]:
                    errors.append(f"budget:{counter}")
    recovery = root / "runtime" / "recovery.json"
    if recovery.is_file() and recovery.is_symlink():
        errors.append("recovery:symlink")
    return errors
