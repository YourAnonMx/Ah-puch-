#!/usr/bin/env python3
"""Automatic target-boundary checks for the canonical Ah-Puch runtime."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .asset_graph import host_within_target, url_within_target
    from .authorization import AuthorizationManifest
except ImportError:
    from asset_graph import host_within_target, url_within_target
    from authorization import AuthorizationManifest


def install(base: Any, v2: Any, runtime_module: Any | None = None) -> Any:
    """Install automatic operator-target boundary semantics exactly once."""
    del v2, runtime_module
    current = base.UnifiedRun
    if getattr(current, "_ah_puch_target_boundary", False):
        return base

    class TargetBoundaryUnifiedRun(current):  # type: ignore[misc, valid-type]
        _ah_puch_target_boundary = True

        def __init__(self, target: str, args: Any):
            super().__init__(target, args)
            self.authorization = None
            self.authorization_error = ""
            self.scope_policy_ok = True
            policy = str(getattr(args, "authorization_manifest", "") or "").strip()
            self.authorization_manifest_path = policy
            if not policy:
                return
            try:
                self.authorization = AuthorizationManifest.load(Path(policy).expanduser().resolve())
                self.scope_policy_ok = bool(self.authorization.allows(self.target, "assessment"))
                if not self.scope_policy_ok:
                    self.authorization_error = "optional scope policy excludes the operator target"
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self.authorization_error = f"{type(exc).__name__}: {exc}"
                self.scope_policy_ok = False
            self.event(
                {
                    "engine": "scope_policy",
                    "status": "narrowed" if self.scope_policy_ok else "failed",
                    "policy": policy,
                    "reason": self.authorization_error,
                }
            )

        def _target_boundary_allows(self, value: str) -> bool:
            text = str(value).strip()
            if text.startswith(("http://", "https://")):
                within = url_within_target(text, self.target, self.boundary_mode)
            else:
                within = host_within_target(text, self.target, self.boundary_mode)
            if not within or self.authorization is None:
                return within
            return bool(self.authorization.allows(text, "assessment"))

        def _allowed(self, value: str) -> bool:
            return self._target_boundary_allows(value)

        def _endpoint_allowed_current(
            self,
            host: str,
            port: int,
            service: str = "",
            protocol: str = "tcp",
        ) -> bool:
            """Evaluate one concrete endpoint against the target boundary."""
            try:
                number = int(port)
            except (TypeError, ValueError):
                return False
            if not 1 <= number <= 65535 or str(protocol).lower() not in {"tcp", "udp"}:
                return False
            candidate_host = str(host).strip().strip("[]")
            if not host_within_target(candidate_host, self.target, self.boundary_mode):
                return False
            if self.authorization is None:
                return True
            # Host/IP manifests use the exact endpoint primitive. URL rows
            # retain scheme/path restrictions and therefore receive a URL
            # candidate anchored to the current operator target.
            if str(self.target).startswith(("http://", "https://")):
                parsed = urlsplit(self.target)
                display = f"[{candidate_host}]" if ":" in candidate_host else candidate_host
                authority = f"{display}:{number}"
                path = parsed.path or "/"
                candidate = f"{parsed.scheme.lower()}://{authority}{path}"
                return bool(self.authorization.allows(candidate, "assessment", service))
            return bool(self.authorization.allows_port(candidate_host, number, "assessment", service))

        def _endpoint_allowed(
            self,
            host: str,
            port: int,
            service: str = "",
            protocol: str = "tcp",
        ) -> bool:
            if not self.scope_policy_ok:
                return False
            return self._endpoint_allowed_current(host, port, service, protocol)

        def _refresh_scope_policy(self) -> bool:
            """Reload the optional narrowing policy at an execution edge."""
            if not self.authorization_manifest_path:
                return True
            try:
                refreshed = AuthorizationManifest.load(Path(self.authorization_manifest_path).expanduser().resolve())
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self.authorization_error = f"{type(exc).__name__}: {exc}"
                self.scope_policy_ok = False
                self.authorization = None
                return False
            self.authorization = refreshed
            self.scope_policy_ok = bool(refreshed.allows(self.target, "assessment"))
            self.authorization_error = "" if self.scope_policy_ok else "optional scope policy excludes the operator target"
            return self.scope_policy_ok

        def execute(self) -> int:
            if self.scope_policy_ok and self._refresh_scope_policy():
                return super().execute()
            self.current_stage = "scope-policy"
            self.event(
                {
                    "engine": "scope_policy",
                    "status": "failed",
                    "reason": self.authorization_error or "optional scope policy excludes the operator target",
                    "contacted_target": False,
                }
            )
            # Produce a truthful local failure artifact without entering any
            # network/native/catalog stage. Outer runtime wrappers still add
            # the normal target-contract/checkpoint seals.
            try:
                base.write_json(
                    self.root / "manifest.json",
                    {
                        "version": base.VERSION,
                        "target": base.safe_target(self.target),
                        "target_sha256": base.hashlib.sha256(base.safe_target(self.target).encode("utf-8")).hexdigest(),
                        "profile": str(self.args.profile),
                        "dry_run": bool(self.args.dry_run),
                        "scope_policy": "INVALID",
                        "scope_policy_error": self.authorization_error,
                    },
                )
                self.finish()
                base.checkpoint(self.checkpoint_path, "scope-policy", "failed", events=len(self.events), exit_code=2)
                base.reseal_saved_run(self.root)
            except (OSError, ValueError, RuntimeError):
                pass
            return 2

    TargetBoundaryUnifiedRun.__name__ = "TargetBoundaryUnifiedRun"
    TargetBoundaryUnifiedRun.__qualname__ = "TargetBoundaryUnifiedRun"
    base.UnifiedRun = TargetBoundaryUnifiedRun
    return base
