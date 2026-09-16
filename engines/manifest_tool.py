#!/usr/bin/env python3
"""Build and validate machine-verifiable Ah-Puch authorization manifests."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .authorization import AUTHORIZATION_REFERENCE, AuthorizationManifest, _source_sha256
except ImportError:
    from authorization import AUTHORIZATION_REFERENCE, AuthorizationManifest, _source_sha256


def _ports(value: str) -> list[int]:
    result: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise argparse.ArgumentTypeError(f"invalid port range: {token}")
            start, end = int(start_text), int(end_text)
            if not 1 <= start <= end <= 65535:
                raise argparse.ArgumentTypeError(f"port range outside 1-65535: {token}")
            # Manifest rows use explicit ports. Keep accidental giant manifests
            # out of this helper; full-range authorization belongs in the target
            # profile/action contract rather than a 65k-element JSON list.
            if end - start > 4096:
                raise argparse.ArgumentTypeError("one manifest port range may contain at most 4097 ports")
            result.update(range(start, end + 1))
        elif token.isdigit() and 1 <= int(token) <= 65535:
            result.add(int(token))
        else:
            raise argparse.ArgumentTypeError(f"invalid port: {token}")
    return sorted(result)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ah-puch-manifest", description="Build or validate an Ah-Puch machine authorization manifest")
    sub = p.add_subparsers(dest="command", required=True)

    digest = sub.add_parser("hash", help="print the deterministic authorization source-corpus SHA-256")
    digest.add_argument("source")

    validate = sub.add_parser("validate", help="validate source binding and manifest rows")
    validate.add_argument("manifest")

    build = sub.add_parser("build", help="build a manifest from explicit owner-approved target rows")
    build.add_argument("--source", required=True, help="owner-approved source corpus file or directory")
    build.add_argument("--output", required=True)
    build.add_argument("--target", action="append", required=True, help="explicit authorized URL, host, IP or CIDR; repeat as needed")
    build.add_argument("--action", action="append", default=["assessment"], help="allowed action for every supplied row; repeat as needed")
    build.add_argument("--service", action="append", default=[], help="optional service restriction; repeat as needed")
    build.add_argument("--ports", type=_ports, default=[], help="optional explicit comma/range port restriction")
    build.add_argument("--path", action="append", default=[], help="optional URL path subtree restriction; repeat as needed")
    return p


def _build(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    if not source.exists():
        raise ValueError("authorization source does not exist")
    digest = _source_sha256(source)
    actions = list(dict.fromkeys(str(value) for value in args.action if str(value).strip()))
    services = list(dict.fromkeys(str(value) for value in args.service if str(value).strip()))
    paths = list(dict.fromkeys(str(value) for value in args.path if str(value).strip()))
    targets = []
    for target in dict.fromkeys(str(value).strip() for value in args.target if str(value).strip()):
        row = {"target": target, "allowed_actions": actions}
        if services:
            row["services"] = services
        if args.ports:
            row["ports"] = list(args.ports)
        if paths:
            row["paths"] = paths
        targets.append(row)
    if not targets:
        raise ValueError("at least one explicit target is required")
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": 1,
        "authorization_reference": AUTHORIZATION_REFERENCE,
        "source_path": str(source),
        "source_sha256": digest,
        "targets": targets,
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)
    # Self-validate the exact bytes just written before reporting success.
    AuthorizationManifest.load(output)
    print(str(output))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "hash":
            source = Path(args.source).expanduser().resolve()
            print(_source_sha256(source))
            return 0
        if args.command == "validate":
            manifest = AuthorizationManifest.load(Path(args.manifest).expanduser().resolve())
            print(json.dumps({
                "valid": True,
                "authorization_reference": AUTHORIZATION_REFERENCE,
                "source_path": str(manifest.source_path),
                "source_sha256": manifest.source_sha256,
                "targets": len(manifest.rows),
            }, sort_keys=True))
            return 0
        if args.command == "build":
            return _build(args)
    except (OSError, ValueError) as exc:
        print(f"authorization manifest error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
