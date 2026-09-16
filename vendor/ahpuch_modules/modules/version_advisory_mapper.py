#!/usr/bin/env python3
"""Passive, offline product/version observation for catalog module 131.

This compatibility module deliberately performs no target contact, HTTP
request, NVD query, package import from the network, or subprocess execution.
The canonical selector 177 performs the richer mapping of normalized saved-run
observations against an explicitly imported local advisory store.
"""
from __future__ import annotations

import argparse
import json
import sys


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        prog="version_advisory_mapper.py",
        description="Record a passive target hint for later offline advisory mapping.",
    )
    value.add_argument("target", nargs="?", help=argparse.SUPPRESS)
    value.add_argument("threads", nargs="?", help=argparse.SUPPRESS)
    value.add_argument("module_options", nargs="?", help=argparse.SUPPRESS)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    print(json.dumps({
        "status": "recorded",
        "module_id": "131",
        "capability": "passive-version-observation",
        "network_contact": False,
        "target_hint": args.target or "",
        "message": "Target hint retained for normalized local advisory mapping by selector 177.",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
