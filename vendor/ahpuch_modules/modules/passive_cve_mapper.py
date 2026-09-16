#!/usr/bin/env python3
"""Compatibility entry-point alias for module 131.

Ah Puch keeps the safer offline implementation under
``version_advisory_mapper.py``.  This file preserves the historical catalog
module name for scripts and saved command recipes without restoring the old
behavior that contacted NVD directly or executed provider-dependent work.
"""
from __future__ import annotations

try:
    from .version_advisory_mapper import main, parser
except ImportError:  # pragma: no cover - direct legacy-style invocation
    from version_advisory_mapper import main, parser


if __name__ == "__main__":
    raise SystemExit(main())
