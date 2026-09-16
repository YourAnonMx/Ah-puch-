"""Compatibility entry for the retired vendor CLI.

The historical interactive shell used its own module runner, report state and
option precedence. Keeping that shell as an executable entrypoint would create
a second user-facing Ah-Puch engine. All normal execution now returns through
``engines.entry``; the canonical catalog browser already provides browse,
search, selection, options, favorites, recent/rerun and saved-run inspection.

The compatibility module contains no independent shell implementation.
"""
from __future__ import annotations

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_ROOT_CANDIDATES = (PACKAGE_ROOT.parents[1], PACKAGE_ROOT.parent)
ROOT = next(
    (candidate for candidate in _ROOT_CANDIDATES if (candidate / "config").is_dir()),
    PACKAGE_ROOT.parents[1],
)


def main(argv: list[str] | None = None) -> int:
    """Delegate the historical package entry to the canonical runtime."""
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from engines.entry import main as canonical_main

    raw = list(sys.argv[1:] if argv is None else argv)
    return int(canonical_main(raw))
