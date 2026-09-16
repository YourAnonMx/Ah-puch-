"""Memory-bounded wordlist selection for the bundled fuzzing data."""

from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path
import subprocess
import tempfile


def iter_words(path: Path, limit: int = 0) -> Iterator[str]:
    """Yield cleaned entries one at a time; zero means no line limit."""
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            yield value
            count += 1
            if limit and count >= limit:
                return


def bundled_path(data_root: Path, tier: str) -> Path:
    names = {
        "micro": "web-micro.txt",
        "short": "web-short.txt",
        "long": "web-long.txt",
    }
    return data_root / "wordlists" / names.get(tier, names["micro"])


def category_paths(data_root: Path, suffix: str = "_short.txt") -> Iterator[Path]:
    """Yield technology/type lists without materializing their contents."""
    yield from sorted((data_root / "wordlists" / "categories").glob(f"*{suffix}"))


def payload_path(data_root: Path, name: str) -> Path:
    return data_root / "payloads" / f"{name}.txt"


def build_wordlist(source: Path, output: Path, tier: str, timeout: int | None = None) -> int:
    """Build a tier with external sort and an optional caller-controlled bound."""
    source = source.expanduser().resolve()
    output = output.expanduser().resolve()
    if tier not in {"micro", "short", "long"}:
        return 2

    files: list[Path] = []
    if tier == "short":
        files = sorted(source.glob("*_short.txt"))
    elif tier == "long":
        files = sorted(source.glob("*_long.txt"))
        if not files:
            bundled_short = source.parent / "web-short.txt"
            if bundled_short.is_file():
                files = [bundled_short]
    else:
        bundled_micro = source.parent / "web-micro.txt"
        if bundled_micro.is_file():
            files = [bundled_micro]
        else:
            files = sorted(source.glob("*_short.txt"))
    if not files:
        return 2

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output.parent, prefix=f".{output.name}.", suffix=".tmp", delete=False
    )
    temporary_path = Path(temporary.name)
    try:
        with temporary:
            try:
                result = subprocess.run(
                    ["sort", "-u", *(str(path) for path in files)],
                    stdout=temporary,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                return 124
        if result.returncode == 0:
            os.replace(temporary_path, output)
        return result.returncode
    finally:
        temporary_path.unlink(missing_ok=True)
