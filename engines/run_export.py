#!/usr/bin/env python3
"""Deterministic, local-only export of one sealed Ah-Puch saved run."""
from __future__ import annotations

import gzip
import hashlib
import os
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExportFile:
    relative: Path
    size: int
    mode: int
    sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _checksum_ledger(root: Path) -> dict[str, str]:
    path = root / "checksums.sha256"
    if not path.is_file() or path.is_symlink():
        raise ValueError("saved run has no regular checksums.sha256 ledger")
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
        digest, separator, raw = line.partition("  ")
        relative = Path(raw)
        if (
            not separator
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.lower())
            or relative.is_absolute()
            or relative.anchor
            or ".." in relative.parts
            or not raw
        ):
            raise ValueError("saved run checksum ledger contains an invalid row")
        result[relative.as_posix()] = digest.lower()
    return result


def _snapshot(root: Path, *, file_limit: int, total_limit: int) -> list[ExportFile]:
    ledger = _checksum_ledger(root)
    files: list[ExportFile] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"saved run contains a symlink: {path.relative_to(root)}")
        if not path.is_file():
            continue
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"saved run contains a non-regular file: {path.relative_to(root)}")
        relative = path.relative_to(root)
        digest = _sha256(path)
        if relative.as_posix() != "checksums.sha256" and ledger.get(relative.as_posix()) != digest:
            raise ValueError(f"saved run integrity mismatch: {relative}")
        total += metadata.st_size
        if len(files) + 1 > file_limit:
            raise ValueError(f"saved run exceeds export file limit ({file_limit})")
        if total > total_limit:
            raise ValueError(f"saved run exceeds export byte limit ({total_limit})")
        files.append(ExportFile(relative, metadata.st_size, metadata.st_mode & 0o777, digest))
    expected = set(ledger)
    observed = {row.relative.as_posix() for row in files if row.relative.as_posix() != "checksums.sha256"}
    if expected != observed:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        detail = (missing or extra or ["unknown"])[0]
        raise ValueError(f"saved run ledger/tree mismatch: {detail}")
    if not any(row.relative.as_posix() == "manifest.json" for row in files):
        raise ValueError("saved run has no regular manifest.json")
    return files


def export_saved_run(
    run: Path,
    output: Path,
    *,
    file_limit: int = 100_000,
    total_limit: int = 50 * 1024 * 1024 * 1024,
) -> dict[str, object]:
    """Write a byte-reproducible ``.tar.gz`` without modifying the run."""
    root = Path(run).expanduser()
    if root.is_symlink():
        raise ValueError("saved run root may not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("saved run must be a directory")
    destination = Path(output).expanduser()
    if destination.suffixes[-2:] != [".tar", ".gz"]:
        raise ValueError("export output must end in .tar.gz")
    destination = destination.resolve(strict=False)
    try:
        destination.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("export output must be outside the saved run")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"export output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    files = _snapshot(root, file_limit=max(1, int(file_limit)), total_limit=max(1, int(total_limit)))
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for row in files:
                        source = root / row.relative
                        info = tarfile.TarInfo(f"ah-puch-run/{row.relative.as_posix()}")
                        info.size = row.size
                        info.mode = row.mode
                        info.mtime = 0
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        with source.open("rb") as handle:
                            archive.addfile(info, handle)
            raw.flush()
            os.fsync(raw.fileno())
        # Detect mutation or new files before publishing the temporary archive.
        if _snapshot(root, file_limit=max(1, int(file_limit)), total_limit=max(1, int(total_limit))) != files:
            raise ValueError("saved run changed while it was being exported")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        return {
            "status": "exported",
            "archive": str(destination),
            "sha256": _sha256(destination),
            "files": len(files),
            "bytes": destination.stat().st_size,
            "prefix": "ah-puch-run/",
        }
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
