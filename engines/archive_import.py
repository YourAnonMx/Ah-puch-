#!/usr/bin/env python3
"""Safely import a bounded local dictionary archive.

The importer validates the complete member table before writing anything.  It
accepts regular files and directories only, keeps every path below the chosen
destination, and never follows archive or pre-existing filesystem links.
"""
from __future__ import annotations

import argparse
import gzip
import os
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable, Iterable


DEFAULT_MEMBER_LIMIT = 64 * 1024 * 1024
DEFAULT_TOTAL_LIMIT = 128 * 1024 * 1024
DEFAULT_FILE_LIMIT = 10_000


class UnsafeArchive(ValueError):
    """Raised when an archive cannot be extracted within the safe contract."""


@dataclass(frozen=True)
class Member:
    name: str
    size: int
    directory: bool
    opener: Callable[[], BinaryIO] | None


def _relative(name: str) -> Path:
    value = name.replace("\\", "/")
    pure = PurePosixPath(value)
    if not value or value.startswith("/") or pure.is_absolute():
        raise UnsafeArchive(f"absolute or empty archive path: {name!r}")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise UnsafeArchive(f"non-canonical archive path: {name!r}")
    if pure.parts and ":" in pure.parts[0]:
        raise UnsafeArchive(f"drive-qualified archive path: {name!r}")
    return Path(*pure.parts)


def _zip_members(handle: zipfile.ZipFile) -> list[Member]:
    rows: list[Member] = []
    for info in handle.infolist():
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and stat.S_ISLNK(mode):
            raise UnsafeArchive(f"link member is forbidden: {info.filename!r}")
        directory = info.is_dir()
        file_type = stat.S_IFMT(mode)
        if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise UnsafeArchive(f"special member is forbidden: {info.filename!r}")
        rows.append(
            Member(
                info.filename.rstrip("/") if directory else info.filename,
                0 if directory else info.file_size,
                directory,
                None if directory else lambda item=info: handle.open(item, "r"),
            )
        )
    return rows


def _tar_members(handle: tarfile.TarFile) -> list[Member]:
    rows: list[Member] = []
    for info in handle.getmembers():
        if not (info.isfile() or info.isdir()):
            raise UnsafeArchive(f"link or special member is forbidden: {info.name!r}")
        rows.append(
            Member(
                info.name.rstrip("/") if info.isdir() else info.name,
                0 if info.isdir() else info.size,
                info.isdir(),
                None if info.isdir() else lambda item=info: _tar_open(handle, item),
            )
        )
    return rows


def _tar_open(handle: tarfile.TarFile, info: tarfile.TarInfo) -> BinaryIO:
    stream = handle.extractfile(info)
    if stream is None:
        raise UnsafeArchive(f"regular member has no data: {info.name!r}")
    return stream


def _validate(rows: Iterable[Member], member_limit: int, total_limit: int, file_limit: int) -> list[tuple[Member, Path]]:
    checked: list[tuple[Member, Path]] = []
    total = 0
    files = 0
    seen: set[Path] = set()
    for row in rows:
        relative = _relative(row.name)
        if relative in seen:
            raise UnsafeArchive(f"duplicate archive path: {row.name!r}")
        seen.add(relative)
        if row.size < 0 or row.size > member_limit:
            raise UnsafeArchive(f"member exceeds size limit: {row.name!r}")
        if not row.directory:
            files += 1
            total += row.size
        if files > file_limit:
            raise UnsafeArchive("archive exceeds file-count limit")
        if total > total_limit:
            raise UnsafeArchive("archive exceeds total uncompressed-size limit")
        checked.append((row, relative))
    kinds = {relative: row.directory for row, relative in checked}
    for row, relative in checked:
        for parent in relative.parents:
            if parent == Path("."):
                break
            if parent in kinds and not kinds[parent]:
                raise UnsafeArchive(f"file member is also a parent directory: {row.name!r}")
    return checked


def _preflight_destination(root: Path, checked: list[tuple[Member, Path]]) -> None:
    """Reject all existing path hazards before the first archive byte is written."""
    for row, relative in checked:
        current = root
        for part in relative.parent.parts:
            current = current / part
            if current.exists() or current.is_symlink():
                if current.is_symlink() or not current.is_dir():
                    raise UnsafeArchive(f"unsafe existing parent: {relative}")
        target = root / relative
        if target.exists() or target.is_symlink():
            expected = target.is_dir() if row.directory else target.is_file()
            if target.is_symlink() or not expected:
                raise UnsafeArchive(f"unsafe existing destination: {relative}")


def _safe_parent(root: Path, relative: Path) -> Path:
    current = root
    for part in relative.parent.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise UnsafeArchive(f"unsafe existing parent: {relative}")
        else:
            current.mkdir(mode=0o700)
    return current


def _write_member(root: Path, relative: Path, stream: BinaryIO, declared_size: int | None, member_limit: int) -> None:
    parent = _safe_parent(root, relative)
    target = parent / relative.name
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file():
            raise UnsafeArchive(f"unsafe existing destination: {relative}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{relative.name}.", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    os.chmod(temporary, 0o600)
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as destination:
            while True:
                block = stream.read(min(1024 * 1024, member_limit + 1 - written))
                if not block:
                    break
                written += len(block)
                if written > member_limit:
                    raise UnsafeArchive(f"member expanded beyond limit: {relative}")
                destination.write(block)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    if declared_size is not None and written != declared_size:
        temporary.unlink(missing_ok=True)
        raise UnsafeArchive(f"member size mismatch: {relative}")
    os.replace(temporary, target)
    target.chmod(0o600)


def _extract_rows(root: Path, checked: list[tuple[Member, Path]], member_limit: int) -> int:
    _preflight_destination(root, checked)
    for row, relative in checked:
        if row.directory:
            parent = _safe_parent(root, relative)
            directory = parent / relative.name
            if directory.exists() or directory.is_symlink():
                if directory.is_symlink() or not directory.is_dir():
                    raise UnsafeArchive(f"unsafe existing directory: {relative}")
            else:
                directory.mkdir(mode=0o700)
            continue
        if row.opener is None:
            raise UnsafeArchive(f"member has no reader: {row.name!r}")
        with row.opener() as stream:
            _write_member(root, relative, stream, row.size, member_limit)
    return sum(1 for row, _relative_path in checked if not row.directory)


def extract_archive(
    archive: Path,
    destination: Path,
    *,
    member_limit: int = DEFAULT_MEMBER_LIMIT,
    total_limit: int = DEFAULT_TOTAL_LIMIT,
    file_limit: int = DEFAULT_FILE_LIMIT,
) -> int:
    archive = archive.expanduser().resolve(strict=True)
    if not archive.is_file():
        raise UnsafeArchive("archive must be a regular file")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_symlink() or not destination.is_dir():
        raise UnsafeArchive("destination must be a real directory")
    root = destination.resolve(strict=True)

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as handle:
            rows = _validate(_zip_members(handle), member_limit, total_limit, file_limit)
            return _extract_rows(root, rows, member_limit)
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive, mode="r:*") as handle:
            rows = _validate(_tar_members(handle), member_limit, total_limit, file_limit)
            return _extract_rows(root, rows, member_limit)
    if archive.suffix.casefold() == ".gz":
        name = archive.name[:-3]
        relative = _relative(name)
        with gzip.open(archive, "rb") as stream:
            _write_member(root, relative, stream, None, min(member_limit, total_limit))
        return 1
    raise UnsafeArchive("unsupported or malformed archive format")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--member-limit", type=int, default=DEFAULT_MEMBER_LIMIT)
    parser.add_argument("--total-limit", type=int, default=DEFAULT_TOTAL_LIMIT)
    parser.add_argument("--file-limit", type=int, default=DEFAULT_FILE_LIMIT)
    args = parser.parse_args(argv)
    if min(args.member_limit, args.total_limit, args.file_limit) < 1:
        parser.error("all limits must be positive")
    try:
        count = extract_archive(
            args.archive,
            args.destination,
            member_limit=args.member_limit,
            total_limit=args.total_limit,
            file_limit=args.file_limit,
        )
    except (OSError, UnsafeArchive, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(2, f"archive rejected: {exc}\n")
    print(f"archive imported: files={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
