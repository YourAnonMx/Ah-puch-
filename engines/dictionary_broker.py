#!/usr/bin/env python3
"""Capability-aware local dictionary broker.

No external corpus is downloaded here. The broker selects already-local,
operator-provided, project-local, or installer-imported resources and keeps
runtime consumption separate from redistribution policy.

A dictionary class is semantic: a directory corpus is not silently reused as a
parameter/password/extension corpus merely because both are line-oriented
files. Requested directory tiers are deterministic views (micro=500,
short=5000, long=all available entries) of an admitted local source corpus.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
VALID_CLASSES = {
    "subdomain", "directory", "file", "extension", "parameter", "api-path",
    "username", "password", "technology", "device-path",
}
VALID_TIERS = {"micro", "short", "long"}
TIER_LIMITS: dict[str, int | None] = {"micro": 500, "short": 5000, "long": None}
TEXT_SUFFIXES = {"", ".txt", ".lst", ".list", ".dict", ".wordlist"}
MAX_SOURCE_BYTES = 64 * 1024 * 1024
_BASE_RECEIPT_KEYS = (
    "class", "requested_tier", "effective_tier", "tier_exact", "path",
    "available", "source", "provenance",
)
_VALIDATION_RECEIPT_KEYS = ("reason", "bytes", "entries", "sha256", "validation")


def persistent_data() -> Path:
    configured = os.environ.get("AH_PUCH_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    return (Path(xdg).expanduser() if xdg else Path.home() / ".local/share") / "ah-puch"


def resource_dictionaries() -> Path:
    return persistent_data() / "resources" / "dictionaries"


def _env_key(dictionary_class: str) -> str:
    return "AH_PUCH_DICTIONARY_" + dictionary_class.upper().replace("-", "_")


def _usable(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_SOURCE_BYTES
    except OSError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _resolution(
    dictionary_class: str,
    tier: str,
    path: Path | None,
    *,
    source: str,
    effective_tier: str,
    tier_exact: bool,
    provenance: str,
) -> dict[str, Any]:
    return {
        "class": dictionary_class,
        "requested_tier": tier,
        "effective_tier": effective_tier,
        "tier_exact": bool(tier_exact),
        "path": str(path) if path else "",
        "available": bool(path),
        "source": source,
        "provenance": provenance,
    }


def _usable_for_class(path: Path, dictionary_class: str) -> bool:
    """Apply the generic file bound plus semantic directory exclusions."""
    if not _usable(path):
        return False
    if dictionary_class == "directory" and _path_under(path, DATA / "payloads"):
        return False
    return True


def _first(
    dictionary_class: str,
    tier: str,
    candidates: list[tuple[Path, str, str, bool, str]],
) -> dict[str, Any] | None:
    for path, source, effective_tier, exact, provenance in candidates:
        if _usable_for_class(path, dictionary_class):
            return _resolution(
                dictionary_class,
                tier,
                path,
                source=source,
                effective_tier=effective_tier,
                tier_exact=exact,
                provenance=provenance,
            )
    return None


def _path_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def explicit_info(dictionary_class: str, path_value: str, *, tier: str = "custom") -> dict[str, Any]:
    """Validate an operator-selected corpus without weakening class routing.

    Explicit paths are still local-only, regular, non-symlink, bounded UTF-8
    files.  A payload corpus can never become a directory dictionary merely by
    passing its path through ``dirsearch.wordlist``.
    """
    cls = str(dictionary_class).strip().lower()
    if cls not in VALID_CLASSES:
        raise ValueError(f"unsupported dictionary class: {dictionary_class}")
    requested = str(tier).strip().lower() or "custom"
    candidate = Path(str(path_value).strip()).expanduser()
    base = _resolution(
        cls,
        requested,
        None,
        source="operator-invalid",
        effective_tier="custom",
        tier_exact=False,
        provenance="operator-local",
    )
    try:
        if candidate.is_symlink():
            base["reason"] = "symlink-not-allowed"
            return base
        resolved = candidate.resolve(strict=True)
        if not _usable_for_class(resolved, cls):
            base["reason"] = "not-a-bounded-class-compatible-file"
            if cls == "directory" and _path_under(resolved, DATA / "payloads"):
                base["reason"] = "payload-corpus-is-not-a-directory-dictionary"
            return base
        text = resolved.read_text(encoding="utf-8")
        entries = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        if cls == "directory" and any("\x00" in line or len(line) > 240 for line in entries):
            base["reason"] = "directory-entry-is-invalid"
            return base
        if not entries:
            base["reason"] = "empty-corpus"
            return base
        size = resolved.stat().st_size
        digest = _sha256(resolved)
    except (OSError, UnicodeError):
        base["reason"] = "unreadable-or-non-utf8-corpus"
        return base
    result = _resolution(
        cls,
        requested,
        resolved,
        source="operator-tool-option",
        effective_tier="custom" if requested not in VALID_TIERS else requested,
        tier_exact=False,
        provenance="operator-local",
    )
    result.update({"bytes": size, "entries": len(entries), "sha256": digest, "validation": "regular-local-utf8"})
    return result


def receipt_info(info: dict[str, Any]) -> dict[str, Any]:
    """Project dictionary provenance into a stable, JSON-safe execution receipt."""
    result = {key: info.get(key) for key in _BASE_RECEIPT_KEYS}
    result.update({key: info[key] for key in _VALIDATION_RECEIPT_KEYS if key in info})
    return result


def _directory_system_roots() -> tuple[Path, ...]:
    """Return roots whose contents are unambiguously web-directory corpora."""
    return (
        Path("/usr/share/seclists/Discovery/Web-Content"),
        Path("/usr/share/dirb/wordlists"),
        Path("/usr/share/dirbuster/wordlists"),
    )


def _approved_legacy_source(path: Path, resources: Path, semantic_class: str = "directory") -> bool:
    """Admit only typed or unambiguously directory-oriented local sources."""
    if semantic_class != "directory":
        return False
    if path.is_symlink() or path.suffix.casefold() not in TEXT_SUFFIXES or not _usable(path):
        return False
    if _path_under(path, DATA / "payloads"):
        return False

    # New imports are class-addressed. Untyped files elsewhere under imported/
    # are deliberately not inferred as directory corpora.
    if _path_under(path, resources / "imported" / "directory"):
        return True

    return any(_path_under(path, root) for root in _directory_system_roots() if root.exists())


def _legacy_manifest_sources(resources: Path) -> tuple[list[Path], str]:
    """Read installer sources without trusting arbitrary manifest paths.

    New manifests may declare a ``class`` column. Only ``class=directory`` is
    accepted here. Historical manifests without that column remain compatible
    only for paths under known web-directory roots; broad SecLists/wordlists
    roots and payload families are never inferred as directory dictionaries.
    Every admitted source is hash-verified before tier materialization.
    """
    manifest = resources / "manifest.tsv"
    if not _usable(manifest):
        return [], ""
    try:
        lines = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return [], ""
    if not lines:
        return [], ""
    header = lines[0].split("\t")
    try:
        file_index = header.index("file")
        sha_index = header.index("sha256")
    except ValueError:
        return [], ""
    class_index = header.index("class") if "class" in header else None
    sources: list[Path] = []
    for line in lines[1:]:
        fields = line.split("\t")
        required_index = max(file_index, sha_index, class_index if class_index is not None else 0)
        if len(fields) <= required_index:
            continue
        semantic_class = fields[class_index].strip().lower() if class_index is not None else "directory"
        if semantic_class != "directory":
            continue
        path = Path(fields[file_index]).expanduser()
        expected = fields[sha_index].strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            continue
        if not _approved_legacy_source(path, resources, semantic_class):
            continue
        try:
            if _sha256(path) != expected:
                continue
        except OSError:
            continue
        sources.append(path)
    try:
        digest = _sha256(manifest)
    except OSError:
        digest = ""
    return sorted(set(sources), key=lambda value: str(value)), digest


def _repository_directory_sources() -> list[Path]:
    result: list[Path] = []
    for name in ("web-micro.txt", "web-short.txt", "web-long.txt"):
        path = DATA / "wordlists" / name
        if _usable(path):
            result.append(path)
    return result


def _repository_typed_sources(dictionary_class: str) -> list[Path]:
    """Return bundled sources whose semantic class is explicit in their name."""
    candidates: dict[str, tuple[str, ...]] = {
        "subdomain": ("subdomains_short.txt",),
        "parameter": ("parameters_short.txt", "burp-parameter-names_short.txt"),
        "password": ("passwords_short.txt",),
        "username": ("top-usernames_short.txt", "unix_users_short.txt"),
        "extension": ("extensions_short.txt",),
        "file": ("web-files_short.txt",),
        "api-path": ("common-api-endpoints_short.txt", "api_short.txt"),
    }
    return [
        DATA / "wordlists" / "categories" / name
        for name in candidates.get(dictionary_class, ())
        if _usable(DATA / "wordlists" / "categories" / name)
    ]


def _materialize_typed_tier(
    resources: Path,
    dictionary_class: str,
    tier: str,
    sources: list[Path],
) -> Path | None:
    """Build a deterministic private tier from an explicitly typed source."""
    sources = [path for path in sources if _usable(path)]
    if not sources:
        return None
    signature = _source_signature(sources, f"{dictionary_class}-repository")
    destination_dir = resources / "derived"
    destination = destination_dir / f"{dictionary_class}-{tier}-repository.txt"
    metadata = destination_dir / f"{dictionary_class}-{tier}-repository.meta.json"
    if _usable(destination) and metadata.is_file():
        try:
            current = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            current = {}
        if current.get("source_signature") == signature and current.get("tier") == tier:
            return destination

    values: set[str] = set()
    for source in sources:
        try:
            lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            value = raw.rstrip("\r").strip()
            if not value or value.startswith("#") or "\x00" in value or len(value) > 240:
                continue
            values.add(value)
    ordered = sorted(values)
    limit = TIER_LIMITS[tier]
    if limit is not None:
        ordered = ordered[:limit]
    if not ordered:
        return None

    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_suffix(".tmp")
    temporary.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, destination)
    destination.chmod(0o600)
    metadata.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "class": dictionary_class,
                "tier": tier,
                "entries": len(ordered),
                "source": "repository-categories",
                "provenance": "repository-local",
                "source_signature": signature,
                "verified_sources": len(sources),
                "network_download": False,
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    metadata.chmod(0o600)
    return destination


def _source_signature(sources: list[Path], identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8"))
    for source in sources:
        try:
            digest.update(str(source.resolve()).encode("utf-8"))
            digest.update(_sha256(source).encode("ascii"))
        except OSError:
            continue
    return digest.hexdigest()


def _materialize_directory_tier(
    resources: Path,
    tier: str,
    sources: list[Path],
    *,
    source_name: str,
    provenance: str,
    signature_hint: str = "",
) -> Path | None:
    """Build a typed local-only directory tier from admitted source files."""
    sources = [path for path in sources if _usable(path)]
    if not sources:
        return None
    signature = signature_hint or _source_signature(sources, source_name)
    if not signature:
        return None
    destination_dir = resources / "derived"
    destination = destination_dir / f"directory-{tier}-{source_name}.txt"
    metadata = destination_dir / f"directory-{tier}-{source_name}.meta.json"
    if _usable(destination) and metadata.is_file():
        try:
            current = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            current = {}
        if current.get("source_signature") == signature and current.get("tier") == tier:
            return destination

    values: set[str] = set()
    for source in sources:
        try:
            lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            value = raw.rstrip("\r").strip()
            if not value or value.startswith("#") or "\x00" in value or len(value) > 240:
                continue
            values.add(value)
    ordered = sorted(values)
    limit = TIER_LIMITS[tier]
    if limit is not None:
        ordered = ordered[:limit]
    if not ordered:
        return None

    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = destination.with_suffix(".tmp")
    temporary.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, destination)
    destination.chmod(0o600)
    metadata.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "class": "directory",
                "tier": tier,
                "entries": len(ordered),
                "source": source_name,
                "provenance": provenance,
                "source_signature": signature,
                "verified_sources": len(sources),
                "payload_family_excluded": True,
                "network_download": False,
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    metadata.chmod(0o600)
    return destination


def resolve_info(dictionary_class: str, *, tier: str = "micro", technology: str = "") -> dict[str, Any]:
    cls = dictionary_class.strip().lower()
    if cls not in VALID_CLASSES:
        raise ValueError(f"unsupported dictionary class: {dictionary_class}")
    requested_tier = tier.strip().lower()
    if requested_tier not in VALID_TIERS:
        raise ValueError(f"unsupported dictionary tier: {tier}")
    resources = resource_dictionaries()
    candidates: list[tuple[Path, str, str, bool, str]] = []

    explicit = os.environ.get(_env_key(cls), "").strip()
    if explicit:
        candidates.append((Path(explicit).expanduser(), "operator-class-env", "custom", False, "operator-local"))

    # The historical generic environment variable is retained only for the
    # directory/content class. Reusing it for passwords/parameters/extensions
    # would recreate semantic class mixing.
    generic = os.environ.get("AH_PUCH_DICTIONARY", "").strip()
    if generic and cls == "directory":
        candidates.append((Path(generic).expanduser(), "operator-generic-env", "custom", False, "operator-local"))

    candidates.extend([
        (resources / f"{cls}-{requested_tier}.txt", "persistent-class-tier", requested_tier, True, "local-import"),
        (resources / "categories" / f"{cls}-{requested_tier}.txt", "persistent-category-tier", requested_tier, True, "local-import"),
        (resources / f"{cls}.txt", "persistent-class", "custom", False, "local-import"),
        (resources / "categories" / f"{cls}.txt", "persistent-category", "custom", False, "local-import"),
        (resources / "imported" / f"{cls}.txt", "persistent-imported-class", "custom", False, "local-import"),
    ])

    if cls == "directory":
        found = _first(cls, requested_tier, candidates)
        if found:
            return found

        installer_sources, manifest_sha = _legacy_manifest_sources(resources)
        derived = _materialize_directory_tier(
            resources,
            requested_tier,
            installer_sources,
            source_name="installer",
            provenance="local-import-manifest",
            signature_hint=manifest_sha,
        )
        if derived:
            return _resolution(
                cls,
                requested_tier,
                derived,
                source="verified-installer-sources",
                effective_tier=requested_tier,
                tier_exact=True,
                provenance="local-derived",
            )

        repo_sources = _repository_directory_sources()
        derived = _materialize_directory_tier(
            resources,
            requested_tier,
            repo_sources,
            source_name="repository",
            provenance="repository-local",
        )
        if derived:
            return _resolution(
                cls,
                requested_tier,
                derived,
                source="repository-local-derived",
                effective_tier=requested_tier,
                tier_exact=True,
                provenance="repository-local",
            )
        return _resolution(cls, requested_tier, None, source="unavailable", effective_tier="", tier_exact=False, provenance="")

    if cls == "device-path":
        candidates.append((DATA / "wordlists" / "range.paths.txt", "repository-native-device-path", "custom", False, "first-party"))
    elif cls == "subdomain":
        candidates.extend([
            (DATA / "wordlists" / f"subdomains-{requested_tier}.txt", "repository-local-tier", requested_tier, True, "repository-local"),
            (DATA / "wordlists" / "subdomains.txt", "repository-local-subdomain", "custom", False, "repository-local"),
            (DATA / "wordlists" / "subdomains-short.txt", "repository-local-subdomain", "short", requested_tier == "short", "repository-local"),
        ])
    elif cls == "technology" and technology:
        slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in technology).strip("-")
        candidates.extend([
            (DATA / "wordlists" / "categories" / f"{slug}_{requested_tier}.txt", "repository-technology-tier", requested_tier, True, "repository-local"),
            (DATA / "wordlists" / "categories" / f"{slug}_short.txt", "repository-technology-short", "short", requested_tier == "short", "repository-local"),
            (DATA / "wordlists" / "categories" / f"{slug}.txt", "repository-technology", "custom", False, "repository-local"),
        ])
    elif cls == "username":
        if requested_tier == "short":
            candidates.append((Path("/usr/share/seclists/Usernames/top-usernames-shortlist.txt"), "system-seclists", "short", True, "system-local"))

    found = _first(cls, requested_tier, candidates)
    if found:
        return found

    typed_sources = _repository_typed_sources(cls)
    if typed_sources:
        derived = _materialize_typed_tier(resources, cls, requested_tier, typed_sources)
        if derived:
            return _resolution(
                cls,
                requested_tier,
                derived,
                source="repository-typed-derived",
                effective_tier=requested_tier,
                tier_exact=True,
                provenance="repository-local",
            )
    return _resolution(cls, requested_tier, None, source="unavailable", effective_tier="", tier_exact=False, provenance="")


def resolve(dictionary_class: str, *, tier: str = "micro", technology: str = "") -> Path | None:
    info = resolve_info(dictionary_class, tier=tier, technology=technology)
    return Path(str(info["path"])) if info["available"] else None


def resolve_directory_info(*, tier: str = "micro", configured_path: str = "") -> dict[str, Any]:
    """Resolve the family directory resource, honoring one explicit override."""
    configured = str(configured_path or "").strip()
    if configured:
        return explicit_info("directory", configured, tier=tier)
    return resolve_info("directory", tier=tier)


def describe(*, tier: str = "micro") -> list[dict[str, Any]]:
    return [resolve_info(cls, tier=tier) for cls in sorted(VALID_CLASSES)]


def install_frontend(base: Any) -> Any:
    """Make the canonical menu report the same broker used by production."""
    if getattr(base, "_ah_puch_dictionary_frontend", False):
        return base

    def print_dictionary_info() -> None:
        print("Local dictionary broker (network downloads: disabled during target execution)")
        rows = describe(tier="micro")
        for row in rows:
            path = row["path"] or "-"
            exact = "exact" if row["tier_exact"] else "custom/unavailable"
            print(f"  {row['class']:<12} {path}  source={row['source']} tier={row['effective_tier'] or '-'} ({exact})")
        print("  directory tiers:")
        for tier_name in ("micro", "short", "long"):
            row = resolve_info("directory", tier=tier_name)
            print(f"    {tier_name:<5} {row['path'] or '-'}  source={row['source']}")
        print("  data/payloads is never a dictionary source; payload corpora stay outside runtime dictionary routing.")

    base.print_dictionary_info = print_dictionary_info
    base._ah_puch_dictionary_frontend = True
    return base
