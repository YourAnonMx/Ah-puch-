#!/usr/bin/env python3
"""SRC06 status-aware integration for the canonical offline advisory store.

This module adds no network capability. It replaces the production advisory
projection with one deterministic store load, conservative inventory identity
selection, explicit rejection provenance and partial terminal semantics.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

try:
    from . import advisory_store
except ImportError:
    import advisory_store


def _jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    rejected = 0
    if not path.is_file() or path.is_symlink():
        return rows, rejected
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return rows, 1
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            rejected += 1
            continue
        if isinstance(value, dict):
            rows.append(value)
        else:
            rejected += 1
    return rows, rejected


def _single_list_value(row: dict[str, Any], singular: str, plural: str) -> tuple[str, str]:
    explicit = str(row.get(singular, "") or "").strip()
    if explicit:
        return explicit, "explicit"
    raw = row.get(plural)
    if not isinstance(raw, list):
        return "", "missing"
    values = sorted({str(value).strip() for value in raw if str(value).strip()})
    if len(values) == 1:
        return values[0], "single-plural"
    return "", "ambiguous" if values else "missing"


def _inventory_products(root: Path) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    products: set[tuple[str, str, str]] = set()
    rejected: list[dict[str, Any]] = []
    for relative in ("inventory/services.jsonl", "inventory/devices.jsonl"):
        rows, malformed = _jsonl(root / relative)
        for index in range(malformed):
            rejected.append({"source": relative, "reason": "malformed-jsonl", "ordinal": index + 1})
        for index, row in enumerate(rows, 1):
            vendor, vendor_source = _single_list_value(row, "vendor", "vendors")
            product, product_source = _single_list_value(row, "product", "models")
            version = str(row.get("version", "") or row.get("firmware", "")).strip()
            if not vendor or not product or not version:
                # Rows without a complete product identity are normal inventory
                # rows, not advisory errors. Only ambiguous plural identity is
                # rejected because choosing an arbitrary first value can create
                # a false advisory association.
                if vendor_source == "ambiguous" or product_source == "ambiguous":
                    rejected.append({
                        "source": relative,
                        "ordinal": index,
                        "reason": "ambiguous-product-identity",
                        "vendor_source": vendor_source,
                        "product_source": product_source,
                    })
                continue
            products.add((vendor, product, version))
    return [
        {"vendor": vendor, "product": product, "version": version}
        for vendor, product, version in sorted(products, key=lambda item: (
            advisory_store._product_key(item[0], item[1]), item[2]
        ))
    ], rejected


def _match_loaded(rows: list[dict[str, Any]], product: dict[str, str]) -> list[dict[str, Any]]:
    wanted = advisory_store._product_key(product["vendor"], product["product"])
    try:
        observed = Version(advisory_store._single_line(product["version"], "version", maximum=256))
    except InvalidVersion as exc:
        raise ValueError(f"invalid observed version: {product['version']}") from exc
    matches: list[dict[str, Any]] = []
    for row in rows:
        if advisory_store._product_key(str(row["vendor"]), str(row["product"])) != wanted:
            continue
        constraint = str(row["version_constraint"])
        if constraint == "*" or observed in SpecifierSet(constraint):
            matches.append(row)
    return sorted(matches, key=lambda row: (-float(row["cvss"]), str(row["id"])))


def project(root: Path, store: str) -> dict[str, Any]:
    if not store:
        return {"status": "disabled", "observations": 0, "matches": 0, "rejected": 0}
    store_path = Path(store).expanduser()
    advisories = advisory_store.load_advisories(store_path)
    products, rejected = _inventory_products(root)
    matches: list[dict[str, Any]] = []
    valid_products = 0
    for product in products:
        try:
            product_matches = _match_loaded(advisories, product)
        except ValueError as exc:
            rejected.append({
                "source": "normalized-inventory",
                "reason": "invalid-version",
                "vendor": product["vendor"],
                "product": product["product"],
                "version": product["version"],
                "error": str(exc),
            })
            continue
        valid_products += 1
        for advisory in product_matches:
            matches.append({**product, "advisory": advisory})

    matches.sort(key=lambda row: (
        advisory_store._product_key(row["vendor"], row["product"]),
        row["version"],
        row["advisory"]["id"],
    ))
    destination = root / "10-intelligence"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    matches_path = destination / "advisory-matches.jsonl"
    rejected_path = destination / "advisory-rejections.jsonl"
    matches_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in matches),
        encoding="utf-8",
    )
    rejected_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rejected),
        encoding="utf-8",
    )
    matches_path.chmod(0o600)
    rejected_path.chmod(0o600)
    status = "partial" if rejected else "success"
    return {
        "status": status,
        "observations": len(products),
        "valid_observations": valid_products,
        "matches": len(matches),
        "rejected": len(rejected),
        "store_records": len(advisories),
        "artifact": str(matches_path.relative_to(root)),
        "rejections_artifact": str(rejected_path.relative_to(root)),
    }


def install(runtime_module: Any) -> Any:
    if getattr(runtime_module, "_ah_puch_advisory_runtime", False):
        return runtime_module

    original_local = runtime_module._run_local_capability
    runtime_module._offline_advisory_projection = project

    def run_local_capability(args: Any, capability: str) -> int:
        if capability != "advisory-mapping":
            return original_local(args, capability)
        if not args.local_run:
            raise ValueError("advisory-mapping requires --local-run")
        if not args.advisory_store:
            raise ValueError("advisory-mapping requires --advisory-store")
        root = Path(args.local_run).expanduser().resolve()
        if not (root / "manifest.json").is_file():
            raise ValueError("--local-run must contain manifest.json")
        if args.local_action and args.local_action != "advisory":
            raise ValueError(f"advisory-mapping does not support local action {args.local_action!r}")
        result = {"capability": capability, **project(root, args.advisory_store)}
        runtime_module.v2.base.reseal_saved_run(root)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if result["status"] == "success":
            return 0
        if result["status"] == "partial":
            return 3
        return 1

    runtime_module._run_local_capability = run_local_capability
    runtime_module._ah_puch_advisory_runtime = True
    return runtime_module
