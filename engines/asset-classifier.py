#!/usr/bin/env python3
"""Classify discovered assets and write TXT/JSONL queues."""
import json
import os
import sys


def main() -> int:
    if len(sys.argv) != 5:
        return 2
    candidates_path, mapping_path, output_dir, scope_root = sys.argv[1:]
    root = scope_root.strip("[]").rstrip(".").lower()
    addresses = {}
    if os.path.exists(mapping_path):
        for raw in open(mapping_path, encoding="utf-8", errors="replace"):
            parts = raw.rstrip("\n").split("\t")
            if len(parts) >= 3:
                addresses.setdefault(parts[0], set()).add(parts[2])

    def kind(host: str) -> str:
        if host == root:
            return "root"
        if host.endswith("." + root):
            return "subdomain"
        if host.split(".", 1)[0] == root.split(".", 1)[0]:
            return "alternate-tld"
        return "related-domain"

    rows = []
    for raw in open(candidates_path, encoding="utf-8", errors="replace"):
        host = raw.strip().lower().rstrip(".")
        if not host:
            continue
        rows.append(
            {
                "asset": host,
                "kind": kind(host),
                "in_scope": host == root or host.endswith("." + root),
                "addresses": sorted(addresses.get(host, set())),
                "source": "run-artifacts",
            }
        )

    os.makedirs(output_dir, mode=0o700, exist_ok=True)

    def write(name, values):
        with open(os.path.join(output_dir, name), "w", encoding="utf-8") as handle:
            for value in values:
                handle.write(value + "\n")

    write("all-assets.txt", [row["asset"] for row in rows])
    write("root-domains.txt", [row["asset"] for row in rows if row["kind"] == "root"])
    write("subdomains.txt", [row["asset"] for row in rows if row["kind"] == "subdomain"])
    write("related-domains.txt", [row["asset"] for row in rows if row["kind"] == "related-domain"])
    write("alternate-tlds.txt", [row["asset"] for row in rows if row["kind"] == "alternate-tld"])
    certificate_candidates = os.path.join(output_dir, "certificate-names-candidates.txt")
    alias_candidates = os.path.join(output_dir, "aliases-candidates.txt")
    certificate_names = []
    aliases = []
    if os.path.exists(certificate_candidates):
        certificate_names = [line.strip().lower().rstrip(".") for line in open(certificate_candidates, encoding="utf-8", errors="replace") if line.strip()]
    if os.path.exists(alias_candidates):
        aliases = [line.strip().lower().rstrip(".") for line in open(alias_candidates, encoding="utf-8", errors="replace") if line.strip()]
    write("certificate-names.txt", certificate_names)
    write("aliases.txt", aliases)
    write(
        "resolved-hosts.txt",
        [row["asset"] + "\t" + ",".join(row["addresses"]) for row in rows if row["addresses"]],
    )
    write("in-scope.txt", [row["asset"] for row in rows if row["in_scope"]])
    write("out-of-scope.txt", [row["asset"] for row in rows if not row["in_scope"]])
    write("live-assets.txt", [row["asset"] for row in rows if row["addresses"]])
    with open(os.path.join(output_dir, "assets.jsonl"), "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
