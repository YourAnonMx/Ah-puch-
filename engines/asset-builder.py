#!/usr/bin/env python3
"""Build a target asset inventory from an existing saved run."""
import json
import os
import re
import sys
from urllib.parse import urlsplit


def main() -> int:
    if len(sys.argv) != 5:
        return 2
    run_root, scope_root, target_host, output_dir = sys.argv[1:]
    scope_root = scope_root.strip("[]").rstrip(".").lower()
    target_host = target_host.strip("[]").rstrip(".").lower()
    root_label = scope_root.split(".", 1)[0]
    host_re = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
    url_re = re.compile(r"https?://[^\s\"<>]+", re.I)
    candidates = {scope_root, target_host}
    certificate_names = set()
    aliases = set()

    def add(value: str) -> None:
        value = value.strip("[]").rstrip(".,;:)]").lower()
        if not value or "." not in value or len(value) > 253:
            return
        if (
            value == scope_root
            or value.endswith("." + scope_root)
            or value.split(".", 1)[0].startswith(root_label)
        ):
            candidates.add(value)

    for current, dirs, files in os.walk(run_root):
        dirs[:] = [
            item
            for item in dirs
            if item not in {"responses", "session", "report-db", "markdown", "screenshots"}
            and not item.startswith(".")
        ]
        for name in files:
            if name in {"commands.log", "ah-puch.log", "checksums.sha256"}:
                continue
            path = os.path.join(current, name)
            try:
                if os.path.getsize(path) > 8 * 1024 * 1024:
                    continue
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            relative = os.path.relpath(path, run_root).lower()
            if "/tls/" in f"/{relative}" or "certificate" in relative or "cert" in relative:
                for value in host_re.findall(text):
                    value = value.rstrip(".").lower()
                    if value == scope_root or value.endswith("." + scope_root):
                        certificate_names.add(value)
            if "/dns/" in f"/{relative}" and ("cname" in relative or "alias" in relative):
                for value in host_re.findall(text):
                    add(value)
                    aliases.add(value.rstrip(".").lower())
            for value in url_re.findall(text):
                try:
                    add(urlsplit(value).hostname or "")
                except ValueError:
                    pass
            for value in host_re.findall(text):
                add(value)

    os.makedirs(output_dir, mode=0o700, exist_ok=True)
    candidates_path = os.path.join(output_dir, "candidates.txt")
    with open(candidates_path, "w", encoding="utf-8") as handle:
        for value in sorted(candidates):
            handle.write(value + "\n")
    with open(os.path.join(output_dir, "certificate-names-candidates.txt"), "w", encoding="utf-8") as handle:
        for value in sorted(certificate_names):
            handle.write(value + "\n")
    with open(os.path.join(output_dir, "aliases-candidates.txt"), "w", encoding="utf-8") as handle:
        for value in sorted(aliases):
            handle.write(value + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
