#!/usr/bin/env python3
"""Rebuild readable queues from a saved run without contacting targets."""
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)")
SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("generic-secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b\s*[:=]\s*[\"']?[^\"'\s]{8,}")),
    ("connection-string", re.compile(r"(?i)\b(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s\"'<>]+")),
]


def files_under(root, include):
    base = os.path.join(root, include)
    if not os.path.exists(base):
        return
    for current, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in {"responses", "session", "screenshots", "report-db"}]
        for name in files:
            if name.startswith(".") or name in {"commands.log", "ah-puch.log", "checksums.sha256"}:
                continue
            path = os.path.join(current, name)
            try:
                if os.path.getsize(path) <= 10 * 1024 * 1024:
                    yield path
            except OSError:
                continue


def read_text(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def target_prefix(root):
    try:
        manifest = json.load(open(os.path.join(root, "manifest.json"), encoding="utf-8"))
        raw = manifest.get("target", {}).get("raw") or manifest.get("target", {}).get("url") or "target"
        value = urlsplit(raw).hostname or raw
    except (OSError, ValueError, TypeError):
        value = "target"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")[:120] or "target"


def write_lines(path, values):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for value in sorted(set(value for value in values if value)):
            handle.write(value + "\n")


def build_directories(root):
    out = os.path.join(root, "directories")
    target_url = ""
    boundary_mode = "authority"
    scope_root = ""
    try:
        manifest = json.load(open(os.path.join(root, "manifest.json"), encoding="utf-8"))
        target_url = manifest.get("target", {}).get("url", "")
        boundary_mode = manifest.get("scope", {}).get("mode", "authority")
        scope_root = manifest.get("scope", {}).get("root", "").strip("[]").rstrip(".").lower()
    except (OSError, ValueError, TypeError):
        pass

    def effective_port(parsed):
        return parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

    target = urlsplit(target_url) if target_url else None

    def allowed(value):
        if "://" not in value:
            path = value.split("?", 1)[0]
            return path == "/" or (path.startswith("/") and not path.startswith(("//", "/tmp/", "/usr/", "/home/", "/var/")) and re.match(r"^/[A-Za-z0-9._~-]", path))
        try:
            parsed = urlsplit(value)
            host = (parsed.hostname or "").lower().rstrip(".")
            if not host or parsed.scheme.lower() not in {"http", "https"}:
                return False
            if boundary_mode == "domain":
                return host == scope_root or host.endswith("." + scope_root)
            if boundary_mode == "host":
                return host == scope_root
            return bool(target) and parsed.scheme.lower() == target.scheme.lower() and host == (target.hostname or "").lower().rstrip(".") and effective_port(parsed) == effective_port(target)
        except ValueError:
            return False

    def normalize(value):
        value = value.rstrip(".,;:)]")
        if "://" not in value:
            if not allowed(value):
                return ""
            if target_url:
                from urllib.parse import urljoin
                return urljoin(target_url, value)
            return value
        return value if allowed(value) else ""

    urls = {}
    derived_names = {"discovered.txt", "roots.txt", "files.txt", "backups.txt", "api-paths.txt", "provenance.tsv", "partial"}
    for path in list(files_under(root, "dirsearch")) + list(files_under(root, "directories")):
        relative = os.path.relpath(path, root).lower()
        if relative.startswith("dirsearch/queues/") or os.path.basename(relative) in derived_names or relative.endswith((".log", ".console.log", ".errors.log")):
            continue
        text = read_text(path)
        for value in URL_RE.findall(text):
            clean = normalize(value)
            if clean:
                urls.setdefault(clean, os.path.relpath(path, root))
        for value in PATH_RE.findall(text):
            clean = normalize(value)
            if clean and len(clean) > 1:
                urls.setdefault(clean, os.path.relpath(path, root))
    directories, files, backups, api = [], [], [], []
    provenance = []
    for value, source in urls.items():
        parsed = urlsplit(value) if "://" in value else None
        path = parsed.path if parsed else value.split("?", 1)[0]
        path = path or "/"
        clean_path = path.rstrip("/") or "/"
        lower = clean_path.lower()
        is_file = bool(re.search(r"\.[a-z0-9]{1,8}$", clean_path, re.I))
        is_backup = bool(re.search(r"(?:\.bak|\.old|\.orig|\.save|\.swp|\.zip|\.tar|\.gz|\.7z|backup|dump)", lower))
        is_api = bool(re.search(r"/(?:api|rest|graphql|swagger|openapi|soap|v\d+)(?:/|$)", lower))
        if is_file:
            files.append(value)
        else:
            directories.append(value)
        if is_backup:
            backups.append(value)
        if is_api:
            api.append(value)
        provenance.append(f"{value}\t{source}\t{'file' if is_file else 'directory'}")
    write_lines(os.path.join(out, "discovered.txt"), urls)
    write_lines(os.path.join(out, "roots.txt"), directories)
    write_lines(os.path.join(out, "files.txt"), files)
    write_lines(os.path.join(out, "backups.txt"), backups)
    write_lines(os.path.join(out, "api-paths.txt"), api)
    with open(os.path.join(out, "provenance.tsv"), "w", encoding="utf-8") as handle:
        handle.write("value\tsource\ttype\n")
        handle.write("\n".join(sorted(set(provenance))))
        handle.write("\n")
    write_lines(os.path.join(root, "queues", "directories", "roots.txt"), directories)
    write_lines(os.path.join(root, "queues", "directories", "files.txt"), files)


def build_secrets(root):
    out = os.path.join(root, "secrets")
    rows = []
    for include in ("crawl", "katana", "httpx-deep", "directories", "wapiti", "zap-passive", "zap-active"):
        for path in files_under(root, include):
            text = read_text(path)
            for line_number, line in enumerate(text.splitlines(), 1):
                for kind, pattern in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue
                    value = match.group(0)
                    digest = hashlib.sha256(value.encode()).hexdigest()
                    redacted = value[:4] + "..." + value[-3:] if len(value) > 10 else "[redacted]"
                    source = os.path.relpath(path, root)
                    rows.append({"type": kind, "source": source, "line": line_number, "redacted": redacted, "sha256": digest, "confidence": "high" if kind in {"private-key", "aws-key", "github-token", "jwt"} else "medium"})
                    break
    os.makedirs(out, mode=0o700, exist_ok=True)
    with open(os.path.join(out, "secrets.jsonl"), "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    with open(os.path.join(out, "findings.txt"), "w", encoding="utf-8") as handle:
        handle.write("type\tsource\tline\tredacted\tconfidence\n")
        for row in rows:
            handle.write(f"{row['type']}\t{row['source']}\t{row['line']}\t{row['redacted']}\t{row['confidence']}\n")
    write_lines(os.path.join(out, "javascript.txt"), [r["source"] for r in rows if r["source"].endswith((".js", ".jsonl"))])
    write_lines(os.path.join(out, "configuration.txt"), [r["source"] for r in rows if not r["source"].endswith((".js", ".jsonl"))])
    return len(rows)


def build_sqlmap(root):
    out = os.path.join(root, "queues", "sqlmap")
    prefix = target_prefix(root)
    values = set()
    post = set()
    api = set()
    forms = []
    endpoint_jsonl = os.path.join(root, "endpoints", "endpoints.jsonl")
    if os.path.exists(endpoint_jsonl):
        for raw in open(endpoint_jsonl, encoding="utf-8", errors="replace"):
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            url = row.get("url", "")
            if "?" in url and "=" in url:
                values.add(url)
            if row.get("method") == "POST" or row.get("kind") == "form":
                post.add(url)
            if row.get("kind") == "form" or row.get("method") in {"POST", "PUT", "PATCH"}:
                forms.append((row.get("method", "GET"), url, ",".join(row.get("parameters", [])), row.get("source", "endpoint-inventory")))
            if row.get("kind") == "api" or re.search(r"/(?:api|rest|graphql|swagger|openapi|v\d+)(?:/|$)", url, re.I):
                api.add(url)
    for include in ("recon", "katana", "crawl", "wapiti", "endpoints"):
        for path in files_under(root, include):
            for value in URL_RE.findall(read_text(path)):
                value = value.rstrip(".,;:)]")
                if "?" in value and "=" in value:
                    values.add(value)
    write_lines(os.path.join(out, "get-urls.txt"), values)
    write_lines(os.path.join(out, "post-urls.txt"), post)
    write_lines(os.path.join(out, "api.txt"), api)
    write_lines(os.path.join(out, "parameters.txt"), values)
    with open(os.path.join(out, "forms.tsv"), "w", encoding="utf-8") as handle:
        handle.write("method\turl\tparameters\tsource\n")
        for method, url, parameters, source in sorted(set(forms)):
            handle.write(f"{method}\t{url}\t{parameters}\t{source}\n")
    with open(os.path.join(out, f"{prefix}.sqlmap.analysis-order.tsv"), "w", encoding="utf-8") as handle:
        handle.write("score\tqueue\tconsumer\tvalue\treason\n")
        for url in sorted(values):
            query = urlsplit(url).query.lower()
            score = 90 if any(key in query for key in ("id=", "url=", "file=", "path=", "query=", "search=")) else 70
            handle.write(f"{score}\tparameterized.urls\tsqlmap\t{url}\t{'high-value parameter' if score == 90 else 'parameterized URL'}\n")


def build_analysis_order(root):
    """Create one ordered handoff list from every derived queue."""
    out = os.path.join(root, "queues")
    prefix = target_prefix(root)
    records = {}

    def add(value, source, score, consumer):
        value = value.strip()
        if not value:
            return
        current = records.get(value)
        row = (int(score), source, consumer)
        if current is None or row[0] > current[0]:
            records[value] = row

    for name, score, consumer in (
        (f"queues/sqlmap/{prefix}.sqlmap.analysis-order.tsv", 90, "sqlmap"),
        ("endpoints/endpoints.in-scope.txt", 80, "endpoint-analysis"),
        ("directories/backups.txt", 75, "content-review"),
        ("directories/api-paths.txt", 70, "api-analysis"),
        ("recon/live_urls.txt", 60, "http-analysis"),
        ("queues/assets/live-assets.txt", 55, "asset-review"),
    ):
        path = os.path.join(root, name)
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8", errors="replace"):
            if name.endswith("analysis-order.tsv"):
                fields = line.rstrip("\n").split("\t")
                if fields and fields[0].isdigit() and len(fields) >= 4:
                    add(fields[3], name, int(fields[0]), consumer)
            elif line.strip() and not line.startswith("#"):
                add(line, name, score, consumer)
    os.makedirs(out, mode=0o700, exist_ok=True)
    ordered = sorted(records.items(), key=lambda item: (-item[1][0], item[0]))
    with open(os.path.join(out, f"{prefix}.analysis-order.tsv"), "w", encoding="utf-8") as handle:
        handle.write("score\tqueue\tconsumer\tvalue\treason\n")
        for value, (score, source, consumer) in ordered:
            handle.write(f"{score}\t{source}\t{consumer}\t{value}\tqueue handoff\n")
    write_lines(os.path.join(out, f"{prefix}.analysis-high.txt"), [value for value, row in ordered if row[0] >= 75])
    write_lines(os.path.join(out, f"{prefix}.analysis-order.txt"), [value for value, _ in ordered])


def main():
    if len(sys.argv) != 3:
        return 2
    mode, root = sys.argv[1:]
    if mode in {"directories", "all"}:
        build_directories(root)
    if mode in {"secrets", "all"}:
        build_secrets(root)
    if mode in {"sqlmap", "all"}:
        build_sqlmap(root)
    if mode == "all":
        build_analysis_order(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
