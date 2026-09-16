#!/usr/bin/env python3
"""Passive CDN/fronting origin collection with target-gated validation."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
CDN_MARKERS = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri", "cdn")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep baseline collection on the exact target URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirect not followed during origin baseline", headers, fp)


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def collect_candidates(root: Path, target: str, known_addresses: list[str], *, max_files: int = 1000) -> list[dict]:
    target_host = (urlsplit(target).hostname if target.startswith(("http://", "https://")) else target.split(":", 1)[0]).strip("[]").lower().rstrip(".")
    rows: dict[str, dict] = {}
    files = [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in {".txt", ".json", ".jsonl", ".tsv"}][:max_files]
    cdn_seen = False
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lowered = text.lower()
        if any(marker in lowered for marker in CDN_MARKERS):
            cdn_seen = True
        source = str(path.relative_to(root))
        for value in IP_RE.findall(text):
            if not _valid_ip(value):
                continue
            row = rows.setdefault(value, {"ip": value, "score": 0, "sources": [], "reasons": []})
            if source not in row["sources"]:
                row["sources"].append(source)
            if "dns" in source.lower() or "history" in source.lower():
                row["score"] += 3
                row["reasons"].append("dns/history evidence")
            if "certificate" in source.lower() or "tls" in source.lower():
                row["score"] += 2
                row["reasons"].append("certificate/TLS evidence")
            if "subdomain" in source.lower() or "host" in source.lower():
                row["score"] += 1
                row["reasons"].append("host/subdomain evidence")
            if target_host and target_host in lowered:
                row["score"] += 2
                row["reasons"].append("target-host co-occurrence")
    for value in known_addresses:
        if not _valid_ip(value):
            continue
        row = rows.setdefault(value, {"ip": value, "score": 0, "sources": [], "reasons": []})
        row["score"] += 1
        row["reasons"].append("observed resolved address")
    ordered = sorted(rows.values(), key=lambda row: (-int(row["score"]), row["ip"]))
    for row in ordered:
        row["cdn_context"] = cdn_seen
        row["reasons"] = sorted(set(row["reasons"]))
    destination = root / "cdn-origin"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = destination / "candidates.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in ordered), encoding="utf-8")
    path.chmod(0o600)
    return ordered


def _title(text: str) -> str:
    match = TITLE_RE.search(text)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:1000] if match else ""


def _parse_http(data: bytes) -> dict:
    head, _, body = data.partition(b"\r\n\r\n")
    head_text = head.decode("iso-8859-1", errors="replace")
    body_text = body.decode("utf-8", errors="replace")
    lines = head_text.splitlines()
    status = 0
    if lines:
        match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
        status = int(match.group(1)) if match else 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return {
        "status": status,
        "server": headers.get("server", ""),
        "title": _title(body_text),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
        "content_type": headers.get("content-type", ""),
        "response_head": "\n".join(lines[:40]),
    }


def _baseline_probe(target: str, timeout: float) -> dict:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}/"
    request = urllib.request.Request(url, headers={"User-Agent": "ah-puch/2", "Range": "bytes=0-65535"})
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(request, timeout=max(0.5, timeout)) as response:
            body = response.read(65536)
            text = body.decode("utf-8", errors="replace")
            return {
                "status": int(getattr(response, "status", response.getcode())),
                "server": response.headers.get("Server", ""),
                "title": _title(text),
                "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
                "content_type": response.headers.get("Content-Type", ""),
                "url": response.geturl(),
                "redirect_followed": False,
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(65536)
        except Exception:
            body = b""
        text = body.decode("utf-8", errors="replace")
        return {
            "status": int(exc.code),
            "server": exc.headers.get("Server", "") if exc.headers else "",
            "title": _title(text),
            "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "url": exc.geturl() or url,
            "location": exc.headers.get("Location", "") if exc.headers else "",
            "redirect_followed": False,
        }
    except Exception as exc:
        return {"status": 0, "error": f"{type(exc).__name__}: {exc}", "redirect_followed": False}


def _raw_probe(ip: str, host_header: str, timeout: float, *, tls: bool) -> dict:
    port = 443 if tls else 80
    request = f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: ah-puch/2\r\nConnection: close\r\nRange: bytes=0-65535\r\n\r\n".encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            if tls:
                context = ssl.create_default_context()
                with context.wrap_socket(raw, server_hostname=host_header) as stream:
                    cert = stream.getpeercert()
                    stream.sendall(request)
                    chunks: list[bytes] = []
                    total = 0
                    while total < 131072:
                        block = stream.recv(min(16384, 131072 - total))
                        if not block:
                            break
                        chunks.append(block)
                        total += len(block)
                    result = _parse_http(b"".join(chunks))
                    result.update({"ip": ip, "transport": "https", "tls_verified_for_host": True, "certificate": cert})
                    return result
            raw.sendall(request)
            chunks = []
            total = 0
            while total < 131072:
                block = raw.recv(min(16384, 131072 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
            result = _parse_http(b"".join(chunks))
            result.update({"ip": ip, "transport": "http", "tls_verified_for_host": False})
            return result
    except Exception as exc:
        return {
            "ip": ip,
            "transport": "https" if tls else "http",
            "status": 0,
            "tls_verified_for_host": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _similarity(baseline: dict, candidate: dict) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if baseline.get("status") and candidate.get("status") and baseline.get("status") == candidate.get("status"):
        score += 1
        reasons.append("same-status")
    if baseline.get("title") and candidate.get("title") and baseline["title"] == candidate["title"]:
        score += 3
        reasons.append("same-title")
    if baseline.get("body_sha256") and candidate.get("body_sha256") and baseline["body_sha256"] == candidate["body_sha256"]:
        score += 5
        reasons.append("same-body")
    if baseline.get("server") and candidate.get("server") and str(baseline["server"]).casefold() == str(candidate["server"]).casefold():
        score += 2
        reasons.append("same-server")
    if baseline.get("content_type") and candidate.get("content_type") and str(baseline["content_type"]).split(";", 1)[0].casefold() == str(candidate["content_type"]).split(";", 1)[0].casefold():
        score += 1
        reasons.append("same-content-type")
    if candidate.get("tls_verified_for_host"):
        score += 4
        reasons.append("tls-valid-for-target-host")
    return score, reasons


def validate_target_candidates(
    root: Path,
    target: str,
    candidates: list[dict],
    *,
    active: bool,
    allow_ip: Callable[[str], bool],
    timeout: float = 3.0,
    limit: int = 10,
) -> list[dict]:
    host = (urlsplit(target).hostname if target.startswith(("http://", "https://")) else target.split(":", 1)[0]).strip("[]")
    rows: list[dict] = []
    baseline = _baseline_probe(target, max(0.5, timeout)) if active else {"status": 0, "redirect_followed": False}
    for candidate in candidates[: max(1, limit)]:
        ip = str(candidate.get("ip", ""))
        if not ip:
            continue
        if not allow_ip(ip):
            rows.append({"ip": ip, "validated": False, "status": "outside-target", "candidate_score": candidate.get("score", 0)})
            continue
        if not active:
            rows.append({"ip": ip, "validated": False, "status": "not-probed", "candidate_score": candidate.get("score", 0)})
            continue

        probes = [
            _raw_probe(ip, host, max(0.5, timeout), tls=True),
            _raw_probe(ip, host, max(0.5, timeout), tls=False),
        ]
        ranked: list[tuple[int, list[str], dict]] = []
        for probe in probes:
            score, reasons = _similarity(baseline, probe)
            ranked.append((score, reasons, probe))
        score, reasons, best = max(ranked, key=lambda item: item[0])
        # A reachable web server is not sufficient. Require either a strong
        # content match or multiple independent identity signals.
        validated = score >= 5 and bool(best.get("status"))
        rows.append(
            {
                "ip": ip,
                "validated": validated,
                "status": best.get("status", 0),
                "transport": best.get("transport", ""),
                "similarity_score": score,
                "similarity_reasons": reasons,
                "candidate_score": candidate.get("score", 0),
                "server": best.get("server", ""),
                "title": best.get("title", ""),
                "body_sha256": best.get("body_sha256", ""),
                "tls_verified_for_host": bool(best.get("tls_verified_for_host")),
                "error": best.get("error", ""),
            }
        )
    destination = root / "cdn-origin"
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    baseline_path = destination / "baseline.json"
    baseline_path.write_text(json.dumps(baseline, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    baseline_path.chmod(0o600)
    path = destination / "validation.jsonl"
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    path.chmod(0o600)
    return rows
