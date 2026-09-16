#!/usr/bin/env python3
"""Validate one operator-approved credential pair against one approved service."""

from __future__ import annotations

import base64
import json
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirect blocked during auth validation", headers, fp)


def _ssh(target: str, username: str, password: str, timeout: int) -> dict:
    try:
        import paramiko
    except ImportError:
        return {"service": "ssh", "success": False, "status": "dependency-unavailable", "error": "paramiko unavailable"}
    host, port = target, 22
    if target.startswith("[") and "]" in target:
        end = target.index("]")
        host = target[1:end]
        suffix = target[end + 1 :]
        if suffix.startswith(":") and suffix[1:].isdigit():
            port = int(suffix[1:])
    elif target.count(":") == 1 and target.rsplit(":", 1)[1].isdigit():
        host, raw_port = target.rsplit(":", 1)
        port = int(raw_port)
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=timeout, auth_timeout=timeout, banner_timeout=timeout, allow_agent=False, look_for_keys=False)
        transport = client.get_transport()
        key = transport.get_remote_server_key() if transport else None
        return {"service": "ssh", "success": True, "status": "authenticated", "host": host, "port": port, "server_key_type": key.get_name() if key else "", "server_key_fingerprint": key.get_fingerprint().hex() if key else ""}
    except paramiko.AuthenticationException:
        return {"service": "ssh", "success": False, "status": "authentication-failed", "host": host, "port": port}
    except (paramiko.SSHException, socket.error, OSError) as exc:
        return {"service": "ssh", "success": False, "status": "connection-error", "host": host, "port": port, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        client.close()


def _http_request(opener: urllib.request.OpenerDirector, request: urllib.request.Request, timeout: int) -> tuple[int, dict[str, str], str]:
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(getattr(response, "status", response.getcode())), dict(response.headers.items()), response.geturl()
    except urllib.error.HTTPError as exc:
        return int(exc.code), dict(exc.headers.items()) if exc.headers else {}, exc.geturl() or request.full_url


def _http_basic(target: str, username: str, password: str, timeout: int) -> dict:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}/"
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"service": "http-basic", "success": False, "status": "invalid-target", "url": url}
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    challenge = urllib.request.Request(url, method="GET", headers={"User-Agent": "ah-puch/10"})
    try:
        challenge_status, challenge_headers, challenge_url = _http_request(opener, challenge, timeout)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"service": "http-basic", "success": False, "status": "connection-error", "url": url, "error": f"{type(exc).__name__}: {exc}"}
    auth_header = challenge_headers.get("WWW-Authenticate", challenge_headers.get("Www-Authenticate", ""))
    if challenge_status != 401 or "basic" not in auth_header.casefold():
        return {"service": "http-basic", "success": False, "status": "not-basic-challenge", "url": challenge_url, "http_status": challenge_status}
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = urllib.request.Request(url, method="GET", headers={"Authorization": f"Basic {token}", "User-Agent": "ah-puch/10"})
    try:
        status, _headers, response_url = _http_request(opener, request, timeout)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"service": "http-basic", "success": False, "status": "connection-error", "url": url, "error": f"{type(exc).__name__}: {exc}"}
    success = 200 <= status < 400
    return {"service": "http-basic", "success": success, "status": "authenticated" if success else ("authentication-failed" if status in {401, 403} else "http-error"), "url": response_url, "http_status": status, "challenge_status": challenge_status}


def validate_once(service: str, target: str, username: str, password: str, timeout: int = 8) -> dict:
    if not username or not password:
        raise ValueError("exact approved username and password are required")
    selected = service.strip().lower()
    if selected == "ssh":
        return _ssh(target, username, password, max(1, min(int(timeout), 60)))
    if selected in {"http-basic", "http_basic"}:
        return _http_basic(target, username, password, max(1, min(int(timeout), 60)))
    raise ValueError(f"unsupported exact credential validation service: {service}")


def write_result(root: Path, result: dict) -> Path:
    destination = root / "sensitive" / "auth-validation.jsonl"
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    destination.chmod(0o600)
    return destination
