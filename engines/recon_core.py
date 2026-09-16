#!/usr/bin/env python3
"""Automatic discovery pipeline."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

try:
    from .content_fuzz_policy import dirsearch_args
    from .dictionary_broker import explicit_info
    from .runner_registry import admitted_path
    from .wordlists import category_paths, iter_words
    from .tool_options import WAPITI_DEFAULT_MODULES, parse_assignments as parse_tool_assignments
except ImportError:
    from content_fuzz_policy import dirsearch_args
    from dictionary_broker import explicit_info
    from runner_registry import admitted_path
    from wordlists import category_paths, iter_words
    from tool_options import WAPITI_DEFAULT_MODULES, parse_assignments as parse_tool_assignments


VERSION = "2.0.0"
PROGRAM = "ah-puch"
BUNDLED_DATA = Path(__file__).resolve().parents[1] / "data"
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
PATH_RE = re.compile(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)")
NOISE_URL_MARKERS = ("setuptools.pypa.io", "pkg_resources", "/usr/", "/home/", "/tmp/")
HOST_RE = re.compile(r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])", re.I)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
SOCIAL_RE = re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com|facebook\.com|instagram\.com|youtube\.com|t\.me|linkedin\.com)(?:/[^\s\"'<>]*)?", re.I)
FILE_EXTENSIONS = ("js", "txt", "pdf", "xlsx", "doc", "docx", "csv", "zip", "jpg", "png", "rar", "apk", "json", "xml", "bak", "old", "conf", "env")
ICS_TERMS = {"modbus": "modbus", "scada": "scada", "siemens": "siemens", "bacnet": "bacnet", "dnp3": "dnp3", "industrial control": "industrial-control"}
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
SECRET_RE = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("cloud-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("generic-secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|client[_-]?secret)\b\s*[:=]\s*[\"']?[^\"'\s]{8,}")),
]

TOOL_REGISTRY = {
    "gau": "historical URLs and public source aggregation",
    "subfinder": "passive subdomain discovery",
    "getips": "address attribution for discovered hosts",
    "dig": "DNS record queries",
    "httpx": "HTTP service probing and metadata",
    "katana": "bounded endpoint crawling",
    "gospider": "secondary crawl and source collection",
    "dirsearch": "directory and extension discovery",
    "nmap": "ports, HTTP enumeration, services, and vulnerability scripts",
    "nikto": "web server checks",
    "arachni": "web application audit reports",
    "sqlmap": "parameter queue consumer",
    "masscan": "range service discovery",
    "testssl.sh": "TLS configuration checks",
    "nuclei": "template-based finding checks",
    "wapiti": "web audit consumer",
    "zap-baseline.py": "optional passive web report consumer",
    "zap-full-scan.py": "optional explicitly enabled web report consumer",
    "docker": "containerized report consumer",
    "curl": "HTTP response and range-path verification",
}

RUNNER_ID_BY_BINARY = {
    "gau": "historical_url_collection",
    "subfinder": "subdomain_discovery",
    "getips": "address_attribution",
    "dig": "dns_query",
    "httpx": "http_probe",
    "katana": "crawl_primary",
    "gospider": "crawl_secondary",
    "dirsearch": "directory_primary",
    "nmap": "network_service",
    "nikto": "web_server_check",
    "arachni": "web_audit_report",
    "sqlmap": "parameter_validation",
    "masscan": "range_discovery",
    "testssl.sh": "tls_configuration",
    "testssl": "tls_configuration",
    "nuclei": "template_checks",
    "wapiti": "web_audit_secondary",
    "zap-baseline.py": "web_proxy_passive",
    "zap-full-scan.py": "web_proxy_active",
}

ACTIVE_PROCESS_GROUP: int | None = None
_HTTPX_COMPATIBLE: bool | None = None
# The unified runner bounds a core stage to 30 minutes.  Keep individual
# producers within that budget while allowing deep/full profiles to use their
# advertised long-running window; a one-minute ceiling silently truncated
# those profiles.
MAX_TOOL_SECONDS = 1800


def stop_active_process(_signum: int, _frame: object) -> None:
    """Terminate the current child process group when the runner is stopped."""
    global ACTIVE_PROCESS_GROUP
    if ACTIVE_PROCESS_GROUP:
        try:
            os.killpg(ACTIVE_PROCESS_GROUP, signal.SIGTERM)
        except OSError:
            pass
    raise SystemExit(143)


def slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (value or "target")[:120]


def target_parts(value: str) -> tuple[str, str, str, str]:
    raw = value.strip().strip("'\";,()")
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return str(network), f"range://{network}/", slug(str(network)), "range"
        except ValueError:
            pass
    try:
        address = ipaddress.ip_address(raw.strip("[]"))
        if address.version == 6:
            host = str(address)
            return host, f"https://[{host}]/", slug(host), "host"
    except ValueError:
        pass
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if not parsed.hostname:
        raise ValueError("target has no hostname")
    host = parsed.hostname.lower().rstrip(".")
    scheme = parsed.scheme.lower() if parsed.scheme in {"http", "https"} else "https"
    port = parsed.port or (443 if scheme == "https" else 80)
    display = f"[{host}]" if ":" in host else host
    authority = f"{display}:{port}" if port not in {80, 443} else display
    base = f"{scheme}://{authority}/"
    return host, base, slug(host), "host"


def is_ip_literal(value: str) -> bool:
    """Return whether a normalized target host is a literal IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", errors="replace")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def write_lines(path: Path, values: set[str] | list[str]) -> None:
    clean = sorted({v.strip() for v in values if v and v.strip()})
    write_text(path, "\n".join(clean) + ("\n" if clean else ""))


def command_path(name: str) -> str:
    runner_id = RUNNER_ID_BY_BINARY.get(name)
    return admitted_path(runner_id) if runner_id else ""


def command_exists(name: str) -> bool:
    return bool(command_path(name))


_DEFAULT_COMMAND_EXISTS = command_exists


def executable(name: str) -> str:
    """Resolve production identity while retaining monkeypatched test guards."""
    path = command_path(name)
    if path:
        return path
    if command_exists is not _DEFAULT_COMMAND_EXISTS and command_exists(name):
        return name
    return ""


def projectdiscovery_httpx_available() -> bool:
    """Accept only the batch scanner CLI, not the unrelated Python HTTP client."""
    global _HTTPX_COMPATIBLE
    if _HTTPX_COMPATIBLE is not None:
        return _HTTPX_COMPATIBLE
    _HTTPX_COMPATIBLE = bool(executable("httpx"))
    return _HTTPX_COMPATIBLE


def bounded_tool_timeout(overall: int, ceiling: int = MAX_TOOL_SECONDS) -> int:
    """Keep one external producer within the configured core-stage budget."""
    return max(1, min(overall, ceiling))


def useful_url(value: str) -> bool:
    clean = value.rstrip(".,;:)]}")
    return bool(clean.startswith(("http://", "https://"))) and not any(marker in clean for marker in NOISE_URL_MARKERS)


def scoped_url(value: str, scope_host: str, scope_kind: str) -> bool:
    """Keep discovered HTTP URLs attached to the original target scope."""
    clean = value.rstrip(".,;:)]}")
    if not useful_url(clean):
        return False
    try:
        candidate = (urlsplit(clean).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not candidate:
        return False
    if scope_kind == "range":
        try:
            return ipaddress.ip_address(candidate) in ipaddress.ip_network(scope_host, strict=False)
        except ValueError:
            return False
    try:
        base = ipaddress.ip_address(scope_host.strip("[]"))
        return candidate == str(base)
    except ValueError:
        base = scope_host.lower().rstrip(".")
        return candidate == base or candidate.endswith("." + base)


def run_command(command: list[str], cwd: Path, output: Path, timeout: int) -> tuple[int, bool, float]:
    global ACTIVE_PROCESS_GROUP
    output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    timed_out = False
    with output.open("w", encoding="utf-8", errors="replace") as handle:
        try:
            proc = subprocess.Popen(command, cwd=str(cwd), stdout=handle, stderr=subprocess.STDOUT, text=True, start_new_session=True)
            ACTIVE_PROCESS_GROUP = proc.pid
            try:
                rc = proc.wait(timeout=max(1, timeout))
            except subprocess.TimeoutExpired:
                timed_out = True
                rc = 124
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except OSError:
                        pass
            finally:
                ACTIVE_PROCESS_GROUP = None
        except OSError as exc:
            handle.write(f"process-start-error: {exc}\n")
            rc = 127
    return rc, timed_out, time.monotonic() - started


class CoreRun:
    def __init__(
        self,
        target: str,
        output: Path,
        profile: str,
        intrusive: bool,
        timeout: int,
        wordlist_tier: str = "micro",
        range_ports: str = "80,443,554,8000,8080,8554,502,102,20000,47808",
        range_rate: int = 500,
        range_host_limit: int = 256,
        tool_options: dict[str, dict[str, object]] | None = None,
        use_dictionaries: bool = True,
    ):
        self.raw_target = target
        self.host, self.base_url, self.target_slug, self.target_kind = target_parts(target)
        self.output = output.resolve()
        self.profile = profile
        self.intrusive = intrusive
        self.timeout = timeout
        self.wordlist_tier = wordlist_tier
        self.use_dictionaries = use_dictionaries
        self.range_ports = range_ports
        self.range_rate = max(1, range_rate)
        self.range_host_limit = max(1, range_host_limit)
        self.tool_options = tool_options or {}
        self.events: list[dict[str, object]] = []
        self.urls: set[str] = set() if self.target_kind == "range" else {self.base_url}
        self.hosts: set[str] = {self.host}
        self.output.mkdir(parents=True, mode=0o700, exist_ok=True)

    def tool_value(self, tool: str, key: str, default: object) -> object:
        return self.tool_options.get(tool, {}).get(key, default)

    def tool_int(self, tool: str, key: str, default: int, minimum: int = 1) -> int:
        value = self.tool_value(tool, key, default)
        try:
            return max(minimum, int(value))
        except (TypeError, ValueError):
            return default

    def tool_bool(self, tool: str, key: str, default: bool) -> bool:
        value = self.tool_value(tool, key, int(default))
        return bool(value) and str(value).lower() not in {"0", "false", "no", "off"}

    def event(self, stage: str, status: str, command: list[str] | None = None, **extra: object) -> None:
        row: dict[str, object] = {"engine": "recon_core", "stage": stage, "status": status, "timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}
        if command:
            row["command"] = command
        row.update(extra)
        self.events.append(row)
        with (self.output / "module_status.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        try:
            (self.output / "module_status.jsonl").chmod(0o600)
        except OSError:
            pass

    def alert(self, category: str, evidence: str, source: str) -> None:
        path = self.output / "alerts" / f"{self.target_slug}.alerts.txt"
        existing = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        line = f"{category}\tsource={source}\tevidence={evidence}"
        if line not in existing.splitlines():
            write_text(path, existing + line + "\n")
        print(f"[alert] {category}: {evidence}")
        self.event("alerts", "alert", category=category, evidence=evidence, source=source)

    def artifact(self, stage: str, suffix: str) -> Path:
        return self.output / stage / f"{self.target_slug}.{suffix}.txt"

    def execute(self, stage: str, command: list[str], suffix: str, timeout: int | None = None) -> Path:
        destination = self.artifact(stage, suffix)
        console = self.output / stage / f"{self.target_slug}.{suffix}.console.txt"
        rc, timed_out, duration = run_command(command, self.output, console, timeout or self.timeout)
        if not destination.exists() or destination.stat().st_size == 0:
            try:
                write_text(destination, console.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        status = "timeout" if timed_out else ("success" if rc == 0 else "partial")
        self.event(stage, status, command, exit_code=rc, duration=round(duration, 3), output=str(destination.relative_to(self.output)), console=str(console.relative_to(self.output)))
        return destination

    def discover(self) -> None:
        stage = "01-discovery"
        if self.target_kind == "range":
            write_lines(self.artifact(stage, "subdomains"), {self.host})
            write_lines(self.artifact(stage, "hosts"), {self.host})
            self.event(stage, "success", reason="range input recorded")
            return
        subs: set[str] = {self.host}
        sub_path = self.artifact(stage, "subfinder.subdomains")
        subfinder = executable("subfinder")
        if not is_ip_literal(self.host) and subfinder:
            command = [subfinder, "-d", self.host, "-silent", "-duc", "-t", str(self.tool_int("subfinder", "threads", 10)), "-o", str(sub_path)]
            sources = str(self.tool_value("subfinder", "sources", ""))
            if sources:
                command.extend(["-s", sources])
            if self.tool_bool("subfinder", "recursive", False):
                command.append("-recursive")
            self.execute(stage, command, "subfinder.subdomains", bounded_tool_timeout(self.timeout))
            subs.update(x.strip().lower() for x in sub_path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip())
        else:
            self.event(stage, "skipped", reason="subfinder unavailable or target is an IP")
        write_lines(self.artifact(stage, "subdomains"), subs)
        self.hosts.update(subs)

        ips_path = self.artifact(stage, "getips.addresses")
        helper_used = False
        getips = executable("getips")
        if getips and sub_path.is_file():
            command = [getips, "-d", str(sub_path), "-o", str(ips_path)]
            if self.tool_bool("getips", "verbose", True):
                command.insert(1, "-v")
            self.execute(stage, command, "getips.addresses", bounded_tool_timeout(self.timeout))
            if ips_path.is_file():
                helper_addresses = set()
                for line in ips_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    value = line.strip()
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    helper_addresses.add(value)
                if helper_addresses:
                    self.hosts.update(helper_addresses)
                    helper_used = True
        if not helper_used:
            addresses: set[str] = set()
            for host in subs:
                try:
                    addresses.update(result[4][0] for result in socket.getaddrinfo(host, None))
                except socket.gaierror:
                    continue
            write_lines(ips_path, addresses)
            self.hosts.update(addresses)
            self.event(stage, "success", reason="built-in DNS address attribution fallback", addresses=len(addresses), helper_fallback=True)

        gau_path = self.artifact(stage, "gau.urls")
        gau = executable("gau")
        if gau and not is_ip_literal(self.host):
            command = [gau, "--threads", str(self.tool_int("gau", "threads", 30)), "--timeout", str(self.tool_int("gau", "timeout", 10)), "--o", str(gau_path)]
            if self.tool_bool("gau", "subs", True):
                command.append("--subs")
            command.append(self.host)
            self.execute(stage, command, "gau.urls", bounded_tool_timeout(self.timeout))
            if gau_path.is_file():
                self.urls.update(value for value in URL_RE.findall(gau_path.read_text(encoding="utf-8", errors="replace")) if scoped_url(value, self.host, self.target_kind))
        else:
            write_lines(gau_path, set())
            self.event(stage, "skipped", reason="gau unavailable or target is an IP")
        write_lines(self.artifact(stage, "historical.urls"), self.urls)
        write_lines(self.artifact(stage, "hosts"), self.hosts)

    def dns(self) -> None:
        stage = "02-dns"
        if self.target_kind == "range":
            write_lines(self.artifact(stage, "dns.records"), set())
            write_lines(self.artifact(stage, "host-addresses"), {self.host})
            self.event(stage, "skipped", reason="DNS lookup is not applicable to a network range")
            return
        records: list[str] = []
        for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"):
            path = self.artifact(stage, f"dns.{record_type.lower()}")
            dig = executable("dig")
            if dig:
                self.execute(stage, [dig, "+short", record_type, self.host], f"dns.{record_type.lower()}", min(self.timeout, 60))
                if path.is_file():
                    records.extend(f"{record_type}\t{x.strip()}" for x in path.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip())
            else:
                self.event(stage, "skipped", reason="dig unavailable")
        write_lines(self.artifact(stage, "dns.records"), records)
        addresses: set[str] = set()
        for host in self.hosts:
            try:
                for result in socket.getaddrinfo(host, None):
                    addresses.add(result[4][0])
            except socket.gaierror:
                continue
        write_lines(self.artifact(stage, "host-addresses"), addresses)
        self.hosts.update(addresses)

    def http(self) -> None:
        stage = "03-http"
        if self.target_kind == "range":
            write_lines(self.artifact(stage, "inputs"), set())
            write_lines(self.artifact(stage, "live.urls"), set())
            self.event(stage, "skipped", reason="HTTP probing is deferred to range service discovery")
            return
        inputs = self.artifact(stage, "inputs")
        write_lines(inputs, self.urls | {self.base_url})
        live = self.artifact(stage, "httpx.live")
        httpx = executable("httpx") if projectdiscovery_httpx_available() else ""
        if httpx:
                command = [httpx, "-l", str(inputs), "-silent", "-json"]
                for option, flag in (("status_code", "-sc"), ("title", "-title"), ("server", "-server"), ("ip", "-ip"), ("cname", "-cname"), ("tech_detect", "-td")):
                    if self.tool_bool("httpx", option, True):
                        command.append(flag)
                command.extend(["-threads", str(self.tool_int("httpx", "threads", 50)), "-timeout", str(self.tool_int("httpx", "timeout", 10))])
                rate_limit = self.tool_int("httpx", "rate_limit", 0, 0)
                if rate_limit > 0:
                    command.extend(["-rate-limit", str(rate_limit)])
                command.extend(["-o", str(live)])
                self.execute(stage, command, "httpx.live", bounded_tool_timeout(self.timeout))
        else:
            self.event(stage, "skipped", reason="compatible batch HTTP probe unavailable")
        observed: set[str] = set()
        if live.is_file():
            for line in live.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    row = json.loads(line)
                    if row.get("url"):
                        observed.add(str(row["url"]))
                except json.JSONDecodeError:
                    if line.startswith(("http://", "https://")):
                        observed.add(line.split()[0])
        if not observed:
            try:
                request = Request(self.base_url, headers={"User-Agent": f"{PROGRAM}/{VERSION}"})
                with urlopen(request, timeout=min(self.timeout, 15)) as response:
                    observed.add(self.base_url)
                    write_text(self.artifact(stage, "http.response"), f"url={self.base_url}\nstatus={response.status}\nserver={response.headers.get('Server', '')}\n")
            except Exception as exc:
                self.event(stage, "partial", reason=f"direct probe failed: {exc}")
        self.urls.update(observed)
        write_lines(self.artifact(stage, "live.urls"), observed)
        write_lines(self.artifact(stage, "services"), observed)

    def content(self) -> None:
        stage = "04-crawl"
        if self.target_kind == "range":
            write_lines(self.artifact(stage, "crawl.urls"), set())
            self.event(stage, "skipped", reason="crawling requires discovered HTTP origins")
            return
        origins = self.artifact(stage, "origins")
        write_lines(origins, {f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/" for url in self.urls if urlsplit(url).scheme in {"http", "https"} and urlsplit(url).netloc})
        crawl = self.artifact(stage, "katana.urls")
        katana = executable("katana")
        if katana:
            command = [katana, "-list", str(origins), "-silent", "-d", str(self.tool_int("katana", "depth", 3)), "-c", str(self.tool_int("katana", "threads", self.tool_int("katana", "concurrency", 10))), "-o", str(crawl)]
            if self.tool_bool("katana", "js_crawl", True):
                command.append("-jc")
            self.execute(stage, command, "katana.urls", bounded_tool_timeout(self.timeout))
        else:
            write_lines(crawl, set())
            self.event(stage, "skipped", reason="katana unavailable")
        secondary_crawl = self.artifact(stage, "gospider.urls")
        gospider = executable("gospider")
        if gospider:
            raw_dir = self.output / stage / f"{self.target_slug}.gospider-raw"
            command = [gospider, "-v", "-S", str(origins), "-t", str(self.tool_int("gospider", "threads", 5)), "-c", str(self.tool_int("gospider", "concurrency", 10)), "-d", str(self.tool_int("gospider", "depth", 5)), "-o", str(raw_dir)]
            if self.tool_bool("gospider", "other_source", True):
                command.append("--other-source")
            self.execute(stage, command, "gospider.urls", bounded_tool_timeout(self.timeout))
            gathered: set[str] = set()
            if raw_dir.is_dir():
                for raw_file in raw_dir.rglob("*"):
                    if raw_file.is_file():
                        try:
                            gathered.update(URL_RE.findall(raw_file.read_text(encoding="utf-8", errors="replace")))
                        except OSError:
                            pass
                shutil.rmtree(raw_dir, ignore_errors=True)
            write_lines(secondary_crawl, gathered)
        else:
            write_lines(secondary_crawl, set())
            self.event(stage, "skipped", reason="gospider unavailable")
        if not crawl.is_file() and secondary_crawl.is_file():
            crawl = secondary_crawl
        if crawl.is_file():
            self.urls.update(value for value in URL_RE.findall(crawl.read_text(encoding="utf-8", errors="replace")) if scoped_url(value, self.host, self.target_kind))
        if secondary_crawl.is_file():
            self.urls.update(value for value in URL_RE.findall(secondary_crawl.read_text(encoding="utf-8", errors="replace")) if scoped_url(value, self.host, self.target_kind))
        write_lines(self.artifact(stage, "crawl.urls"), self.urls)

        directory = self.artifact("05-content", "dirsearch.paths")
        origin = next(iter(sorted({f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/" for url in self.urls if urlsplit(url).scheme in {"http", "https"}})), self.base_url)
        dirsearch = executable("dirsearch")
        if dirsearch:
            command = [
                dirsearch, "-u", origin, "--format=plain", "-o", str(directory),
                *dirsearch_args(
                    self.tool_options.get("dirsearch", {}),
                    timeout=self.timeout,
                    threads=self.tool_int("dirsearch", "threads", 4),
                ),
            ]
            dictionary = self.dictionary_path()
            # The broker is the only authority allowed to select the corpus;
            # invalid explicit paths therefore cannot leak into subprocess argv.
            if dictionary:
                command.extend(["-w", str(dictionary)])
            self.execute("05-content", command, "dirsearch.paths", bounded_tool_timeout(self.timeout))
        else:
            write_lines(directory, set())
            self.event("05-content", "skipped", reason="dirsearch unavailable")
        write_lines(self.artifact("05-content", "directories"), {x for x in directory.read_text(encoding="utf-8", errors="replace").splitlines() if "/" in x} if directory.is_file() else set())

    def crawl_projections(self) -> None:
        """Publish the extra evidence produced by the secondary crawl workflow."""
        stage = "04-crawl"
        urls: set[str] = {value for value in self.urls if scoped_url(value, self.host, self.target_kind)}
        texts: list[tuple[Path, str]] = []
        for path in self.output.rglob("*.txt"):
            if path.name.endswith((".console.txt", ".stderr.txt", ".error.txt")):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            texts.append((path, text))
            urls.update(value for value in URL_RE.findall(text) if scoped_url(value, self.host, self.target_kind))
        files: set[str] = set()
        domains: set[str] = set()
        emails: set[str] = set()
        social: set[str] = set()
        injections: set[str] = {value for value in urls if "?" in value and "=" in value}
        titles: set[str] = set()
        banners: set[str] = set()
        title_re = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
        for value in urls:
            parsed = urlsplit(value)
            if parsed.hostname:
                domains.add(parsed.hostname.lower().rstrip("."))
            if parsed.path.lower().rsplit("/", 1)[-1].split("?", 1)[0].lower().endswith(tuple(f".{ext}" for ext in FILE_EXTENSIONS)):
                files.add(value)
        for path, text in texts:
            emails.update(EMAIL_RE.findall(text))
            social.update(value.rstrip(".,;:)]}") for value in SOCIAL_RE.findall(text))
            for match in title_re.findall(text):
                clean = re.sub(r"\s+", " ", match).strip()
                if clean:
                    titles.add(clean)
            for line in text.splitlines():
                lowered = line.lower()
                if any(marker in lowered for marker in ("server:", "x-powered-by:", "webserver", "server=")):
                    banners.add(line.strip())
        write_lines(self.artifact(stage, "files"), files)
        write_lines(self.artifact(stage, "domains"), domains)
        write_lines(self.artifact(stage, "emails"), emails)
        write_lines(self.artifact(stage, "social-links"), social)
        write_lines(self.artifact(stage, "injection.urls"), injections)
        write_lines(self.artifact(stage, "titles"), titles)
        write_lines(self.artifact(stage, "banners"), banners)
        self.urls.update(urls)
        self.event(stage, "success", projections={"files": len(files), "domains": len(domains), "emails": len(emails), "social": len(social), "injections": len(injections), "titles": len(titles), "banners": len(banners)})

    def doctor(self) -> None:
        path = self.artifact("00-doctor", "tool-catalog")
        rows = ["tool\tcapability\tstatus\tpath"]
        for tool, capability in TOOL_REGISTRY.items():
            found = executable(tool)
            compatible = bool(found)
            if tool == "getips" and not found:
                compatible = True
                found = "built-in DNS attribution fallback"
            rows.append(f"{tool}\t{capability}\t{'available' if compatible else 'missing/incompatible'}\t{found or '-'}")
        write_text(path, "\n".join(rows) + "\n")
        dictionary = self.dictionary_path()
        categories = list(category_paths(BUNDLED_DATA))
        typed_patterns = sorted(path.stem for path in (BUNDLED_DATA / "payloads").glob("*.txt"))
        write_text(
            self.artifact("00-doctor", "dictionaries"),
            f"enabled={str(self.use_dictionaries).lower()}\ntier={self.wordlist_tier}\nselected={dictionary or '-'}\ncategories={len(categories)}\ntyped_patterns={','.join(typed_patterns)}\n",
        )
        self.event("00-doctor", "success")

    def dictionary_path(self) -> Path | None:
        if not self.use_dictionaries:
            return None
        tier = self.wordlist_tier
        configured = str(self.tool_value("dirsearch", "wordlist", "") or "").strip()
        if configured:
            info = explicit_info("directory", configured, tier=tier)
            return Path(str(info["path"])) if info.get("available") else None
        bundled = {
            "micro": BUNDLED_DATA / "wordlists" / "web-micro.txt",
            "short": BUNDLED_DATA / "wordlists" / "web-short.txt",
            "long": BUNDLED_DATA / "wordlists" / "web-long.txt",
        }
        candidates = [
            os.environ.get("AH_PUCH_DICTIONARY", ""),
            os.environ.get(f"AH_PUCH_{tier.upper()}_WORDLIST", ""),
            str(bundled.get(tier, bundled["micro"])),
            str(bundled["short"]) if tier == "long" else "",
            os.environ.get("AH_PUCH_DATA_DIR", "") + "/dictionaries/web-content.txt",
            os.environ.get("AH_PUCH_DATA", "") + "/dictionaries/web-content.txt",
            str(Path.home() / ".local/share/ah-puch/dictionaries/web-content.txt"),
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).is_file() and Path(candidate).stat().st_size:
                return Path(candidate)
        return None

    def optional_consumers(self) -> None:
        stage = "11-consumers"
        origins = sorted({f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/" for url in self.urls if urlsplit(url).scheme in {"http", "https"}}) or [self.base_url]
        if self.intrusive and self.profile in {"full", "deep"}:
            nikto = executable("nikto")
            if nikto:
                self.execute(stage, [nikto, "-h", origins[0], "-Cgidirs", str(self.tool_value("nikto", "cgi_dirs", "all")), "-mutate", str(self.tool_value("nikto", "mutate", "12345")), "-o", str(self.artifact(stage, "nikto"))], "nikto", bounded_tool_timeout(self.timeout))
            else:
                self.event(stage, "skipped", reason="nikto unavailable")
            arachni = executable("arachni")
            if arachni:
                for check, suffix in (("sqli*", "arachni.sqli"), ("xss*", "arachni.xss"), ("", "arachni.common")):
                    report = self.output / stage / f"{self.target_slug}.{suffix}.afr"
                    command = [arachni, origins[0], "--audit-links", "--audit-forms", "--audit-headers", "--output-verbose", "--output-only-positives", "--report-save-path", str(report)]
                    if not self.tool_bool("arachni", "audit_links", True) and "--audit-links" in command:
                        command.remove("--audit-links")
                    if not self.tool_bool("arachni", "audit_forms", True) and "--audit-forms" in command:
                        command.remove("--audit-forms")
                    if not self.tool_bool("arachni", "audit_headers", True) and "--audit-headers" in command:
                        command.remove("--audit-headers")
                    if check:
                        configured_checks = str(self.tool_value("arachni", "checks", ""))
                        command.insert(3, f"--checks={configured_checks or check}")
                    self.execute(stage, command, suffix, bounded_tool_timeout(self.timeout))
            else:
                self.event(stage, "skipped", reason="arachni unavailable")
            tls = executable("testssl.sh")
            if tls:
                self.execute("08-network", [tls, "--quiet", "--warnings", str(self.tool_value("testssl", "warnings", "batch")), "--color", str(self.tool_value("testssl", "color", 0)), origins[0]], "testssl", bounded_tool_timeout(self.timeout))
            else:
                self.event("08-network", "skipped", reason="testssl unavailable")
            nuclei = executable("nuclei")
            if nuclei:
                web = self.artifact("11-consumers", "nuclei.targets")
                write_lines(web, self.urls)
                command = [nuclei, "-l", str(web), "-silent", "-jsonl", "-o", str(self.artifact(stage, "nuclei"))]
                severity = str(self.tool_value("nuclei", "severity", ""))
                if severity:
                    command.extend(["-severity", severity])
                rate = self.tool_int("nuclei", "rate_limit", 0, 0)
                if rate > 0:
                    command.extend(["-rl", str(rate)])
                threads = self.tool_int("nuclei", "threads", 0, 0)
                if threads > 0:
                    command.extend(["-c", str(threads)])
                self.execute(stage, command, "nuclei", bounded_tool_timeout(self.timeout))
            else:
                self.event(stage, "skipped", reason="nuclei unavailable")
            wapiti = executable("wapiti")
            if wapiti:
                command = [wapiti, "-u", origins[0], "--scope", "url", "-m", str(self.tool_value("wapiti", "modules", WAPITI_DEFAULT_MODULES)), "-f", str(self.tool_value("wapiti", "format", "json")), "-o", str(self.artifact(stage, "wapiti"))]
                if self.tool_bool("wapiti", "no_bugreport", True):
                    command.append("--no-bugreport")
                self.execute(stage, command, "wapiti", bounded_tool_timeout(self.timeout))
            else:
                self.event(stage, "skipped", reason="wapiti unavailable")
            zap_baseline = executable("zap-baseline.py")
            if zap_baseline:
                command = [
                    zap_baseline,
                    "-t", origins[0],
                    "-J", str(self.artifact(stage, "zap.baseline.json")),
                    "-r", str(self.artifact(stage, "zap.baseline.html")),
                    "-m", str(self.tool_int("zap", "passive_minutes", 10)),
                ]
                if self.tool_bool("zap", "ajax", False):
                    command.append("-j")
                self.execute(stage, command, "zap.baseline", bounded_tool_timeout(self.timeout))
            else:
                self.event(stage, "skipped", reason="zap-baseline.py unavailable")
            zap_active = executable("zap-full-scan.py")
            if zap_active and self.tool_bool("zap", "active", False):
                command = [
                    zap_active,
                    "-t", origins[0],
                    "-J", str(self.artifact(stage, "zap.active.json")),
                    "-r", str(self.artifact(stage, "zap.active.html")),
                    "-m", str(self.tool_int("zap", "active_minutes", 5)),
                ]
                self.execute(stage, command, "zap.active", bounded_tool_timeout(self.timeout))
            elif self.tool_bool("zap", "active", False):
                self.event(stage, "skipped", reason="zap-full-scan.py unavailable")
        else:
            self.event(stage, "skipped", reason="intrusive profile disabled")

    def run_range_surface(self) -> None:
        """Discover services in a CIDR and verify common paths from the dictionary."""
        stage = "10-range"
        if self.target_kind != "range":
            self.event(stage, "skipped", reason="target is not a network range")
            return
        services = self.artifact(stage, "masscan.services")
        masscan = executable("masscan")
        nmap = executable("nmap")
        if masscan and self.intrusive:
            raw = self.output / stage / f"{self.target_slug}.masscan.json"
            ports = str(self.tool_value("masscan", "ports", self.range_ports))
            rate = self.tool_int("masscan", "rate", self.range_rate)
            self.execute(stage, [masscan, "--ports", ports, "--max-rate", str(rate), "--output-format", "json", "--output-filename", str(raw), self.host], "masscan.services", bounded_tool_timeout(self.timeout))
            if raw.is_file():
                rows: list[str] = []
                for line in raw.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    items = parsed if isinstance(parsed, list) else [parsed]
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        ip = str(item.get("ip", "")).strip()
                        for port in item.get("ports", []):
                            number = port.get("port") if isinstance(port, dict) else port
                            if ip and number:
                                rows.append(f"{ip}\t{number}")
                limited = self._bounded_service_rows(rows)
                write_text(services, "\n".join(limited) + ("\n" if limited else ""))
        elif nmap and self.intrusive:
            raw = self.output / stage / f"{self.target_slug}.nmap.grep.txt"
            self.execute(stage, [nmap, "-Pn", "-n", "--open", "-p", self.range_ports, "-oG", str(raw), self.host], "nmap.services", bounded_tool_timeout(self.timeout))
            rows = []
            if raw.is_file():
                for line in raw.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not line.startswith("Host:") or "Ports:" not in line:
                        continue
                    ip = line.split()[1]
                    port_text = line.split("Ports:", 1)[1]
                    for record in port_text.split(","):
                        fields = record.strip().split("/")
                        if len(fields) >= 2 and fields[1] == "open":
                            rows.append(f"{ip}\t{fields[0]}")
            limited = self._bounded_service_rows(rows)
            write_text(services, "\n".join(limited) + ("\n" if limited else ""))
            self.event(stage, "success", reason="nmap range fallback", services=len(limited))
        else:
            write_text(services, "")
            self.event(stage, "skipped", reason="masscan unavailable or range profile is not active")
        paths = self.artifact(stage, "http.paths")
        range_source = Path(os.environ.get("AH_PUCH_RANGE_PATHS", "")) if os.environ.get("AH_PUCH_RANGE_PATHS") else BUNDLED_DATA / "wordlists" / "range.paths.txt"
        range_candidates: list[str] = []
        if range_source.is_file():
            try:
                range_candidates = [line.strip().lstrip("/") for line in range_source.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
            except OSError:
                range_candidates = []
        dictionary = self.dictionary_path()
        candidates = []
        if dictionary:
            try:
                candidates = [line.lstrip("/") for line in iter_words(dictionary, limit=100)]
            except OSError:
                candidates = []
        candidates = list(dict.fromkeys(range_candidates + candidates))[:100]
        write_text(self.artifact(stage, "range.paths"), "\n".join(candidates) + ("\n" if candidates else ""))
        services_rows = services.read_text(encoding="utf-8", errors="replace").splitlines() if services.is_file() else []
        verified: list[str] = []
        for row in services_rows[:100]:
            ip, _, port = row.partition("\t")
            if not ip or not port:
                continue
            for path in [""] + candidates[:25]:
                host = f"[{ip}]" if ":" in ip and not ip.startswith("[") else ip
                url = f"http://{host}:{port}/{path}" if path else f"http://{host}:{port}/"
                try:
                    request = Request(url, method="GET", headers={"User-Agent": f"{PROGRAM}/{VERSION}"})
                    with urlopen(request, timeout=min(self.timeout, 5)) as response:
                        verified.append(f"{response.status}\t{url}")
                except Exception:
                    continue
        write_text(paths, "\n".join(sorted(set(verified))) + ("\n" if verified else ""))
        self.event(stage, "success", services=len(services_rows), verified=len(verified))

    def _bounded_service_rows(self, rows: list[str]) -> list[str]:
        """Keep all observed ports for at most range_host_limit distinct hosts."""
        unique = sorted(set(rows), key=lambda value: (value.split("\t", 1)[0], value))
        hosts: set[str] = set()
        limited: list[str] = []
        for row in unique:
            host = row.split("\t", 1)[0]
            if host not in hosts and len(hosts) >= self.range_host_limit:
                continue
            hosts.add(host)
            limited.append(row)
        return limited

    def ics(self) -> None:
        """Build an ICS candidate queue from collected URLs and response text."""
        stage = "09-ics"
        candidates: set[str] = set()
        protocols: set[str] = set()
        for path in self.output.rglob("*.txt"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lowered = text.lower()
            matched = {label for term, label in ICS_TERMS.items() if term in lowered}
            if matched:
                scoped_candidates = {
                    url.rstrip(".,;:)]")
                    for url in URL_RE.findall(text)
                    if scoped_url(url, self.host, self.target_kind)
                }
                path_candidates = {
                    url for url in scoped_candidates
                    if any(term in url.lower() for term in matched)
                } or scoped_candidates
                if path.name.endswith(".urls.txt"):
                    path_candidates.update(
                        line.strip()
                        for line in text.splitlines()
                        if line.strip().startswith(("http://", "https://"))
                        and scoped_url(line.strip(), self.host, self.target_kind)
                    )
                if not path_candidates:
                    path_candidates.add(self.base_url)
                candidates.update(path_candidates)
                for label in matched:
                    for value in sorted(path_candidates):
                        protocols.add(f"{label}\t{value}\t{path.relative_to(self.output)}")
        write_lines(self.artifact(stage, "ics-candidates"), candidates)
        write_text(self.artifact(stage, "protocols"), "protocol\tcandidate\tsource\n" + "\n".join(sorted(protocols)) + ("\n" if protocols else ""))
        for candidate in sorted(candidates)[:25]:
            self.alert("ICS candidate", candidate, "09-ics")
        nmap = executable("nmap")
        if self.intrusive and candidates and nmap:
            hosts = sorted({urlsplit(url).hostname for url in candidates if urlsplit(url).hostname})
            target_file = self.artifact(stage, "nmap.targets")
            write_lines(target_file, hosts)
            self.execute(stage, [nmap, "-Pn", "-sV", "--script", "modbus-discover,bacnet-info,dnp3-info", "-p", "502,47808,20000", "-iL", str(target_file), "-oN", str(self.artifact(stage, "ics-services"))], "ics-services", bounded_tool_timeout(self.timeout))
        else:
            self.event(stage, "skipped", reason="no ICS candidates or active network checks disabled", probe_count=0)

    def endpoints(self) -> None:
        stage = "06-endpoints"
        urls: set[str] = set(self.urls)
        for path in self.output.rglob("*.txt"):
            if path.name.endswith((".console.txt", ".stderr.txt", ".error.txt")):
                continue
            if path == self.artifact(stage, "endpoints"):
                continue
            try:
                urls.update(value for value in URL_RE.findall(path.read_text(encoding="utf-8", errors="replace")) if scoped_url(value, self.host, self.target_kind))
            except OSError:
                continue
        params = {url.rstrip(".,;:)]") for url in urls if "?" in url and "=" in url}
        write_lines(self.artifact(stage, "endpoints"), urls)
        write_lines(self.artifact(stage, "parameters"), params)
        self.urls.update(urls)

    def analysis(self) -> None:
        stage = "07-analysis"
        findings: list[str] = []
        for path in self.output.rglob("*.txt"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_number, line in enumerate(text.splitlines(), 1):
                for kind, pattern in SECRET_RE:
                    if pattern.search(line):
                        digest = hashlib.sha256(line.encode()).hexdigest()
                        findings.append(f"{kind}\t{path.relative_to(self.output)}\t{line_number}\t{digest}")
                        break
        write_text(self.artifact(stage, "secrets"), "type\tsource\tline\tsha256\n" + "\n".join(sorted(set(findings))) + ("\n" if findings else ""))
        technology_rows: set[str] = set()
        for path in self.output.rglob("*.httpx.live.txt"):
            try:
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    for key in ("webserver", "tech", "technologies", "cdn"):
                        value = row.get(key)
                        if isinstance(value, list):
                            technology_rows.update(str(item) for item in value)
                        elif value:
                            technology_rows.add(str(value))
            except OSError:
                pass
        write_lines(self.artifact(stage, "technologies"), technology_rows)

    def assets(self) -> None:
        stage = "10-intelligence"
        rows: list[str] = []
        for host in sorted(self.hosts):
            kind = "root" if host == self.host else ("subdomain" if host.endswith("." + self.host) else "address-or-related")
            rows.append(f"{host}\t{kind}\t{'in-scope' if kind in {'root', 'subdomain'} else 'observed'}")
        write_text(self.artifact(stage, "assets"), "asset\tkind\tstatus\n" + "\n".join(rows) + ("\n" if rows else ""))
        write_lines(self.artifact(stage, "subdomains"), {host for host in self.hosts if "." in host and not re.fullmatch(r"[0-9a-fA-F:.]+", host)})
        write_lines(self.artifact(stage, "addresses"), {host for host in self.hosts if re.fullmatch(r"[0-9a-fA-F:.]+", host)})
        self.event(stage, "success", assets=len(rows))

    def cve(self) -> None:
        """Match observed CVE references against the bundled passive index."""
        stage = "10-intelligence"
        hot_path = BUNDLED_DATA / "advisories" / "hot_advisories.csv"
        metadata: dict[str, dict[str, str]] = {}
        hot: set[str] = set()
        if hot_path.is_file():
            try:
                with hot_path.open(newline="", encoding="utf-8", errors="replace") as handle:
                    for row in csv.DictReader(handle):
                        cve = str(row.get("cve_id", "")).upper().strip()
                        if not cve:
                            continue
                        hot.add(cve)
                        metadata[cve] = {
                            "product": str(row.get("product", "unknown")).strip() or "unknown",
                            "version": str(row.get("version", "unknown")).strip() or "unknown",
                            "severity": str(row.get("severity", "unknown")).strip() or "unknown",
                            "reference": str(row.get("reference", "")).strip(),
                            "provenance": str(row.get("provenance", "data/advisories/hot_advisories.csv")).strip() or "data/advisories/hot_advisories.csv",
                        }
            except OSError:
                pass
        observed: dict[str, set[str]] = {}
        for path in self.output.rglob("*.txt"):
            if path.name.endswith((".console.txt", ".stderr.txt", ".error.txt")):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for value in CVE_RE.findall(text):
                observed.setdefault(value.upper(), set()).add(str(path.relative_to(self.output)))
        rows = ["cve\tstatus\tproduct\tversion\tseverity\treference\tprovenance\tsources"]
        for value in sorted(observed):
            item = metadata.get(value, {"product": "unknown", "version": "unknown", "severity": "unknown", "reference": "", "provenance": "observed-output"})
            rows.append("\t".join((value, "hot-index" if value in hot else "observed", item["product"], item["version"], item["severity"], item["reference"], item["provenance"], ",".join(sorted(observed[value])))))
        write_text(self.artifact(stage, "advisories.matches"), "\n".join(rows) + "\n")
        index_rows = ["cve\tproduct\tversion\tseverity\treference\tprovenance"]
        for value in sorted(metadata):
            item = metadata[value]
            index_rows.append("\t".join((value, item["product"], item["version"], item["severity"], item["reference"], item["provenance"])))
        write_text(self.artifact(stage, "advisories.index"), "\n".join(index_rows) + "\n")
        self.event(stage, "success", cve_matches=len(observed), hot_index=len(hot), metadata_entries=len(metadata), network_contact=False)

    def consumers(self) -> None:
        stage = "11-consumers"
        queue_dir = self.output / "queues"
        parameter_file = queue_dir / f"{self.target_slug}.analysis-order.txt"
        order_tsv = queue_dir / f"{self.target_slug}.analysis-order.tsv"
        ordered_params: list[str] = []
        if order_tsv.is_file():
            for raw in order_tsv.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
                fields = raw.split("\t", 4)
                if len(fields) >= 4 and fields[2] == "sqlmap":
                    ordered_params.append(fields[3])
        params = set(ordered_params)
        write_text(self.artifact(stage, "sqlmap.targets"), "\n".join(ordered_params) + ("\n" if ordered_params else ""))
        addresses = self.artifact("02-dns", "host-addresses")
        hosts = set(addresses.read_text(encoding="utf-8", errors="replace").splitlines()) if addresses.is_file() else {self.host}
        write_lines(self.artifact("08-network", "nmap.targets"), hosts)
        nmap = executable("nmap")
        if self.intrusive and self.profile in {"full", "deep"} and nmap and addresses.is_file() and addresses.stat().st_size:
            target_file = str(addresses)
            self.execute("08-network", [nmap, "-Pn", "-T3", "--top-ports", str(self.tool_int("nmap", "top_ports", 100)), "-iL", target_file, "-oN", str(self.artifact("08-network", "nmap.ports"))], "nmap.ports", bounded_tool_timeout(self.timeout))
            service_command = [nmap, "-Pn"]
            if self.tool_bool("nmap", "service_detection", True):
                service_command.append("-sV")
            if self.tool_bool("nmap", "os_detection", True):
                service_command.append("-O")
            service_command.extend(["-iL", target_file, "-oN", str(self.artifact("08-network", "nmap.os-services"))])
            self.execute("08-network", service_command, "nmap.os-services", bounded_tool_timeout(self.timeout))
            scripts = str(self.tool_value("nmap", "scripts", "") or "vuln")
            self.execute("08-network", [nmap, "-Pn", "--script", scripts, "-iL", target_file, "-oN", str(self.artifact("08-network", "nmap.vulnerabilities"))], "nmap.vulnerabilities", bounded_tool_timeout(self.timeout))
            self.execute("08-network", [nmap, "-Pn", "-p", str(self.tool_value("nmap", "ports", "80,443,8080,8000")), "--script", "http-enum,http-auth,http-methods", "-iL", target_file, "-oN", str(self.artifact("08-network", "nmap.http"))], "nmap.http", bounded_tool_timeout(self.timeout))
        else:
            self.event("08-network", "skipped", reason="nmap unavailable or intrusive profile disabled")
        sqlmap = executable("sqlmap")
        if self.intrusive and params and sqlmap:
            default_level, default_risk = ((5, 3) if self.profile == "deep" else (3, 2))
            level = self.tool_int("sqlmap", "level", default_level)
            risk = self.tool_int("sqlmap", "risk", default_risk)
            command = [sqlmap, "-m", str(self.artifact(stage, "sqlmap.targets")), f"--level={level}", f"--risk={risk}", "--output-dir", str(self.output / stage / "sqlmap")]
            if self.tool_bool("sqlmap", "batch", True):
                command.append("--batch")
            if self.tool_bool("sqlmap", "skip_static", True):
                command.append("--skip-static")
            command.append("--random-agent")
            self.execute(stage, command, "sqlmap.results", bounded_tool_timeout(self.timeout))
        else:
            self.event(stage, "skipped", reason="sqlmap unavailable, no parameter queue, or intrusive profile disabled")

    def build_queues(self) -> None:
        """Materialize every hand-off used by the automatic chain."""
        stage = "11-consumers"
        all_urls: set[str] = {value for value in self.urls if scoped_url(value, self.host, self.target_kind)}
        for path in self.output.rglob("*.txt"):
            if path.name.endswith((".console.txt", ".stderr.txt", ".error.txt")):
                continue
            try:
                all_urls.update(value for value in URL_RE.findall(path.read_text(encoding="utf-8", errors="replace")) if scoped_url(value, self.host, self.target_kind))
            except OSError:
                continue
        params = {url.rstrip(".,;:)]") for url in all_urls if "?" in url and "=" in url}
        paths: set[str] = set()
        for path in self.output.rglob("*.txt"):
            if path.name.endswith((".console.txt", ".stderr.txt", ".error.txt")):
                continue
            if "05-content" not in str(path) and "04-crawl" not in str(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                for value in URL_RE.findall(text):
                    if scoped_url(value, self.host, self.target_kind):
                        all_urls.add(value.rstrip(".,;:)]"))
                for value in PATH_RE.findall(text):
                    value = value.rstrip(".,;:)]")
                    if not re.match(r"^/[A-Za-z0-9.~\-]", value) or value.startswith(("/usr/", "/home/", "/tmp/", "/var/")):
                        continue
                    if value != "/":
                        paths.add(value)
            except OSError:
                continue
        queues = self.output / "queues"
        prefix = self.target_slug
        q = lambda name: queues / f"{prefix}.{name}.txt"
        write_lines(q("all.urls"), all_urls)
        write_lines(q("parameterized.urls"), params)
        write_lines(q("directories.paths"), paths)
        write_lines(q("sqlmap.urls"), params)
        write_lines(q("nmap.hosts"), self.hosts)
        crawl_files = self.artifact("04-crawl", "files")
        crawl_domains = self.artifact("04-crawl", "domains")
        injection_file = self.artifact("04-crawl", "injection.urls")
        write_lines(q("crawl.files"), set(crawl_files.read_text(encoding="utf-8", errors="replace").splitlines()) if crawl_files.is_file() else set())
        write_lines(q("crawl.domains"), set(crawl_domains.read_text(encoding="utf-8", errors="replace").splitlines()) if crawl_domains.is_file() else set())
        write_lines(q("injection.urls"), set(injection_file.read_text(encoding="utf-8", errors="replace").splitlines()) if injection_file.is_file() else params)
        ics_path = self.artifact("09-ics", "ics-candidates")
        ics_values = set(ics_path.read_text(encoding="utf-8", errors="replace").splitlines()) if ics_path.is_file() else set()
        write_lines(q("ics.candidates"), ics_values)

        order: dict[str, tuple[int, str, str, str]] = {}

        def add(value: str, score: int, queue: str, consumer: str, reason: str) -> None:
            value = value.strip()
            if not value:
                return
            current = order.get(value)
            candidate = (score, queue, consumer, reason)
            if current is None or score > current[0]:
                order[value] = candidate

        for value in params:
            query = urlsplit(value).query.lower()
            score = 90 if any(key in query for key in ("id=", "url=", "file=", "path=", "query=", "search=")) else 70
            add(value, score, "parameterized.urls", "sqlmap", "parameterized endpoint")
        for value in ics_values:
            add(value, 100, "ics.candidates", "ics", "industrial indicator")
        for value in paths:
            lowered = value.lower()
            if any(token in lowered for token in (".bak", ".old", ".zip", ".tar", ".gz", "backup", "dump")):
                add(value, 88, "directories.paths", "content-review", "backup candidate")
            elif any(token in lowered for token in ("/api", "/rest", "/graphql", "/swagger", "/openapi")):
                add(value, 82, "directories.paths", "api-analysis", "API candidate")
            else:
                add(value, 60, "directories.paths", "content-review", "discovered path")
        for value in all_urls:
            if value not in order:
                lowered = urlsplit(value).path.lower()
                if any(token in lowered for token in (".bak", ".old", ".zip", ".tar", ".gz", "backup", "dump")):
                    add(value, 88, "all.urls", "content-review", "backup URL candidate")
                elif any(token in lowered for token in ("/api", "/rest", "/graphql", "/swagger", "/openapi")):
                    add(value, 82, "all.urls", "api-analysis", "API URL candidate")
                else:
                    add(value, 40, "all.urls", "web-analysis", "observed URL")
        ordered = sorted(order.items(), key=lambda item: (-item[1][0], item[0]))
        rows = ["score\tqueue\tconsumer\tvalue\treason"]
        for value, (score, queue, consumer, reason) in ordered:
            rows.append(f"{score}\t{queue}\t{consumer}\t{value}\t{reason}")
        write_text(queues / f"{prefix}.analysis-order.tsv", "\n".join(rows) + "\n")
        write_text(queues / f"{prefix}.analysis-order.txt", "\n".join(value for value, _ in ordered) + ("\n" if ordered else ""))
        self.event(stage, "success", queues=12, analysis_order=len(ordered))

    def rebuild_saved(self) -> int:
        """Rebuild queues from an existing run without contacting its target."""
        for path in self.output.rglob("*.txt"):
            if path.name.endswith("analysis-order.txt"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self.urls.update(value for value in URL_RE.findall(text) if scoped_url(value, self.host, self.target_kind))
        for value in self.urls:
            parsed = urlsplit(value)
            if parsed.hostname:
                self.hosts.add(parsed.hostname.lower())
        self.build_queues()
        write_text(self.output / f"{self.target_slug}.queue-rebuild.txt", "saved-run=true\nnetwork-contact=false\nanalysis-order=rebuilt\n")
        return 0

    def finish(self) -> int:
        write_lines(self.output / "queues" / f"{self.target_slug}.urls.txt", self.urls)
        write_lines(self.output / "queues" / f"{self.target_slug}.hosts.txt", self.hosts)
        summary = {"version": VERSION, "target": self.base_url, "profile": self.profile, "events": len(self.events), "urls": len(self.urls), "hosts": len(self.hosts)}
        write_text(self.output / "summary.txt", "\n".join(f"{key}={value}" for key, value in summary.items()) + "\n")
        write_text(self.output / "summary.json", json.dumps(summary, indent=2) + "\n")
        if any(str(event.get("status")) in {"failed", "timeout"} for event in self.events):
            return 10
        return 0

    def run(self) -> int:
        manifest = {"version": VERSION, "target": {"raw": self.raw_target, "url": self.base_url, "host": self.host, "kind": self.target_kind}, "profile": self.profile, "tool_options": self.tool_options, "engine": "recon_core"}
        write_text(self.output / "manifest.json", json.dumps(manifest, indent=2) + "\n")
        self.doctor()
        self.discover()
        self.dns()
        self.http()
        self.content()
        self.crawl_projections()
        self.run_range_surface()
        self.endpoints()
        self.analysis()
        self.cve()
        self.assets()
        self.ics()
        self.build_queues()
        self.consumers()
        self.optional_consumers()
        return self.finish()


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGTERM, stop_active_process)
    signal.signal(signal.SIGINT, stop_active_process)
    parser = argparse.ArgumentParser(prog="recon_core")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--profile", choices=("baseline", "full", "deep"), default="baseline")
    parser.add_argument("--run", default="full")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--intrusive", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--wordlist-tier", choices=("micro", "short", "long"), default="micro")
    parser.add_argument("--no-dictionaries", action="store_true")
    parser.add_argument("--range-ports", default="80,443,554,8000,8080,8554,502,102,20000,47808")
    parser.add_argument("--range-rate", type=int, default=500)
    parser.add_argument("--range-host-limit", type=int, default=256)
    parser.add_argument("--tool-option", action="append", default=[], metavar="TOOL.KEY=VALUE")
    parser.add_argument("--rebuild-saved", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error("timeout must be positive")
    if args.range_rate < 1 or args.range_host_limit < 1:
        parser.error("range rate and host limit must be positive")
    try:
        tool_options = parse_tool_assignments(args.tool_option)
    except ValueError as exc:
        parser.error(str(exc))
    runner = CoreRun(
        args.target,
        Path(args.output),
        args.profile,
        args.intrusive,
        args.timeout,
        args.wordlist_tier,
        args.range_ports,
        args.range_rate,
        args.range_host_limit,
        tool_options,
        use_dictionaries=not args.no_dictionaries,
    )
    return runner.rebuild_saved() if args.rebuild_saved else runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
