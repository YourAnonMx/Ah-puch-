#!/usr/bin/env python3
"""Target-aware adapter around the stable Ah-Puch core pipeline.

The stable core remains the implementation base. This adapter keeps discovery
and downstream network inputs inside the automatic target boundary. DNS A/AAAA
addresses are modeled as derived transport identities of an
hostname already inside the target rather than as unrelated discoveries.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import signal
import socket
from pathlib import Path
from urllib.parse import urlsplit

try:
    from . import recon_core as base
    from .asset_graph import host_within_target, url_within_target
except ImportError:
    import recon_core as base
    from asset_graph import host_within_target, url_within_target


def _gai_status(exc: socket.gaierror) -> str:
    clean_negative = {
        value
        for value in (getattr(socket, "EAI_NONAME", None), getattr(socket, "EAI_NODATA", None))
        if value is not None
    }
    return "no-address" if getattr(exc, "errno", None) in clean_negative else "resolver-error"


class ScopedCoreRun(base.CoreRun):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.boundary_mode = "domain"
        self._dns_attribution: dict[tuple[str, str, str], dict[str, object]] = {}

    @property
    def dns_attribution_path(self) -> Path:
        return self.output / "dns-attribution.jsonl"

    def _allowed_host(self, host: str) -> bool:
        return host_within_target(host, self.raw_target, self.boundary_mode)

    def _allowed_url(self, url: str) -> bool:
        return url_within_target(url, self.raw_target, self.boundary_mode)

    def _write_dns_attribution(self) -> None:
        rows = sorted(
            self._dns_attribution.values(),
            key=lambda row: (
                str(row.get("source_host", "")),
                str(row.get("address", "")),
                str(row.get("status", "")),
            ),
        )
        self.dns_attribution_path.write_text(
            "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self.dns_attribution_path.chmod(0o600)

    def _record_dns(self, source_host: str, address: str, status: str, **extra: object) -> None:
        key = (source_host, address, status)
        row: dict[str, object] = {
            "source_host": source_host,
            "address": address,
            "status": status,
            "source_within_target": bool(self._allowed_host(source_host)),
        }
        row.update(extra)
        self._dns_attribution[key] = row
        self._write_dns_attribution()

    def _resolve_target_host(self, host: str) -> set[str]:
        if not self._allowed_host(host):
            return set()
        try:
            answers = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            self._record_dns(host, "", _gai_status(exc), error=f"{type(exc).__name__}: {exc}")
            return set()
        except OSError as exc:
            self._record_dns(host, "", "resolver-error", error=f"{type(exc).__name__}: {exc}")
            return set()

        addresses: set[str] = set()
        for result in answers:
            raw = str(result[4][0]).split("%", 1)[0].strip()
            try:
                address = str(ipaddress.ip_address(raw))
            except ValueError:
                continue
            family = "ipv6" if ":" in address else "ipv4"
            addresses.add(address)
            self._record_dns(host, address, "verified", family=family, relation="resolves_to")
        if not addresses and not any(
            row.get("source_host") == host and row.get("status") in {"resolver-error", "no-address"}
            for row in self._dns_attribution.values()
        ):
            self._record_dns(host, "", "no-address")
        return addresses

    def _derived_address_allowed(self, address: str) -> bool:
        try:
            canonical = str(ipaddress.ip_address(str(address).split("%", 1)[0].strip("[]")))
        except ValueError:
            return False
        return any(
            row.get("address") == canonical
            and row.get("status") == "verified"
            and row.get("source_within_target") is True
            for row in self._dns_attribution.values()
        )

    def discover(self) -> None:
        stage = "01-discovery"
        if self.target_kind == "range":
            return super().discover()
        candidates: set[str] = {self.host}
        sub_path = self.artifact(stage, "subfinder.subdomains")
        # Public-source discovery may observe more names, but only names inside
        # the automatic target boundary feed later stages.
        subfinder = base.executable("subfinder")
        if self.boundary_mode == "domain" and not base.is_ip_literal(self.host) and subfinder:
            command = [subfinder, "-d", self.host, "-silent", "-duc", "-t", str(self.tool_int("subfinder", "threads", 10)), "-o", str(sub_path)]
            sources = str(self.tool_value("subfinder", "sources", ""))
            if sources:
                command.extend(["-s", sources])
            if self.tool_bool("subfinder", "recursive", False):
                command.append("-recursive")
            self.execute(stage, command, "subfinder.subdomains", base.bounded_tool_timeout(self.timeout))
            if sub_path.is_file():
                for raw in sub_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    value = raw.strip().lower().rstrip(".")
                    if value and self._allowed_host(value):
                        candidates.add(value)
        else:
            base.write_lines(sub_path, set())
            self.event(stage, "skipped", reason="subdomain public-source expansion disabled for exact scope or unavailable")
        target_hosts = {host for host in candidates if self._allowed_host(host)}
        if self._allowed_host(self.host):
            target_hosts.add(self.host)
        base.write_lines(self.artifact(stage, "subdomains"), target_hosts)
        self.hosts = set(target_hosts)

        addresses: set[str] = set()
        for host in sorted(target_hosts):
            addresses.update(self._resolve_target_host(host))
        ips_path = self.artifact(stage, "getips.addresses")
        base.write_lines(ips_path, addresses)
        self.hosts.update(addresses)
        resolver_errors = sum(row.get("status") == "resolver-error" for row in self._dns_attribution.values())
        verified = sum(row.get("status") == "verified" for row in self._dns_attribution.values())
        status = "partial" if resolver_errors and verified else ("failed" if resolver_errors else "success")
        self.event(
            stage,
            status,
            reason="target-bound DNS address attribution",
            addresses=len(addresses),
            promoted_hosts=len(target_hosts),
            resolver_errors=resolver_errors,
        )

        gau_path = self.artifact(stage, "gau.urls")
        gau = base.executable("gau")
        if self.boundary_mode == "domain" and gau and not base.is_ip_literal(self.host):
            command = [gau, "--threads", str(self.tool_int("gau", "threads", 30)), "--timeout", str(self.tool_int("gau", "timeout", 10)), "--o", str(gau_path)]
            if self.tool_bool("gau", "subs", True):
                command.append("--subs")
            command.append(self.host)
            self.execute(stage, command, "gau.urls", base.bounded_tool_timeout(self.timeout))
            if gau_path.is_file():
                self.urls.update(value for value in base.URL_RE.findall(gau_path.read_text(encoding="utf-8", errors="replace")) if self._allowed_url(value))
        else:
            base.write_lines(gau_path, set())
            self.event(stage, "skipped", reason="historical URL expansion disabled for exact scope or unavailable")
        self.urls = {value for value in self.urls if self._allowed_url(value)}
        if not self.urls and self._allowed_url(self.base_url):
            self.urls.add(self.base_url)
        base.write_lines(self.artifact(stage, "historical.urls"), self.urls)
        base.write_lines(self.artifact(stage, "hosts"), self.hosts)

    def dns(self) -> None:
        super().dns()
        if self.target_kind == "range":
            return
        addresses_path = self.artifact("02-dns", "host-addresses")
        if addresses_path.is_file():
            allowed = {
                line.strip()
                for line in addresses_path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and (self._allowed_host(line.strip()) or self._derived_address_allowed(line.strip()))
            }
            base.write_lines(addresses_path, allowed)
            self.hosts = {
                host for host in self.hosts
                if self._allowed_host(host) or self._derived_address_allowed(host)
            } | allowed
        self._write_dns_attribution()

    def content(self) -> None:
        # The v2 outer runner owns canonical status gating and all-origin
        # directory/content work. Avoid pre-gate crawling that could follow an
        # observed-but-unapproved hostname.
        stage = "04-crawl"
        origins = self.artifact(stage, "origins")
        allowed_urls = {url for url in self.urls if self._allowed_url(url)}
        base.write_lines(origins, {f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/" for url in allowed_urls if urlsplit(url).scheme in {"http", "https"} and urlsplit(url).netloc})
        base.write_lines(self.artifact(stage, "crawl.urls"), allowed_urls)
        base.write_lines(self.artifact("05-content", "directories"), set())
        self.event(stage, "deferred", reason="architecture-v2 status gate owns crawl/content fan-out", origins=len(allowed_urls))

    def consumers(self) -> None:
        # A verified DNS-derived address may feed transport-level consumers.
        addresses = self.artifact("02-dns", "host-addresses")
        if addresses.is_file():
            allowed = {
                line.strip()
                for line in addresses.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and (self._allowed_host(line.strip()) or self._derived_address_allowed(line.strip()))
            }
            base.write_lines(addresses, allowed)
        super().consumers()


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGTERM, base.stop_active_process)
    signal.signal(signal.SIGINT, base.stop_active_process)
    parser = argparse.ArgumentParser(prog="recon_core_v2")
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
        tool_options = base.parse_tool_assignments(args.tool_option)
    except ValueError as exc:
        parser.error(str(exc))
    runner = ScopedCoreRun(
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
