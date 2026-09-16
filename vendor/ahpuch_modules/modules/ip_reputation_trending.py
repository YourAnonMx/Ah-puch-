#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import sys
from pathlib import Path

import dns.exception
import dns.resolver
import requests
import urllib3
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ahpuch_modules.config.settings import API_KEYS, DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
TEAL = "#2EC4B6"
PARTIAL_EXIT_CODE = 3
DEFAULT_SHORT = 7
DEFAULT_LONG = 30
MAX_TARGET_IPS = 1024


def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]      Ah-Puch – IP Reputation Trending")
    console.print(f"[{TEAL}]{bar}")


def parse_opts(opts):
    opts = opts if isinstance(opts, dict) else {}
    short = max(1, min(int(opts.get("short_window", DEFAULT_SHORT)), 3650))
    long = max(1, min(int(opts.get("long_window", DEFAULT_LONG)), 3650))
    if short < 1 or long < 1:
        raise ValueError("reputation windows must be positive")
    return (short, long) if long >= short else (short, short)


def resolve_domain(domain: str) -> tuple[list[str], list[dict]]:
    if not domain or not str(domain).strip():
        return [], []
    ips: list[str] = []
    observations: list[dict] = []
    for rr in ("A", "AAAA"):
        try:
            answers = [row.address for row in dns.resolver.resolve(domain, rr, lifetime=DEFAULT_TIMEOUT)]
            observations.append({"source": f"dns:{rr}", "state": "success" if answers else "no-answer", "count": len(answers)})
            ips.extend(answers)
        except dns.resolver.NXDOMAIN:
            observations.append({"source": f"dns:{rr}", "state": "nxdomain"})
        except dns.resolver.NoAnswer:
            observations.append({"source": f"dns:{rr}", "state": "no-answer"})
        except (dns.exception.DNSException, OSError, TypeError, ValueError) as exc:
            observations.append({"source": f"dns:{rr}", "state": "resolver-error", "error": f"{type(exc).__name__}: {exc}"})
    return list(dict.fromkeys(ips)), observations


def expand(target: str) -> tuple[list[str], list[dict]]:
    if not target or not str(target).strip():
        raise ValueError("empty target")
    raw = target.strip()
    if not raw:
        raise ValueError("empty target")
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR target: {raw}") from exc
        hosts = [str(host) for host in network.hosts()]
        if len(hosts) > MAX_TARGET_IPS:
            raise ValueError(f"CIDR expands to more than {MAX_TARGET_IPS} hosts")
        return hosts, [{"source": "input", "state": "success", "kind": "cidr", "count": len(hosts)}]
    try:
        return [str(ipaddress.ip_address(raw.strip("[]")))], [{"source": "input", "state": "success", "kind": "ip", "count": 1}]
    except ValueError:
        domain = clean_domain_input(raw)
        if not domain:
            raise ValueError(f"invalid target: {raw}")
        ips, observations = resolve_domain(domain)
        return ips, observations


def abuse(ip: str, age: int) -> dict:
    if not ip or not str(ip).strip():
        return {"source": f"abuseipdb:{age}", "state": "inapplicable", "reason": "empty-ip", "score": "NA", "reports": "NA"}
    key = API_KEYS.get("ABUSEIPDB_API_KEY")
    if not key:
        return {"source": f"abuseipdb:{age}", "state": "skipped", "reason": "no-api-key", "score": "NA", "reports": "NA"}
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": age},
            headers={"Key": key, "Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT,
            verify=True,
            allow_redirects=False,
        )
    except (OSError, requests.RequestException, TypeError, ValueError) as exc:
        return {"source": f"abuseipdb:{age}", "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "score": "ERR", "reports": "ERR"}
    if response.status_code != 200:
        return {"source": f"abuseipdb:{age}", "state": "http-error", "status": int(response.status_code), "score": "ERR", "reports": "ERR"}
    try:
        data = response.json()["data"]
        return {"source": f"abuseipdb:{age}", "state": "success", "score": str(data["abuseConfidenceScore"]), "reports": str(data["totalReports"])}
    except (KeyError, TypeError, ValueError, requests.JSONDecodeError) as exc:
        return {"source": f"abuseipdb:{age}", "state": "parse-error", "error": f"{type(exc).__name__}: {exc}", "score": "ERR", "reports": "ERR"}


def vt(ip: str) -> dict:
    if not ip or not str(ip).strip():
        return {"source": "virustotal", "state": "inapplicable", "reason": "empty-ip", "malicious": "NA", "reputation": "NA"}
    key = API_KEYS.get("VIRUSTOTAL_API_KEY")
    if not key:
        return {"source": "virustotal", "state": "skipped", "reason": "no-api-key", "malicious": "NA", "reputation": "NA"}
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=DEFAULT_TIMEOUT,
            verify=True,
            allow_redirects=False,
        )
    except (OSError, requests.RequestException, TypeError, ValueError) as exc:
        return {"source": "virustotal", "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "malicious": "ERR", "reputation": "ERR"}
    if response.status_code != 200:
        return {"source": "virustotal", "state": "http-error", "status": int(response.status_code), "malicious": "ERR", "reputation": "ERR"}
    try:
        attributes = response.json()["data"]["attributes"]
        return {"source": "virustotal", "state": "success", "malicious": str(attributes["last_analysis_stats"]["malicious"]), "reputation": str(attributes["reputation"])}
    except (KeyError, TypeError, ValueError, requests.JSONDecodeError) as exc:
        return {"source": "virustotal", "state": "parse-error", "error": f"{type(exc).__name__}: {exc}", "malicious": "ERR", "reputation": "ERR"}


def run(target, threads, opts):
    banner()
    if not target or not str(target).strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    try:
        short, long = parse_opts(opts)
        ips, input_observations = expand(target)
    except (TypeError, ValueError) as exc:
        Path("ip_reputation_trending.json").write_text(json.dumps({"target": target, "status": "failed", "error": str(exc), "observations": [], "rows": []}, indent=2) + "\n", encoding="utf-8")
        console.print(f"[red]Invalid target/options: {exc}[/red]")
        return 2

    rows = []
    observations = list(input_observations)
    with Progress(SpinnerColumn(), TextColumn("Querying…"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("", total=len(ips))
        for ip in ips:
            short_row = abuse(ip, short)
            long_row = abuse(ip, long)
            vt_row = vt(ip)
            observations.extend([{**short_row, "ip": ip}, {**long_row, "ip": ip}, {**vt_row, "ip": ip}])
            short_score = str(short_row.get("score", "ERR"))
            long_score = str(long_row.get("score", "ERR"))
            delta = str(int(short_score) - int(long_score)) if short_score.isdigit() and long_score.isdigit() else "-"
            rows.append((
                ip,
                short_score,
                long_score,
                delta,
                str(short_row.get("reports", "ERR")),
                str(long_row.get("reports", "ERR")),
                str(vt_row.get("malicious", "ERR")),
                str(vt_row.get("reputation", "ERR")),
            ))
            progress.advance(task)

    table = Table(title="IP Reputation Trending", header_style="bold white")
    headers = ("IP", f"AbuseIPDB_{short}d", f"AbuseIPDB_{long}d", "Delta", "Reports_S", "Reports_L", "VT_Mal", "VT_Rep")
    for header in headers:
        table.add_column(header, style="cyan" if header == "IP" else "white")
    for row in rows:
        table.add_row(*row)
    console.print(table)

    error_states = {"resolver-error", "transport-error", "http-error", "parse-error"}
    completed_states = {"success", "nxdomain", "no-answer", "skipped"}
    errors = sum(row.get("state") in error_states for row in observations)
    completed = sum(row.get("state") in completed_states for row in observations)
    status = "failed" if errors and not completed else ("partial" if errors else "success")
    payload = {"target": target, "status": status, "ips": ips, "observations": observations, "rows": [dict(zip(headers, row)) for row in rows]}
    Path("ip_reputation_trending.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, "ip_reputation")
        ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        write_to_file(os.path.join(out, f"{clean_domain_input(target)}.txt"), export_console.export_text())

    if errors and not completed:
        return 2
    if errors:
        return PARTIAL_EXIT_CODE
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(2)
    target = sys.argv[1]
    threads = 1
    options = {}
    if len(sys.argv) > 2:
        try:
            options = json.loads(sys.argv[2])
        except (TypeError, ValueError):
            options = {}
    raise SystemExit(run(target, threads, options))
