#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import requests
from rich.console import Console
from rich.table import Table

from ahpuch_modules.config.settings import API_KEYS, DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR
from ahpuch_modules.utils.util import clean_domain_input

console = Console()

PARTIAL_EXIT_CODE = 3
RBL_DOMS = ("dbl.spamhaus.org", "multi.uribl.com", "black.uribl.com", "rhsbl.scientificspam.net")
IP_RBLS = ("zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org")
COMPLETED_REPUTATION_STATES = {"success", "not-listed", "provider-negative"}
_ERROR_STATES = {
    "timeout",
    "resolver-error",
    "transport-error",
    "http-error",
    "parse-error",
    "internal-error",
    "tls-error",
    "tls-verification-error",
    "error",
}


def _resolver(timeout: int) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = min(float(timeout), 5.0)
    return resolver


def _is_error_state(value: object) -> bool:
    state = str(value or "").strip().lower()
    return bool(state in _ERROR_STATES or state.endswith("-error"))


def _has_partial_failure(
    ip_result: dict[str, Any],
    vt: dict[str, Any],
    rbl_rows: list[dict[str, Any]],
    talos: dict[str, Any],
    urlhaus: dict[str, Any],
    otx: dict[str, Any],
) -> bool:
    rows: list[dict[str, Any]] = [ip_result, vt, talos, urlhaus, otx, *rbl_rows]
    return any(_is_error_state(row.get("state")) for row in rows if isinstance(row, dict))


def resolve_ip(domain: str, timeout: int) -> dict[str, Any]:
    try:
        answers = _resolver(timeout).resolve(domain, "A")
        addresses = sorted({str(ipaddress.ip_address(str(answer).strip())) for answer in answers})
        return {"state": "success", "ip": addresses[0] if addresses else "", "error": ""}
    except dns.resolver.NXDOMAIN:
        return {"state": "nxdomain", "ip": "", "error": ""}
    except dns.resolver.NoAnswer:
        return {"state": "no-answer", "ip": "", "error": ""}
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
        return {"state": "timeout", "ip": "", "error": type(exc).__name__}
    except dns.resolver.NoNameservers as exc:
        return {"state": "resolver-error", "ip": "", "error": type(exc).__name__}
    except (dns.exception.DNSException, ValueError, TypeError) as exc:
        return {"state": "resolver-error", "ip": "", "error": type(exc).__name__}


def rbl_lookup(query_name: str, zone: str, timeout: int) -> dict[str, Any]:
    try:
        answers = _resolver(timeout).resolve(f"{query_name}.{zone}", "A")
        values = sorted({str(answer).strip() for answer in answers})
        return {"provider": zone, "state": "success", "listed": True, "answers": values, "error": ""}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"provider": zone, "state": "not-listed", "listed": False, "answers": [], "error": ""}
    except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
        return {"provider": zone, "state": "timeout", "listed": False, "answers": [], "error": type(exc).__name__}
    except dns.resolver.NoNameservers as exc:
        return {"provider": zone, "state": "resolver-error", "listed": False, "answers": [], "error": type(exc).__name__}
    except (dns.exception.DNSException, ValueError, TypeError) as exc:
        return {"provider": zone, "state": "resolver-error", "listed": False, "answers": [], "error": type(exc).__name__}


def vt_lookup(domain: str, key: str, timeout: int) -> dict[str, Any]:
    if not key:
        return {"state": "skipped:no-api-key", "score": "-", "malicious": None, "total": None, "error": ""}
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": key},
            timeout=timeout,
            verify=True,
        )
    except requests.RequestException as exc:
        return {"state": "transport-error", "score": "-", "malicious": None, "total": None, "error": type(exc).__name__}
    if response.status_code != 200:
        return {"state": "http-error", "score": "-", "malicious": None, "total": None, "error": str(response.status_code)}
    try:
        payload = response.json()
        stats = payload["data"]["attributes"]["last_analysis_stats"]
        if not isinstance(stats, dict):
            raise ValueError("analysis stats must be an object")
        malicious = int(stats.get("malicious", 0))
        total = sum(int(value) for value in stats.values())
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return {"state": "parse-error", "score": "-", "malicious": None, "total": None, "error": type(exc).__name__}
    return {"state": "success", "score": f"{malicious}/{total}", "malicious": malicious, "total": total, "error": ""}


def talos_lookup(domain: str, timeout: int) -> dict[str, Any]:
    try:
        response = requests.get(
            f"https://talosintelligence.com/sb_api/query_lookup?query={domain}&query_type=domain",
            timeout=timeout,
            headers={"User-Agent": "Ah-Puch"},
            verify=True,
        )
    except requests.RequestException as exc:
        return {"state": "transport-error", "category": "", "error": type(exc).__name__}
    if response.status_code != 200:
        return {"state": "http-error", "category": "", "error": str(response.status_code)}
    try:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Talos response is not an object")
        category = str(payload.get("category") or "unknown")
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"state": "parse-error", "category": "", "error": type(exc).__name__}
    return {"state": "success", "category": category, "error": ""}


def urlhaus_lookup(domain: str, timeout: int) -> dict[str, Any]:
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=timeout,
            verify=True,
        )
    except requests.RequestException as exc:
        return {"state": "transport-error", "listed": False, "count": 0, "error": type(exc).__name__}
    if response.status_code != 200:
        return {"state": "http-error", "listed": False, "count": 0, "error": str(response.status_code)}
    try:
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("URLHaus response is not an object")
        query_status = str(payload.get("query_status", ""))
        if query_status == "no_results":
            return {"state": "not-listed", "listed": False, "count": 0, "error": ""}
        if query_status != "ok":
            return {"state": "provider-negative", "listed": False, "count": 0, "error": query_status}
        count = int(payload.get("urls_count") or 0)
        listed = str(payload.get("host", "")).lower().rstrip(".") == domain.lower().rstrip(".") and count > 0
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {"state": "parse-error", "listed": False, "count": 0, "error": type(exc).__name__}
    return {"state": "success", "listed": bool(listed), "count": count, "error": ""}


def otx_lookup(domain: str, key: str, timeout: int) -> dict[str, Any]:
    if not key:
        return {"state": "skipped:no-api-key", "pulses": None, "error": ""}
    try:
        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": key},
            timeout=timeout,
            verify=True,
        )
    except requests.RequestException as exc:
        return {"state": "transport-error", "pulses": None, "error": type(exc).__name__}
    if response.status_code != 200:
        return {"state": "http-error", "pulses": None, "error": str(response.status_code)}
    try:
        payload = response.json()
        pulses = int(payload.get("pulse_info", {}).get("count", 0)) if isinstance(payload, dict) else 0
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {"state": "parse-error", "pulses": None, "error": type(exc).__name__}
    return {"state": "success", "pulses": pulses, "error": ""}


def verdict(vt: dict[str, Any], rbl_rows: list[dict[str, Any]], talos: dict[str, Any], urlhaus: dict[str, Any], otx: dict[str, Any]) -> str:
    completed = 0
    score = 0

    if vt.get("state") == "success" and vt.get("malicious") is not None and vt.get("total"):
        completed += 1
        malicious = int(vt["malicious"])
        total = max(int(vt["total"]), 1)
        percentage = (malicious / total) * 100
        if malicious >= 5 or percentage >= 10:
            score += 2
        elif malicious >= 1:
            score += 1

    completed_rbl = [row for row in rbl_rows if row.get("state") in COMPLETED_REPUTATION_STATES]
    if completed_rbl:
        completed += 1
        hits = sum(bool(row.get("listed")) for row in completed_rbl)
        score += 2 if hits >= 3 else (1 if hits >= 1 else 0)

    if talos.get("state") == "success":
        completed += 1
        category = str(talos.get("category", "")).lower()
        if any(word in category for word in ("malicious", "phishing", "spam", "suspicious", "untrusted")):
            score += 2

    if urlhaus.get("state") in COMPLETED_REPUTATION_STATES:
        completed += 1
        if urlhaus.get("listed"):
            score += 2

    if otx.get("state") == "success" and isinstance(otx.get("pulses"), int):
        completed += 1
        if int(otx["pulses"]) >= 3:
            score += 1

    if not completed:
        return "Indeterminate"
    if score >= 4:
        return "High risk"
    if score >= 2:
        return "Medium risk"
    return "Low risk"


def _style_verdict(value: str) -> str:
    return {
        "High risk": "[bold red]High risk[/]",
        "Medium risk": "[yellow]Medium risk[/]",
        "Low risk": "[bold green]Low risk[/]",
        "Indeterminate": "[bold red]Indeterminate[/]",
    }.get(value, value)


def _export(domain: str, payload: dict[str, Any], table: Table) -> None:
    destination = Path(RESULTS_DIR) / domain
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        destination.chmod(0o700)
    except OSError:
        pass
    json_path = destination / "domain_reputation.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    try:
        json_path.chmod(0o600)
    except OSError:
        pass
    if EXPORT_SETTINGS.get("enable_txt_export"):
        export_console = Console(record=True, width=console.width)
        export_console.print(table)
        text_path = destination / "domain_reputation.txt"
        text_path.write_text(export_console.export_text(), encoding="utf-8")
        try:
            text_path.chmod(0o600)
        except OSError:
            pass


def run(target: str, threads: int, opts: dict[str, Any]) -> int:
    domain = clean_domain_input(target).strip().lower().rstrip(".")
    if not domain:
        console.print("[red]A domain target is required[/red]")
        return 2
    try:
        timeout = max(1, int(opts.get("timeout", DEFAULT_TIMEOUT)))
        workers = max(1, min(int(threads or 1), 32))
    except (TypeError, ValueError) as exc:
        console.print(f"[red]Invalid module options: {exc}[/red]")
        return 2

    ip_result = resolve_ip(domain, timeout)
    ip = str(ip_result.get("ip", ""))
    vt_key = str(opts.get("vt_key") or API_KEYS.get("VIRUSTOTAL_API_KEY", ""))
    otx_key = str(opts.get("otx_key") or API_KEYS.get("OTX_API_KEY", ""))

    vt = vt_lookup(domain, vt_key, timeout)
    talos = talos_lookup(domain, timeout)
    urlhaus = urlhaus_lookup(domain, timeout)
    otx = otx_lookup(domain, otx_key, timeout)

    jobs: list[tuple[str, str]] = [(domain, zone) for zone in RBL_DOMS]
    if ip:
        try:
            address = ipaddress.ip_address(ip)
            if address.version == 4:
                reversed_ip = ".".join(reversed(str(address).split(".")))
                jobs.extend((reversed_ip, zone) for zone in IP_RBLS)
        except ValueError:
            pass

    rbl_rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(jobs)))) as executor:
        futures = {executor.submit(rbl_lookup, query_name, zone, timeout): zone for query_name, zone in jobs}
        for future in as_completed(futures):
            zone = futures[future]
            try:
                row = future.result()
            except Exception as exc:  # isolate one RBL worker without hiding its terminal state
                row = {"provider": zone, "state": "internal-error", "listed": False, "answers": [], "error": type(exc).__name__}
            rbl_rows.append(row)
    rbl_rows.sort(key=lambda row: str(row["provider"]))

    reputation = verdict(vt, rbl_rows, talos, urlhaus, otx)
    rbl_hits = [str(row["provider"]) for row in rbl_rows if row.get("listed")]

    table = Table(title=f"Reputation for {domain}", header_style="bold white")
    table.add_column("Engine")
    table.add_column("State")
    table.add_column("Result", overflow="fold")
    table.add_row("IP", str(ip_result.get("state", "unknown")), ip or "-")
    table.add_row("Verdict", "completed" if reputation != "Indeterminate" else "indeterminate", _style_verdict(reputation))
    table.add_row("VirusTotal", str(vt["state"]), str(vt.get("score", "-")))
    table.add_row("Cisco Talos", str(talos["state"]), str(talos.get("category") or "-"))
    table.add_row("RBL", f"{sum(row['state'] in COMPLETED_REPUTATION_STATES for row in rbl_rows)}/{len(rbl_rows)} completed", str(len(rbl_hits)))
    if rbl_hits:
        table.add_row("RBL Lists", "listed", ", ".join(rbl_hits))
    table.add_row("URLHaus", str(urlhaus["state"]), str(urlhaus.get("count", 0)))
    table.add_row("OTX Pulses", str(otx["state"]), str(otx.get("pulses") if otx.get("pulses") is not None else "-"))
    console.print(table)

    payload = {
        "domain": domain,
        "ip": ip_result,
        "verdict": reputation,
        "virustotal": vt,
        "talos": talos,
        "rbl": {"rows": rbl_rows, "hits": rbl_hits},
        "urlhaus": urlhaus,
        "otx": otx,
        "timestamp": int(time.time()),
    }
    _export(domain, payload, table)

    if reputation == "Indeterminate":
        console.print("[red]Reputation is indeterminate because no reputation source completed[/red]\n")
        return 2
    if _has_partial_failure(ip_result, vt, rbl_rows, talos, urlhaus, otx):
        console.print("[yellow][*] Reputation check completed with partial provider failures[/yellow]\n")
        return PARTIAL_EXIT_CODE
    console.print("[green][*] Reputation check completed[/green]\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        raise SystemExit(2)
    target = sys.argv[1]
    threads = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 4
    try:
        parsed = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except json.JSONDecodeError as exc:
        console.print(f"[red]Invalid options JSON: {exc}[/red]")
        raise SystemExit(2)
    if not isinstance(parsed, dict):
        console.print("[red]Options JSON must be an object[/red]")
        raise SystemExit(2)
    raise SystemExit(run(target, threads, parsed))
