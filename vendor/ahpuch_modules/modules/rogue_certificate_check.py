from __future__ import annotations

import hashlib
import json
import socket
import ssl
import sys
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests
from colorama import init
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

try:
    from OpenSSL import crypto
except ImportError:
    crypto = None

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input

init(autoreset=True)
console = Console()
PARTIAL_EXIT_CODE = 3


def banner():
    console.print("""
    =============================================
       Ah-Puch - Rogue Certificate Check
    =============================================
    """)


def get_live_cert(domain: str, port: int = 443) -> dict:
    if not domain or not str(domain).strip():
        return {
            "domain": domain,
            "port": port,
            "state": "inapplicable",
            "error": "empty domain",
            "cn": "-",
            "sans": [],
            "issuer": "-",
            "not_before": "-",
            "not_after": "-",
            "sha256": "-",
            "sha1": "-",
            "pem": "",
        }
    try:
        pem = ssl.get_server_certificate((domain, port), timeout=DEFAULT_TIMEOUT)
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (OSError, socket.timeout, ssl.SSLError, TypeError, ValueError) as exc:
        return {
            "domain": domain,
            "port": port,
            "state": "transport-error",
            "error": f"{type(exc).__name__}: {exc}",
            "cn": "-",
            "sans": [],
            "issuer": "-",
            "not_before": "-",
            "not_after": "-",
            "sha256": "-",
            "sha1": "-",
            "pem": "",
        }

    cn = domain
    sans: list[str] = []
    issuer = "-"
    not_before = "-"
    not_after = "-"
    parse_error = ""
    if crypto:
        try:
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
            subject = x509.get_subject()
            cn = getattr(subject, "CN", "-") or "-"
            for index in range(x509.get_extension_count()):
                extension = x509.get_extension(index)
                if extension.get_short_name().decode().lower() == "subjectaltname":
                    for part in str(extension).split(","):
                        item = part.strip()
                        if item.lower().startswith("dns:"):
                            sans.append(item.split(":", 1)[1])
            issuer_parts = []
            cert_issuer = x509.get_issuer()
            for attr in ("CN", "O", "OU"):
                value = getattr(cert_issuer, attr, None)
                if value:
                    issuer_parts.append(value)
            issuer = ",".join(issuer_parts) or "-"
            if x509.get_notBefore():
                not_before = datetime.strptime(x509.get_notBefore().decode()[:14], "%Y%m%d%H%M%S").isoformat()
            if x509.get_notAfter():
                not_after = datetime.strptime(x509.get_notAfter().decode()[:14], "%Y%m%d%H%M%S").isoformat()
        except (ValueError, TypeError, AttributeError, crypto.Error) as exc:
            parse_error = f"{type(exc).__name__}: {exc}"

    return {
        "domain": domain,
        "port": port,
        "state": "partial" if parse_error else "success",
        "error": parse_error,
        "cn": cn,
        "sans": sorted(set(sans)),
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "pem": pem,
    }


def fetch_ct(domain: str) -> dict:
    if not domain or not str(domain).strip():
        return {"source": "crt.sh", "state": "inapplicable", "rows": []}
    query = urllib.parse.quote("%." + domain)
    url = f"https://crt.sh/?q={query}&output=json"
    try:
        response = requests.get(
            url,
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "AhPuchRogueCert/1.0"},
            verify=True,
            allow_redirects=False,
        )
    except (OSError, requests.RequestException, TypeError, ValueError) as exc:
        return {"source": "crt.sh", "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "rows": []}
    if response.status_code != 200:
        return {"source": "crt.sh", "state": "http-error", "status": int(response.status_code), "rows": []}
    try:
        try:
            data = response.json()
        except (ValueError, requests.JSONDecodeError):
            data = json.loads("[" + response.text.replace("}{", "},{") + "]")
        if not isinstance(data, list):
            raise ValueError("crt.sh payload is not a list")
        rows = []
        for record in data:
            if not isinstance(record, dict):
                continue
            rows.append({
                "name_value": str(record.get("name_value", "")),
                "common_name": str(record.get("common_name", "")),
                "issuer": str(record.get("issuer_name", "")),
                "not_before": str(record.get("not_before", "")),
                "not_after": str(record.get("not_after", "")),
            })
        return {"source": "crt.sh", "state": "success" if rows else "provider-negative", "rows": rows}
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return {"source": "crt.sh", "state": "parse-error", "error": f"{type(exc).__name__}: {exc}", "rows": []}


def classify_rogue(live_issuer: str, ct_issuer: str) -> str:
    if not ct_issuer or live_issuer == "-":
        return "Unknown"
    if live_issuer.lower() != ct_issuer.lower():
        return "Mismatch"
    return "Match"


def display(domain: str, live: dict, ct_rows: list[dict]) -> None:
    table1 = Table(title=f"Live Certificate: {domain}", show_header=True, header_style="bold magenta")
    table1.add_column("Field", style="cyan")
    table1.add_column("Value", style="green", overflow="fold")
    for label, key in (
        ("State", "state"), ("CN", "cn"), ("Issuer", "issuer"), ("Not Before", "not_before"),
        ("Not After", "not_after"), ("SHA256", "sha256"), ("SHA1", "sha1"),
    ):
        table1.add_row(label, str(live.get(key, "-")))
    table1.add_row("SANs", ",".join(live.get("sans", [])) if live.get("sans") else "-")
    console.print(table1)

    table2 = Table(title="CT Certificates", show_header=True, header_style="bold magenta")
    for name, style in (("DNS Name(s)", "cyan"), ("Common Name", "green"), ("Issuer", "yellow"), ("Not Before", "white"), ("Not After", "white"), ("Class", "blue")):
        table2.add_column(name, style=style, overflow="fold")
    for row in ct_rows:
        table2.add_row(
            row["name_value"].replace("\n", ","), row["common_name"], row["issuer"], row["not_before"], row["not_after"],
            classify_rogue(str(live.get("issuer", "-")), row["issuer"]),
        )
    if ct_rows:
        console.print(table2)
    else:
        console.print("[yellow][!] No CT entries retrieved.[/yellow]")


def main(domain: str) -> int:
    banner()
    console.print(f"[white][*] Checking live certificate for: {domain}[/white]")
    live = get_live_cert(domain)
    console.print("[white][*] Querying CT logs for historical certificates[/white]")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("crt.sh", total=1)
        ct = fetch_ct(domain)
        progress.advance(task)

    rows = list(ct.get("rows", []))
    display(domain, live, rows)
    error_states = {"transport-error", "http-error", "parse-error"}
    live_error = live.get("state") in error_states
    ct_error = ct.get("state") in error_states
    useful = live.get("state") in {"success", "partial"} or ct.get("state") in {"success", "provider-negative"}
    status = "failed" if (live_error and ct_error and not useful) else ("partial" if live_error or ct_error or live.get("state") == "partial" else "success")

    payload = {
        "target": domain,
        "status": status,
        "live": {key: value for key, value in live.items() if key != "pem"},
        "certificate_transparency": ct,
        "comparisons": [
            {**row, "classification": classify_rogue(str(live.get("issuer", "-")), row["issuer"])} for row in rows
        ],
    }
    Path("rogue_certificate_check.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    console.print(f"[white][*] Rogue certificate check completed with status={status}.[/white]")
    if status == "failed":
        return 2
    if status == "partial":
        return PARTIAL_EXIT_CODE
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        banner()
        console.print("[red][!] No domain provided.[/red]")
        raise SystemExit(1)
    domain = clean_domain_input(sys.argv[1])
    if not domain:
        raise SystemExit(2)
    raise SystemExit(main(domain))
