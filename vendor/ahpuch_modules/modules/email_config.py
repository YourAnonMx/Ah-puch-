#!/usr/bin/env python3
import os
import sys
import json
import time
import socket
import ssl
import dns.resolver
import dns.exception
import requests
import urllib3
import base64

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()
MAX_TIMEOUT = 300
MAX_WORKERS = 32
resolver = dns.resolver.Resolver(configure=True)

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "k1"]

def banner():
    bar = "=" * 44
    console.print(f"[cyan]{bar}")
    console.print("[cyan]        Ah-Puch – Email Configuration Analysis")
    console.print(f"[cyan]{bar}\n")

def timed_resolve(name, rdtype, timeout):
    start = time.time()
    try:
        answers = resolver.resolve(name, rdtype, lifetime=timeout)
        elapsed = (time.time() - start) * 1000
        return [(r.to_text(), answers.rrset.ttl) for r in answers], elapsed
    except dns.exception.DNSException:
        return [], (time.time() - start) * 1000

def parse_spf(record):
    if not record or record.strip() == "-":
        return [], 0
    parts = record.split()
    mechs = [p for p in parts if p and p != "v=spf1"]
    includes = [p for p in mechs if p.startswith("include:")]
    return mechs, len(includes)

def parse_dmarc(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            tags[k.lower()] = v
    return tags

def scan_mta_sts(domain, timeout):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        r = requests.get(url, timeout=timeout, verify=True)
        lines = [l.strip() for l in r.text.splitlines() if l and not l.startswith("#")]
        return {l.split("=", 1)[0]: l.split("=", 1)[1] for l in lines}
    except:
        return {}

def check_bimi(domain, timeout):
    name = f"default._bimi.{domain}"
    recs, _ = timed_resolve(name, "TXT", timeout)
    url = "-"
    ok = False
    if recs:
        val = recs[0][0]
        for part in val.split(";"):
            p = part.strip()
            if p.lower().startswith("l="):
                url = p.split("=", 1)[1]
                try:
                    resp = requests.head(url, timeout=timeout, verify=True)
                    ok = resp.ok
                except:
                    ok = False
    return url, ok

def run(target, threads, opts):
    banner()
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    dom = clean_domain_input(str(target or "").split("@")[-1])
    if not dom:
        console.print("[red]✖ No domain provided.[/red]")
        return 2
    selectors = [value.strip() for value in str(options.get("selectors", ",".join(COMMON_DKIM_SELECTORS))).split(",") if value.strip()]
    console.print(f"[*] Inspecting mail DNS records for [cyan]{dom}[/cyan]\n")

    results = {}

    with Progress(SpinnerColumn(), TextColumn("SPF lookup…"), console=console, transient=True) as p:
        task = p.add_task("", total=1)
        recs, spf_time = timed_resolve(dom, "TXT", timeout)
        spf_txt = next((r for r, ttl in recs if r.lower().startswith("v=spf1")), "-")
        mechs, inc_count = parse_spf(spf_txt) if spf_txt != "-" else ([], 0)
        results["SPF"] = {
            "record": spf_txt,
            "mechanisms": mechs,
            "includes": inc_count,
            "time_ms": round(spf_time, 1),
            "ttl": recs[0][1] if recs else "-"
        }
        p.advance(task)

    with Progress(SpinnerColumn(), TextColumn("DMARC lookup…"), console=console, transient=True) as p:
        task = p.add_task("", total=1)
        recs, dmarc_time = timed_resolve(f"_dmarc.{dom}", "TXT", timeout)
        dm_txt = recs[0][0] if recs else "-"
        dm_tags = parse_dmarc(dm_txt) if dm_txt != "-" else {}
        results["DMARC"] = {
            "record": dm_txt,
            "tags": dm_tags,
            "time_ms": round(dmarc_time, 1),
            "ttl": recs[0][1] if recs else "-"
        }
        p.advance(task)

    dkim_out = []
    with Progress(SpinnerColumn(), TextColumn("DKIM selectors…"), BarColumn(), console=console, transient=True) as p:
        task = p.add_task("", total=len(selectors))
        def lookup_dkim(sel):
            name = f"{sel}._domainkey.{dom}"
            recs, dt = timed_resolve(name, "TXT", timeout)
            result = None
            if recs:
                txt = recs[0][0]
                p_val = next((x.split("=", 1)[1] for x in txt.split(";") if x.strip().startswith("p=")), "")
                bits = "-"
                if p_val:
                    try:
                        key = base64.b64decode(p_val)
                        bits = len(key) * 8
                    except:
                        bits = "-"
                result = {
                    "selector": sel,
                    "key_bits": bits,
                    "ttl": recs[0][1],
                    "time_ms": round(dt, 1)
                }
            return result
        try:
            workers = max(1, min(int(options.get("threads", threads)), len(selectors) or 1, MAX_WORKERS))
        except (AttributeError, TypeError, ValueError):
            workers = max(1, min(int(threads or 1), len(selectors) or 1, MAX_WORKERS))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(lookup_dkim, selector) for selector in selectors]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    dkim_out.append(result)
                p.advance(task)
        dkim_out.sort(key=lambda item: item["selector"])
    results["DKIM"] = dkim_out

    with Progress(SpinnerColumn(), TextColumn("MTA‑STS policy…"), console=console, transient=True) as p:
        task = p.add_task("", total=1)
        results["MTA-STS"] = scan_mta_sts(dom, timeout) or {}
        p.advance(task)

    with Progress(SpinnerColumn(), TextColumn("BIMI lookup…"), console=console, transient=True) as p:
        task = p.add_task("", total=1)
        b_url, b_ok = check_bimi(dom, timeout)
        results["BIMI"] = {"url": b_url, "reachable": b_ok}
        p.advance(task)

    spf = results["SPF"]
    tbl_spf = Table(title="SPF", box=box.MINIMAL)
    tbl_spf.add_column("Record", overflow="fold")
    tbl_spf.add_column("Mechanisms")
    tbl_spf.add_column("Includes")
    tbl_spf.add_column("TTL")
    tbl_spf.add_column("Time(ms)")
    tbl_spf.add_row(
        spf["record"],
        ", ".join(spf["mechanisms"]) or "-",
        str(spf["includes"]),
        str(spf["ttl"]),
        str(spf["time_ms"])
    )
    console.print(tbl_spf)

    dmarc = results["DMARC"]
    tbl_dmarc = Table(title="DMARC", box=box.MINIMAL)
    tbl_dmarc.add_column("Tag")
    tbl_dmarc.add_column("Value", overflow="fold")
    tbl_dmarc.add_column("TTL")
    tbl_dmarc.add_column("Time(ms)")
    if dmarc["tags"]:
        for k, v in dmarc["tags"].items():
            tbl_dmarc.add_row(k, str(v), str(dmarc["ttl"]), str(dmarc["time_ms"]))
    else:
        tbl_dmarc.add_row("-", "-", "-", "-")
    console.print(tbl_dmarc)

    tbl_dkim = Table(title="DKIM", box=box.MINIMAL)
    tbl_dkim.add_column("Selector")
    tbl_dkim.add_column("KeyBits")
    tbl_dkim.add_column("TTL")
    tbl_dkim.add_column("Time(ms)")
    for d in results["DKIM"]:
        tbl_dkim.add_row(
            d["selector"],
            str(d["key_bits"]),
            str(d["ttl"]),
            str(d["time_ms"])
        )
    console.print(tbl_dkim)

    tbl_mta = Table(title="MTA‑STS", box=box.MINIMAL)
    if results["MTA-STS"]:
        for k, v in results["MTA-STS"].items():
            tbl_mta.add_row(k, v)
    else:
        tbl_mta.add_row("-", "-")
    console.print(tbl_mta)

    b = results["BIMI"]
    tbl_bimi = Table(title="BIMI", box=box.MINIMAL)
    tbl_bimi.add_column("URL", overflow="fold")
    tbl_bimi.add_column("Reachable")
    tbl_bimi.add_row(b["url"], "Y" if b["reachable"] else "N")
    console.print(tbl_bimi)

    summary = (
        f"SPF mech:{len(spf['mechanisms'])}  DKIM:{len(results['DKIM'])}  "
        f"MTA‑STS:{'Yes' if results['MTA-STS'] else 'No'}  BIMI:{'Yes' if b['reachable'] else 'No'}"
    )
    console.print(Panel(summary, title="Summary", style="bold white"))
    console.print("[green][*] Email configuration analysis completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        report = {
            "domain": dom,
            "spf": spf,
            "dmarc": dmarc["tags"],
            "dkim": results["DKIM"],
            "mta_sts": results["MTA-STS"],
            "bimi": results["BIMI"],
            "summary": summary
        }
        write_to_file(os.path.join(out, "email_config.json"), json.dumps(report, indent=2))
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]✖ No target provided.[/red]")
        sys.exit(1)
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    raise SystemExit(run(tgt, thr, opts))
