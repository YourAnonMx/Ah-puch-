#!/usr/bin/env python3
import os
import re
import sys
import json
import base64
import argparse
import requests
from datetime import datetime, timezone
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init

init(autoreset=True)
console = Console()
try:
    import jwt
    from jwt import algorithms
except ImportError:
    jwt = None

DEFAULT_TIMEOUT = 10

def b64url_decode(data: str) -> bytes:
    if not isinstance(data, (str, bytes)):
        return b""
    b = data.encode() if isinstance(data, str) else data
    rem = len(b) % 4
    if rem:
        b += b'=' * (4 - rem)
    try:
        return base64.urlsafe_b64decode(b)
    except (TypeError, ValueError):
        return b""

def decode_parts(token: str):
    if not isinstance(token, str):
        return {}, {}, ""
    parts = token.split(".")
    if len(parts) < 2:
        return {}, {}, ""
    hdr, pl = b64url_decode(parts[0]), b64url_decode(parts[1])
    sig = parts[2] if len(parts) > 2 else ""
    try:
        hdrj = json.loads(hdr.decode())
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        hdrj = {}
    try:
        plj = json.loads(pl.decode())
    except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        plj = {}
    return hdrj, plj, sig

def fetch_jwks(url: str, timeout: int) -> dict:
    if not isinstance(url, str) or not url.strip():
        return {}
    try:
        r = requests.get(url, timeout=timeout, verify=True, allow_redirects=False)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, dict) else {}
    except (AttributeError, OSError, requests.RequestException, TypeError, ValueError):
        return {}

def guess_jwks_urls(domain: str, iss: str, hdr: dict):
    urls = []
    if iss and iss.startswith("http"):
        urls += [urljoin(iss, p) for p in (".well-known/jwks.json", "jwks.json")]
    base = f"https://{domain}"
    urls += [f"{base}/.well-known/jwks.json", f"{base}/jwks.json"]
    seen = []
    for u in urls:
        if u not in seen:
            seen.append(u)
    return seen, hdr.get("kid")

def try_verify(token: str, jwks: dict, kid: str):
    if not jwt or not jwks.get("keys"):
        return "Unavailable", "-"
    keydata = None
    for k in jwks["keys"]:
        if kid and k.get("kid") == kid:
            keydata = k
            break
    if not keydata:
        keydata = jwks["keys"][0]
    try:
        public = algorithms.RSAAlgorithm.from_jwk(json.dumps(keydata))
    except (AttributeError, KeyError, TypeError, ValueError):
        try:
            public = algorithms.ECAlgorithm.from_jwk(json.dumps(keydata))
        except (AttributeError, KeyError, TypeError, ValueError):
            return "BadKey", "-"
    try:
        payload = jwt.decode(token, public, algorithms=[ keydata.get("alg", "RS256") ], options={"verify_aud": False})
        return "Valid", json.dumps(payload)
    except (AttributeError, KeyError, TypeError, ValueError) as e:
        return "Invalid", str(e)

def risk_score(hdr: dict, pl: dict, sig: str, ver_stat: str):
    alg = hdr.get("alg", "").lower()
    risks = []
    if alg in ("none", ""):
        risks.append("ALG_none")
    if "exp" not in pl:
        risks.append("NoExp")
    else:
        try:
            if int(pl["exp"]) < int(datetime.now(timezone.utc).timestamp()):
                risks.append("Expired")
        except (TypeError, ValueError, OverflowError):
            risks.append("BadExp")
    if not sig:
        risks.append("NoSignature")
    if ver_stat not in ("Valid", "Unavailable"):
        risks.append("SignatureFail")
    if not risks:
        return "Low"
    if "ALG_none" in risks or "SignatureFail" in risks:
        return "High"
    if "Expired" in risks or "NoExp" in risks or "BadExp" in risks:
        return "Medium"
    return "Low"

def display(hdr, pl, sig, ver_stat, ver_det, risks):
    t1 = Table(title="JWT Header", header_style="bold magenta")
    t1.add_column("Key", style="cyan")
    t1.add_column("Value", style="green", overflow="fold")
    for k, v in hdr.items():
        t1.add_row(str(k), str(v))
    console.print(t1)

    t2 = Table(title="JWT Claims", header_style="bold magenta")
    t2.add_column("Claim", style="cyan")
    t2.add_column("Value", style="green", overflow="fold")
    for k, v in pl.items():
        t2.add_row(str(k), str(v))
    console.print(t2)

    t3 = Table(title="Analysis", header_style="bold magenta")
    t3.add_column("Field", style="cyan")
    t3.add_column("Value", style="green", overflow="fold")
    t3.add_row("Signature Present", "Yes" if sig else "No")
    t3.add_row("Verify Status", ver_stat)
    t3.add_row("Verify Detail", ver_det if isinstance(ver_det, str) else "-")
    t3.add_row("Risk Level", risks)
    console.print(t3)

def main():
    parser = argparse.ArgumentParser(description="Ah-Puch – JWT Token Analyzer")
    parser.add_argument("input", help="JWT token (three‑part) or domain to auto‑discover one")
    parser.add_argument("-k", "--jwks", help="Explicit JWKS URL")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout seconds")
    args = parser.parse_args()

    inp = args.input.strip()
    token = None
    domain = None

    if inp.count(".") >= 2 and " " not in inp and not inp.startswith("http"):
        token = inp
    else:
        domain = inp
        console.print(f"[white][*] No token given, trying to discover on {domain}[/white]")
        try:
            r = requests.get(f"https://{domain}", timeout=args.timeout, verify=True, allow_redirects=False)
            m = re.search(r"(eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+)", r.text)
            if m:
                token = m.group(1)
        except (OSError, requests.RequestException, TypeError, ValueError):
            pass
        if not token:
            console.print("[yellow][!] No JWT found – please pass it explicitly with the token syntax.[/yellow]")
            sys.exit(0)

    hdr, pl, sig = decode_parts(token)
    iss = pl.get("iss", "")
    urls, kid = ([], None)
    if args.jwks:
        urls, kid = [args.jwks], hdr.get("kid")
    else:
        urls, kid = guess_jwks_urls(domain or "", iss, hdr)

    jwks = {}
    ver_stat, ver_det = "Unavailable", "-"
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as prog:
        task = prog.add_task("Fetching JWKS…", total=len(urls))
        for u in urls:
            jwks = fetch_jwks(u, args.timeout)
            prog.update(task, advance=1)
            if jwks:
                break

    ver_stat, ver_det = try_verify(token, jwks, kid)
    risks = risk_score(hdr, pl, sig, ver_stat)

    display(hdr, pl, sig, ver_stat, ver_det, risks)
    console.print("[green][*] JWT token analysis completed[/green]")

if __name__ == "__main__":
    main()
