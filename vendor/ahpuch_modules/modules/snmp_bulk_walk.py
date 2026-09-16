# modules/snmp_bulk_walk.py
import os
import sys
import json
try:
    from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, nextCmd
    ASYNC_SNMP = False
except ImportError:
    from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, walk_cmd
    ASYNC_SNMP = True
from rich.console import Console
from rich.table import Table
from colorama import init

from ahpuch_modules.utils.util import resolve_to_ip
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()
MAX_TIMEOUT = 300

def banner():
    console.print("""
    =============================================
      Ah-Puch - SNMP Bulk Walk
    =============================================
    """)

def bulk_walk(ip, community, timeout=DEFAULT_TIMEOUT):
    if ASYNC_SNMP:
        return async_bulk_walk(ip, community, timeout)
    results = []
    for errInd, errStat, errIdx, varBinds in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6')),
        lexicographicMode=False
    ):
        if errInd or errStat:
            break
        for oid, val in varBinds:
            results.append((str(oid), str(val)))
    return results


def async_bulk_walk(ip, community, timeout=DEFAULT_TIMEOUT):
    import asyncio

    async def collect():
        results = []
        engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=0)
            async for errInd, errStat, errIdx, varBinds in walk_cmd(
                engine,
                CommunityData(community, mpModel=1),
                target,
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6")),
                lexicographicMode=False,
            ):
                if errInd or errStat:
                    break
                for oid, val in varBinds:
                    results.append((str(oid), str(val)))
            return results
        finally:
            engine.close_dispatcher()

    try:
        return asyncio.run(asyncio.wait_for(collect(), timeout=max(1, timeout) + 1))
    except (TimeoutError, OSError, ValueError):
        return []


def run(target, threads=1, opts=None):
    """Perform one bounded SNMP v2c walk using an explicitly supplied community."""
    options = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(options.get("timeout", DEFAULT_TIMEOUT)), MAX_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    cleaned_target = str(target or "").strip()
    if not cleaned_target:
        console.print("[red][!] No target provided. Please pass a domain or IP.[/red]")
        return 2
    ip = resolve_to_ip(cleaned_target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        return 2
    try:
        from ahpuch_modules.config.settings import SNMP_COMMUNITY
    except ImportError:
        SNMP_COMMUNITY = "public"
    community = options.get("community", SNMP_COMMUNITY) or SNMP_COMMUNITY
    console.print(f"[white][*] Using SNMP community: {community}[/white]")
    with console.status("[bold green]Performing SNMP bulk walk...[/bold green]", spinner="dots"):
        try:
            data = bulk_walk(ip, community, timeout)
        except (OSError, RuntimeError, ValueError) as exc:
            console.print(f"[yellow][!] SNMP helper unavailable: {type(exc).__name__}: {exc}[/yellow]")
            data = []
    if data:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("OID", style="cyan")
        table.add_column("Value", style="green")
        for oid, value in data:
            table.add_row(oid, value)
        console.print(table)
    else:
        console.print("[yellow][!] No SNMP data returned or access denied[/yellow]")
    console.print("[white][*] SNMP bulk walk completed.[/white]")
    return 0

if __name__ == "__main__":
    banner()
    try:
        options = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (ValueError, TypeError):
        options = {}
    raise SystemExit(run(sys.argv[1] if len(sys.argv) > 1 else "", 1, options))
