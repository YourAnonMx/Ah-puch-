import os
import sys
import json
import requests
import dns.resolver
from ipaddress import ip_address
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input
init(autoreset=True)
console = Console()
def banner():
    console.print("""
    =============================================
      Ah-Puch - RPKI Route Validity Check
    =============================================
    """)
def resolve_ips(domain):
    if not str(domain or "").strip():
        return []
    ips=[]
    try:
        ans=dns.resolver.resolve(domain,"A",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in ans])
    except:
        pass
    try:
        ans6=dns.resolver.resolve(domain,"AAAA",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in ans6])
    except:
        pass
    return list(dict.fromkeys(ips))
def ripe_prefix(ip):
    if not str(ip or "").strip():
        return "-","-"
    try:
        r=requests.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",timeout=DEFAULT_TIMEOUT)
        if r.status_code==200:
            j=r.json()
            d=j.get("data",{})
            p=d.get("prefix","-")
            asns=d.get("asns",[])
            asn="-"
            if asns:
                asn=asns[0].get("asn","-")
            return p,asn
    except:
        pass
    return "-","-"
def ripe_rpki(resource):
    if not str(resource or "").strip():
        return "-","-"
    try:
        r=requests.get(f"https://stat.ripe.net/data/rpki-validation/data.json?resource={resource}",timeout=DEFAULT_TIMEOUT)
        if r.status_code==200:
            j=r.json()
            d=j.get("data",{})
            vr=d.get("validity",{})
            status=vr.get("status","-")
            reason=vr.get("reason","-")
            return status,reason
    except:
        pass
    return "-","-"
if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] no target provided. Please pass a domain or IP address.[/red]")
        sys.exit(1)
    domain=clean_domain_input(sys.argv[1])
    ips=resolve_ips(domain)
    if not ips:
        console.print("[yellow][!] No IPs resolved for domain.[/yellow]")
        sys.exit(0)
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),console=console,transient=True)
    with progress:
        t=progress.add_task("Validating",total=len(ips))
        seen_prefix=set()
        for ip in ips:
            pref,asn=ripe_prefix(ip)
            if pref!="-":
                if pref not in seen_prefix:
                    status,reason=ripe_rpki(pref)
                    rows.append((ip,pref,str(asn),status,reason))
                    seen_prefix.add(pref)
                else:
                    rows.append((ip,pref,str(asn),"DupPrefix","-"))
            else:
                rows.append((ip,pref,str(asn),"-","-"))
            progress.advance(t)
    table=Table(title=f"RPKI Route Validity: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan")
    table.add_column("Prefix",style="green")
    table.add_column("ASN",style="yellow")
    table.add_column("RPKI",style="white")
    table.add_column("Reason",style="blue",overflow="fold")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] RPKI route validity check completed.[/white]")
