import os
import sys
import json
import requests
import dns.resolver
from datetime import datetime
from ipaddress import ip_address
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input
init(autoreset=True)
console = Console()
def banner():
    console.print("""
    =============================================
     Ah-Puch - IP Allocation History Tracker
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
        return "-","-","-"
    try:
        r=requests.get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",timeout=DEFAULT_TIMEOUT)
        if r.status_code==200:
            j=r.json()
            d=j.get("data",{})
            p=d.get("prefix","-")
            asns=d.get("asns",[])
            asn=asns[0].get("asn","-") if asns else "-"
            org=asns[0].get("holder","-") if asns else "-"
            return p,asn,org
    except:
        pass
    return "-","-","-"
def announced_history(asn):
    if not str(asn or "").strip() or str(asn).strip() == "-":
        return []
    try:
        r=requests.get(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}",timeout=DEFAULT_TIMEOUT)
        if r.status_code==200:
            j=r.json()
            d=j.get("data",{})
            px=d.get("prefixes",[])
            hist=[]
            for pr in px:
                pref=pr.get("prefix","-")
                first=pr.get("first_seen","-")
                last=pr.get("last_seen","-")
                hist.append((pref,first,last))
            return hist
    except:
        pass
    return []
def filter_cover(hist,ip):
    sel=[]
    for pref,first,last in hist:
        if pref=="-":
            continue
        if "/" not in pref:
            continue
        try:
            import ipaddress
            net=ipaddress.ip_network(pref,strict=False)
            if ip_address(ip) in net:
                sel.append((pref,first,last))
        except:
            continue
    return sel
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
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("History",total=len(ips))
        for ip in ips:
            pref,asn,org=ripe_prefix(ip)
            hist=announced_history(asn) if asn!="-" else []
            cov=filter_cover(hist,ip) if hist else []
            if cov:
                for pr,fs,ls in cov:
                    rows.append((ip,pr,str(asn),org,fs,ls))
            else:
                rows.append((ip,pref,str(asn),org,"-","-"))
            progress.advance(task)
    table=Table(title=f"IP Allocation History: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan")
    table.add_column("Prefix",style="green")
    table.add_column("ASN",style="yellow")
    table.add_column("Org",style="white",overflow="fold")
    table.add_column("FirstSeen",style="blue")
    table.add_column("LastSeen",style="magenta")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] IP allocation history tracking completed.[/white]")
