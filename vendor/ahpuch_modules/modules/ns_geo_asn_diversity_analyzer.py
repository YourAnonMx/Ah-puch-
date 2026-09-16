import os
import sys
import dns.resolver
import requests
from collections import defaultdict
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
    Ah-Puch - NS Geo/ASN Diversity Analyzer
    =============================================
    """)
def get_ns(domain):
    if not str(domain or "").strip():
        return []
    try:
        ans=dns.resolver.resolve(domain,"NS",lifetime=DEFAULT_TIMEOUT)
        return [str(r.target).rstrip(".") for r in ans]
    except:
        return []
def a_records(host):
    ips=[]
    try:
        ans=dns.resolver.resolve(host,"A",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in ans])
    except:
        pass
    try:
        ans6=dns.resolver.resolve(host,"AAAA",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in ans6])
    except:
        pass
    return ips
def lookup_geo(ip):
    if not str(ip or "").strip():
        return "-","-","-"
    try:
        r=requests.get(f"https://ipwho.is/{ip}",timeout=DEFAULT_TIMEOUT)
        if r.status_code==200:
            j=r.json()
            cc=j.get("country_code","-")
            city=j.get("city","-")
            asn=j.get("asn") or "-"
            org=j.get("connection",{}).get("org","-")
            return cc,city,(f"AS{asn} {org}" if asn else org or "-")
    except:
        pass
    return "-","-","-"
def diversity_score(asns,countries):
    u_asn=len(asns)
    u_cc=len(countries)
    return str(u_asn*u_cc)
if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] no target provided. Please pass a domain or IP address.[/red]")
        sys.exit(1)
    domain=clean_domain_input(sys.argv[1])
    ns_hosts=get_ns(domain)
    if not ns_hosts:
        console.print("[yellow][!] No NS records found.[/yellow]")
        sys.exit(0)
    rows=[]
    asn_set=set()
    cc_set=set()
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),console=console,transient=True)
    with progress:
        t=progress.add_task("Resolving NS hosts",total=len(ns_hosts))
        for ns in ns_hosts:
            ips=a_records(ns)
            if not ips:
                rows.append((ns,"-","-","-","-"))
            else:
                for ip in ips:
                    cc,city,asn=lookup_geo(ip)
                    rows.append((ns,ip,cc,asn,city))
                    if asn!="-":
                        asn_set.add(asn)
                    if cc!="-":
                        cc_set.add(cc)
            progress.advance(t)
    table=Table(title=f"NS Geo/ASN Diversity: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("NS Host",style="cyan",overflow="fold")
    table.add_column("IP",style="green",overflow="fold")
    table.add_column("CC",style="yellow")
    table.add_column("ASN",style="white",overflow="fold")
    table.add_column("City",style="blue",overflow="fold")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    summary=Table(title="Diversity Summary",show_header=True,header_style="bold magenta")
    summary.add_column("Unique ASNs",style="cyan")
    summary.add_column("Unique Countries",style="green")
    summary.add_column("Diversity Score",style="yellow")
    summary.add_row(str(len(asn_set)),str(len(cc_set)),diversity_score(asn_set,cc_set))
    console.print(summary)
    console.print("[white][*] NS geo/ASN diversity analysis completed.[/white]")
