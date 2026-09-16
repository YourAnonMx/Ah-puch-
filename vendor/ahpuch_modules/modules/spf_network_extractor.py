import os
import sys
import re
import ipaddress
import dns.resolver
import requests
from collections import deque
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input
init(autoreset=True)
console = Console()
spf_mech=re.compile(r"(include|ip4|ip6|a|mx|exists|ptr|redirect|exp)[:=]?([^ \\t]+)?",re.I)
def banner():
    console.print("""
    =============================================
        Ah-Puch - SPF Network Extractor
    =============================================
    """)
def dns_txt(name):
    if not str(name or "").strip():
        return []
    try:
        ans=dns.resolver.resolve(name,"TXT",lifetime=DEFAULT_TIMEOUT)
        out=[]
        for r in ans:
            if hasattr(r,"strings"):
                out.append("".join([s.decode() if isinstance(s,bytes) else s for s in r.strings]))
            else:
                out.append(r.to_text().strip('"'))
        return out
    except:
        return []
def dns_a(name):
    if not str(name or "").strip():
        return []
    try:
        ans=dns.resolver.resolve(name,"A",lifetime=DEFAULT_TIMEOUT)
        return [r.address for r in ans]
    except:
        return []
def dns_mx(name):
    if not str(name or "").strip():
        return []
    try:
        ans=dns.resolver.resolve(name,"MX",lifetime=DEFAULT_TIMEOUT)
        hosts=[str(r.exchange).rstrip(".") for r in ans]
        ips=[]
        for h in hosts:
            ips.extend(dns_a(h))
        return ips
    except:
        return []
def expand_spf(domain,max_depth=10):
    if not str(domain or "").strip():
        return []
    q=deque([(domain,0)])
    seen=set()
    results=[]
    while q:
        d,depth=q.popleft()
        if depth>max_depth or d in seen:
            continue
        seen.add(d)
        txts=dns_txt(d)
        rec=[t for t in txts if t.lower().startswith("v=spf1")]
        if not rec:
            continue
        record=" ".join(rec)
        for m in spf_mech.finditer(record):
            mech=m.group(1).lower()
            val=(m.group(2) or "").strip()
            if mech=="include" and val:
                results.append((d,mech,val,"-","-","-"))
                q.append((val,depth+1))
            elif mech=="redirect" and val:
                results.append((d,mech,val,"-","-","-"))
                q.append((val,depth+1))
            elif mech=="ip4" and val:
                results.append((d,mech,val,"IPv4","-","-"))
            elif mech=="ip6" and val:
                results.append((d,mech,val,"IPv6","-","-"))
            elif mech=="a":
                ips=dns_a(d if not val else val)
                for ip in ips:
                    results.append((d,"a",ip,"IPv4","-","-"))
            elif mech=="mx":
                ips=dns_mx(d if not val else val)
                for ip in ips:
                    results.append((d,"mx",ip,"IPv4","-","-"))
            elif mech=="exists":
                results.append((d,"exists",val,"-","-","-"))
            elif mech=="ptr":
                results.append((d,"ptr",val or d,"-","-","-"))
    return results
def lookup_asn_country(ip):
    if "/" in ip:
        try:
            net=ipaddress.ip_network(ip,strict=False)
            ip=str(next(net.hosts(),net.network_address))
        except:
            return "-","-"
    try:
        r=requests.get(f"https://ipwho.is/{ip}",timeout=DEFAULT_TIMEOUT)
        if r.status_code==200:
            j=r.json()
            asn=j.get("asn") or "-"
            org=j.get("connection",{}).get("org","-")
            cc=j.get("country_code","-")
            return (f"AS{asn} {org}" if asn else org or "-"),cc
    except:
        pass
    return "-","-"
if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] no target provided. Please pass a domain or IP address.[/red]")
        sys.exit(1)
    domain=clean_domain_input(sys.argv[1])
    rows=expand_spf(domain)
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),console=console,transient=True)
    with progress:
        t=progress.add_task("ASN lookups",total=len(rows))
        enriched=[]
        for src,mech,val,typ,asn,cc in rows:
            if typ in ("IPv4","IPv6"):
                asn,cc=lookup_asn_country(val)
            enriched.append((src,mech,val,typ,asn,cc))
            progress.advance(t)
    table=Table(title=f"SPF Network Extractor: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("Source",style="cyan")
    table.add_column("Mech",style="green")
    table.add_column("Value",style="yellow",overflow="fold")
    table.add_column("Type",style="white")
    table.add_column("ASN",style="blue",overflow="fold")
    table.add_column("CC",style="magenta")
    for r in enriched:
        table.add_row(*r)
    console.print(table if enriched else "[yellow][!] No SPF record discovered or no data extracted.[/yellow]")
    console.print("[white][*] SPF network extraction completed.[/white]")
