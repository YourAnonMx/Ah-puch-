import os
import sys
import dns.resolver
import dns.exception
from rich.console import Console
from rich.table import Table
from colorama import init
from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
init(autoreset=True)
console = Console()
selectors_default=["default","selector1","selector2","google","google._domainkey","mail","smtp","k1","dkim","api","amazonses","mandrill","sendgrid","mailgun"]
def banner():
    console.print("""
    =============================================
    Ah-Puch - SPF / DKIM / DMARC Validator
    =============================================
    """)
def get_txt(name):
    if not name or not str(name).strip():
        return []
    try:
        ans=dns.resolver.resolve(name,"TXT",lifetime=DEFAULT_TIMEOUT)
        return ["".join(r.strings if hasattr(r,"strings") else r.to_text().strip('"').split('"')) for r in ans]
    except (dns.exception.DNSException, OSError, TypeError, ValueError):
        return []
def parse_spf(txts):
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return t
    return "-"
def parse_dmarc(txts):
    rec="-"
    policy="-"
    rua="-"
    ruf="-"
    pct="-"
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            rec=t
            parts=t.split(";")
            for p in parts:
                p=p.strip()
                if p.startswith("p="):
                    policy=p.split("=",1)[1]
                elif p.startswith("rua="):
                    rua=p.split("=",1)[1]
                elif p.startswith("ruf="):
                    ruf=p.split("=",1)[1]
                elif p.startswith("pct="):
                    pct=p.split("=",1)[1]
            break
    return rec,policy,rua,ruf,pct
def check_dkim(domain,selectors):
    if not domain or not str(domain).strip():
        return []
    selectors = selectors if selectors is not None else selectors_default
    rows=[]
    for s in selectors:
        sel=s if "." in s else s+"._domainkey"
        name=sel+"."+domain
        txts=get_txt(name)
        if txts:
            rec=[t for t in txts if "v=DKIM1" in t or "k=" in t]
            if rec:
                rows.append((s,"Y",rec[0][:80]))
            else:
                rows.append((s,"Y","TXT"))
        else:
            rows.append((s,"N","-"))
    return rows
if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)
    domain=clean_domain_input(sys.argv[1])
    spf_txts=get_txt(domain)
    spf_rec=parse_spf(spf_txts)
    dmarc_txts=get_txt("_dmarc."+domain)
    dmarc_rec,policy,rua,ruf,pct=parse_dmarc(dmarc_txts)
    dkim_rows=check_dkim(domain,selectors_default)
    table1=Table(title=f"SPF Record: {domain}",show_header=True,header_style="bold magenta")
    table1.add_column("Value",style="cyan",overflow="fold")
    table1.add_row(spf_rec)
    console.print(table1 if spf_rec!="-" else "[yellow][!] No SPF record found.[/yellow]")
    table2=Table(title=f"DMARC Record: {domain}",show_header=True,header_style="bold magenta")
    table2.add_column("Record",style="cyan",overflow="fold")
    table2.add_column("Policy",style="green")
    table2.add_column("RUA",style="yellow",overflow="fold")
    table2.add_column("RUF",style="white",overflow="fold")
    table2.add_column("Pct",style="blue")
    table2.add_row(dmarc_rec,policy,rua,ruf,pct)
    console.print(table2 if dmarc_rec!="-" else "[yellow][!] No DMARC record found.[/yellow]")
    table3=Table(title=f"DKIM Selectors: {domain}",show_header=True,header_style="bold magenta")
    table3.add_column("Selector",style="cyan")
    table3.add_column("Found",style="green")
    table3.add_column("Snippet",style="yellow",overflow="fold")
    for r in dkim_rows:
        table3.add_row(r[0],r[1],r[2])
    console.print(table3)
    console.print("[white][*] SPF/DKIM/DMARC validation completed.[/white]")
