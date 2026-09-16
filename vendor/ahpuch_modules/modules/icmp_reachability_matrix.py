import os
import sys
import platform
import subprocess
import dns.resolver
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
      Ah-Puch - ICMP Reachability Matrix
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
def load_extra(path):
    if not path or not os.path.isfile(path):
        return []
    out=[]
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            line=line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out
def ping_host(ip,count=1,timeout=3):
    if not str(ip or "").strip():
        return False,"-"
    count = max(1, int(count))
    timeout = max(0.1, float(timeout))
    plat=platform.system().lower()
    if plat.startswith("win"):
        cmd=["ping","-n",str(count),"-w",str(timeout*1000),ip]
    else:
        cmd=["ping","-c",str(count),"-W",str(timeout),ip]
    try:
        proc=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout+2)
        out=proc.stdout+proc.stderr
        ok=("ttl=" in out.lower()) or ("time=" in out.lower()) or ("bytes=" in out.lower() and "icmp_seq" in out.lower())
        rtt="-"
        for part in out.replace("=",":").split(":"):
            if part.strip().lower().endswith("ms"):
                try:
                    val=part.strip().split()[0]
                    float(val)
                    rtt=val
                    break
                except:
                    pass
        return ok,rtt
    except:
        return False,"-"
if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] no target provided. Please pass a domain or IP address.[/red]")
        sys.exit(1)
    domain=clean_domain_input(sys.argv[1])
    ips=resolve_ips(domain)
    extra=load_extra(sys.argv[2] if len(sys.argv)>2 else None)
    targets=list(dict.fromkeys(ips+extra))
    console.print(f"[white][*] Probing {len(targets)} IPs[/white]")
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("ICMP",total=len(targets))
        for ip in targets:
            ok,rtt=ping_host(ip)
            rows.append((ip,"Y" if ok else "N",rtt))
            progress.advance(task)
    table=Table(title=f"ICMP Reachability: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan",overflow="fold")
    table.add_column("Reply",style="green")
    table.add_column("RTT(ms)",style="yellow")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] ICMP reachability matrix completed.[/white]")
