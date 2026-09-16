import os
import sys
import socket
import ipaddress
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input

init(autoreset=True)
console = Console()

DEFAULT_PORT = 161
DEFAULT_COMMUNITIES = ["public","private","community"]

OID_SYS_DESCR = b'\x2b\x06\x01\x02\x01\x01\x01\x00'  # 1.3.6.1.2.1.1.1.0

def banner():
    console.print("""
    =============================================
      Ah-Puch - SNMP Public Community Checker
    =============================================
    """)

def parse_opts(argv):
    port=DEFAULT_PORT
    comms=list(DEFAULT_COMMUNITIES)
    i=3
    while i<len(argv):
        a=argv[i]
        if a=="--port" and i+1<len(argv):
            try: port=int(argv[i+1])
            except: pass
            i+=2; continue
        if a=="--comm" and i+1<len(argv):
            comms=[c.strip() for c in argv[i+1].split(",") if c.strip()]
            i+=2; continue
        if a=="--communities" and i+1<len(argv):
            path=argv[i+1]
            if os.path.isfile(path):
                comms=[]
                with open(path,"r",encoding="utf-8",errors="ignore") as f:
                    for l in f:
                        l=l.strip()
                        if l and not l.startswith("#"): comms.append(l)
                if not comms: comms=list(DEFAULT_COMMUNITIES)
            i+=2; continue
        i+=1
    return port,comms

def resolve_domain(domain):
    if not str(domain or "").strip():
        return []
    ips=[]
    try:
        a=dns.resolver.resolve(domain,"A",lifetime=DEFAULT_TIMEOUT)
        for r in a: ips.append(r.address)
    except:
        pass
    try:
        a6=dns.resolver.resolve(domain,"AAAA",lifetime=DEFAULT_TIMEOUT)
        for r in a6: ips.append(r.address)
    except:
        pass
    return list(dict.fromkeys(ips))

def expand_target(t):
    if not str(t or "").strip():
        return []
    try:
        net = ipaddress.ip_network(t, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        pass
    if any(c.isalpha() for c in t):
        d=clean_domain_input(t)
        return resolve_domain(d) or [t]
    return [t]

def build_snmp_get(community,req_id=1):
    com=community.encode()
    ver=b'\x02\x01\x01'
    comseq=b'\x04'+bytes([len(com)])+com
    rid=b'\x02\x04'+req_id.to_bytes(4,'big')
    err=b'\x02\x01\x00'
    eri=b'\x02\x01\x00'
    oid=b'\x06'+bytes([len(OID_SYS_DESCR)])+OID_SYS_DESCR
    null=b'\x05\x00'
    vb_seq=b'\x30'+bytes([len(oid)+len(null)])+oid+null
    vbl=b'\x30'+bytes([len(vb_seq)])+vb_seq
    pdu_tag=b'\xa0'
    pdu_len=len(rid)+len(err)+len(eri)+len(vbl)
    pdu=pdu_tag+bytes([pdu_len])+rid+err+eri+vbl
    seq_len=len(ver)+len(comseq)+len(pdu)
    msg=b'\x30'+bytes([seq_len])+ver+comseq+pdu
    return msg

def parse_snmp_response(data):
    if not data: return "-"
    if b'\x04' in data and b'\x06' in data:
        return "RESP"
    return "-"

def snmp_try(ip,port,community):
    if not str(ip or "").strip() or not str(community or "").strip():
        return "-"
    s=None
    try:
        s=socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6,socket.SOCK_DGRAM)
        s.settimeout(DEFAULT_TIMEOUT)
        pkt=build_snmp_get(community)
        s.sendto(pkt,(ip,port))
        data,_=s.recvfrom(2048)
        return parse_snmp_response(data)
    except:
        return "-"
    finally:
        try:
            if s: s.close()
        except: pass

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain, IP, or CIDR.[/red]")
        sys.exit(1)
    raw=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    port,comms=parse_opts(sys.argv)
    targets=expand_target(raw)
    rows=[]
    total=len(targets)*len(comms)
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Checking SNMP",total=total)
        for ip in targets:
            for c in comms:
                resp=snmp_try(ip,port,c)
                rows.append((ip,str(port),c,"Y" if resp!="-" else "-",resp))
                progress.advance(task)
    table=Table(title="SNMP Public Community Checker",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan")
    table.add_column("Port",style="green")
    table.add_column("Community",style="yellow")
    table.add_column("Responded",style="white")
    table.add_column("Note",style="magenta")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] SNMP community checking completed.[/white]")
