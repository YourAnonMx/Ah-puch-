import os
import sys
import ssl
import socket
import ipaddress
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init
try:
    from OpenSSL import crypto
except:
    crypto=None

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
     Ah-Puch - Network Certificate Inventory
    =============================================
    """)

def resolve_domain_ips(domain):
    if not str(domain or "").strip():
        return []
    ips=[]
    try:
        a=dns.resolver.resolve(domain,"A",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in a])
    except:
        pass
    try:
        a6=dns.resolver.resolve(domain,"AAAA",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in a6])
    except:
        pass
    return ips

def expand_cidr(cidr,limit=512):
    if not str(cidr or "").strip():
        return []
    out=[]
    try:
        net=ipaddress.ip_network(cidr,strict=False)
        for i,ip in enumerate(net.hosts()):
            if i>=limit:
                break
            out.append(str(ip))
    except:
        pass
    return out

def load_ip_file(path):
    if not path or not os.path.isfile(path):
        return []
    out=[]
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for l in f:
            l=l.strip()
            if not l:
                continue
            if "/" in l:
                out.extend(expand_cidr(l))
            else:
                out.append(l)
    return out

def fetch_cert(ip,port=443,server_name=None):
    if not str(ip or "").strip():
        return ("-","ERR","-","-","-","-","-")
    ctx=ssl.create_default_context()
    ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE
    s=None
    try:
        s=socket.create_connection((ip,port),timeout=DEFAULT_TIMEOUT)
        tls=ctx.wrap_socket(s,server_hostname=server_name or ip)
        cert_bin=tls.getpeercert(True)
        tls.close()
    except:
        return (ip,"ERR","-","-","-","-","-")
    sha256=ssl.DER_cert_to_PEM_cert(cert_bin)
    if crypto:
        try:
            x=crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        except:
            try:
                x=crypto.load_certificate(crypto.FILETYPE_PEM,ssl.DER_cert_to_PEM_cert(cert_bin))
            except:
                x=None
        if x:
            subj=x.get_subject()
            cn=getattr(subj,"CN",None) or "-"
            sans=[]
            try:
                ext_count=x.get_extension_count()
                for i in range(ext_count):
                    e=x.get_extension(i)
                    if e.get_short_name().decode().lower()=="subjectaltname":
                        data=str(e)
                        for part in data.split(","):
                            part=part.strip()
                            if part.lower().startswith("dns:"):
                                sans.append(part.split(":",1)[1])
            except:
                pass
            nb=x.get_notBefore().decode()[:14] if x.get_notBefore() else "-"
            na=x.get_notAfter().decode()[:14] if x.get_notAfter() else "-"
            fp=x.digest("sha256").decode() if hasattr(x,"digest") else "-"
            return (ip,cn,",".join(sans[:5]) if sans else "-",nb,na,fp,str(len(cert_bin)))
    try:
        cert=tls.getpeercert()
    except:
        cert={}
    cn="-"
    if cert:
        for tup in cert.get("subject",[]):
            for k,v in tup:
                if k=="commonName":
                    cn=v
    return (ip,cn,"-","-","-","-",str(len(cert_bin)))

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] no target provided. Please pass a domain or IP address.[/red]")
        sys.exit(1)
    target=sys.argv[1]
    ip_inputs=[]
    if "/" in target and not any(c.isalpha() for c in target):
        ip_inputs=expand_cidr(target)
    elif any(c.isalpha() for c in target):
        domain=clean_domain_input(target)
        ip_inputs=resolve_domain_ips(domain)
    else:
        ip_inputs=[target]
    extra=load_ip_file(sys.argv[2]) if len(sys.argv)>2 else []
    ip_inputs.extend(extra)
    ip_inputs=list(dict.fromkeys(ip_inputs))
    if not ip_inputs:
        console.print("[yellow][!] No IPs to scan.[/yellow]")
        sys.exit(0)
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Collecting certs",total=len(ip_inputs))
        with ThreadPoolExecutor(max_workers=50) as exe:
            futs={exe.submit(fetch_cert,ip,443,None):ip for ip in ip_inputs}
            for f in as_completed(futs):
                rows.append(f.result())
                progress.advance(task)
    table=Table(title="Network Certificate Inventory",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan",overflow="fold")
    table.add_column("CN",style="green",overflow="fold")
    table.add_column("SANs",style="yellow",overflow="fold")
    table.add_column("NotBefore",style="white")
    table.add_column("NotAfter",style="white")
    table.add_column("SHA256",style="blue",overflow="fold")
    table.add_column("Bytes",style="magenta")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] Network certificate inventory completed.[/white]")
