import os
import sys
import ssl
import socket
import time
import ipaddress
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init
try:
    from OpenSSL import SSL
except:
    SSL=None
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input
init(autoreset=True)
console = Console()
def banner():
    console.print("""
    =============================================
      Ah-Puch - TLS Session Resumption Map
    =============================================
    """)
def resolve_ips(target):
    if not str(target or "").strip():
        return []
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    ips=[]
    try:
        ans=dns.resolver.resolve(target,"A",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in ans])
    except:
        pass
    try:
        ans6=dns.resolver.resolve(target,"AAAA",lifetime=DEFAULT_TIMEOUT)
        ips.extend([r.address for r in ans6])
    except:
        pass
    return list(dict.fromkeys(ips))
def pyopenssl_resumption(host,ip):
    if not str(host or "").strip() or not str(ip or "").strip() or not SSL:
        return None
    ctx=SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_timeout(int(DEFAULT_TIMEOUT))
    sess=None
    t0=time.time()
    try:
        c1=SSL.Connection(ctx)
        c1.set_tlsext_host_name(host.encode())
        c1.connect((ip,443))
        c1.do_handshake()
        t1=time.time()-t0
        sess=c1.get_session()
        c1.shutdown()
        c1.close()
    except:
        return ("ERR","-","-")
    t2=time.time()
    try:
        c2=SSL.Connection(ctx)
        c2.set_tlsext_host_name(host.encode())
        if sess:
            c2.set_session(sess)
        c2.connect((ip,443))
        c2.do_handshake()
        t3=time.time()-t2
        reused="Y" if c2.session_reused() else "N"
        c2.shutdown()
        c2.close()
    except:
        return ("ERR",f"{t1*1000:.1f}","-")
    return (reused,f"{t1*1000:.1f}",f"{t3*1000:.1f}")
def stdlib_resumption(host,ip):
    if not str(host or "").strip() or not str(ip or "").strip():
        return ("ERR","-","-")
    ctx=ssl.create_default_context()
    ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE
    t0=time.time()
    try:
        s=socket.create_connection((ip,443),timeout=DEFAULT_TIMEOUT)
        tls=ctx.wrap_socket(s,server_hostname=host)
        t1=time.time()-t0
        tls.close()
    except:
        return ("ERR","-","-")
    t2=time.time()
    try:
        s=socket.create_connection((ip,443),timeout=DEFAULT_TIMEOUT)
        tls=ctx.wrap_socket(s,server_hostname=host)
        t3=time.time()-t2
        tls.close()
    except:
        return ("ERR",f"{t1*1000:.1f}","-")
    reused="?"
    return (reused,f"{t1*1000:.1f}",f"{t3*1000:.1f}")
def test_host(host,ip):
    if not str(host or "").strip() or not str(ip or "").strip():
        return ("ERR","-","-")
    if SSL:
        return pyopenssl_resumption(host,ip)
    return stdlib_resumption(host,ip)
if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain or IP address.[/red]")
        sys.exit(1)
    raw_target=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    target=clean_domain_input(raw_target)
    ips=resolve_ips(target)
    if not ips:
        console.print("[yellow][!] No IPs resolved for target.[/yellow]")
        sys.exit(0)
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),console=console,transient=True)
    with progress:
        t=progress.add_task("Testing TLS resumption",total=len(ips))
        for ip in ips:
            reused,t1,t2=test_host(target,ip)
            if reused=="?":
                try:
                    ft1=float(t1.replace("ms",""))
                    ft2=float(t2.replace("ms",""))
                    reused="Y" if t2!="-" and ft2<=(ft1*0.6) else "N"
                except:
                    reused="N"
            rows.append((ip,reused,t1,t2))
            progress.advance(t)
    table=Table(title=f"TLS Session Resumption: {target}",show_header=True,header_style="bold magenta")
    table.add_column("IP",style="cyan",overflow="fold")
    table.add_column("Resumed",style="green")
    table.add_column("1st ms",style="yellow")
    table.add_column("2nd ms",style="white")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] TLS session resumption mapping completed.[/white]")
