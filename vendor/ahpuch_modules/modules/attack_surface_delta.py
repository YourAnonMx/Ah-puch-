#!/usr/bin/env python3
import os, sys, json, asyncio, aiohttp, ssl, socket, datetime
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file, resolve_to_ip
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

console=Console()

async def fetch_json(session,url,timeout):
    if not url or not str(url).strip():
        return None
    try:
        async with session.get(url,timeout=timeout,headers={"User-Agent":"Mozilla"}) as r:
            if r.status==200: return await r.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, TypeError, ValueError):
        pass
    return None

async def passive_subdomains(domain,session,timeout):
    if not domain or not str(domain).strip():
        return set()
    out=set()
    crt=await fetch_json(session,f"https://crt.sh/?q=%25.{domain}&output=json",timeout)
    if crt: out.update({e['name_value'].lower() for e in crt})
    buf=await fetch_json(session,f"https://dns.bufferover.run/dns?q=.{domain}",timeout)
    if buf and buf.get("FDNS_A"): out.update({t.split(",")[1] for t in buf["FDNS_A"]})
    tc=await fetch_json(session,f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",timeout)
    if tc and tc.get("subdomains"): out.update(tc["subdomains"])
    return {s.strip().lower().lstrip("*.") for s in out if s.endswith(domain)}

async def resolve_batch(subs,thr,timeout):
    if not subs:
        return defaultdict(set)
    thr=max(1,min(int(thr),32))
    sem=asyncio.Semaphore(thr)
    dns=asyncio.get_running_loop().getaddrinfo
    ips=defaultdict(set)
    async def res(s):
        async with sem:
            try:
                for fam,_,_,_,addr in await dns(s,0,proto=socket.IPPROTO_TCP):
                    ips[s].add(addr[0])
            except (OSError, asyncio.TimeoutError, TypeError, ValueError):
                pass
    await asyncio.gather(*(res(s) for s in subs))
    return ips

async def scan_port(ip,port,timeout):
    if not ip or not port:
        return False
    try:
        fut=asyncio.open_connection(ip,port,ssl=None)
        reader,writer=await asyncio.wait_for(fut,timeout)
        writer.close(); await writer.wait_closed(); return True
    except (OSError, asyncio.TimeoutError, TypeError, ValueError): return False

async def portscan(ips,ports,thr,timeout):
    if not ips or not ports:
        return defaultdict(list)
    thr=max(1,min(int(thr),32))
    sem=asyncio.Semaphore(thr)
    openmap=defaultdict(list)
    async def worker(ip,port):
        async with sem:
            if await scan_port(ip,port,timeout): openmap[ip].append(port)
    await asyncio.gather(*(worker(ip,p) for ip in ips for p in ports))
    return openmap

async def http_probe(session,url,timeout):
    if not url or not str(url).strip():
        return None
    try:
        async with session.get(url,timeout=timeout,allow_redirects=False) as r:
            t=await r.text()
            title=""
            if "<title" in t.lower():
                title=t.split("<title",1)[1].split(">",1)[1].split("</title",1)[0].strip()
            return {"code":r.status,"server":r.headers.get("server",""),"title":title[:80]}
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, TypeError, ValueError): return None

async def web_fingerprints(subs,thr,timeout):
    if not subs:
        return {}
    thr=max(1,min(int(thr),32))
    sem=asyncio.Semaphore(thr)
    out={}
    async with aiohttp.ClientSession() as s:
        async def wrk(sub):
            async with sem:
                for scheme in ("https","http"):
                    u=f"{scheme}://{sub}"
                    data=await http_probe(s,u,timeout)
                    if data: out[sub]=data; break
        await asyncio.gather(*(wrk(sub) for sub in subs))
    return out

async def main_async(domain,threads,opts):
    if not domain or not str(domain).strip():
        return 2
    opts=opts if isinstance(opts,dict) else {}
    try:
        timeout=max(1,min(int(opts.get("timeout",DEFAULT_TIMEOUT)),60))
    except (TypeError,ValueError):
        timeout=DEFAULT_TIMEOUT
    try:
        threads=max(1,min(int(threads),32))
    except (TypeError,ValueError):
        threads=1
    try:
        ports_top=max(1,min(int(opts.get("ports_top",12)),14))
    except (TypeError,ValueError):
        ports_top=12
    ports=[80,443,8080,8443,21,22,25,3306,5432,6379,8000,7001,9200,27017][:ports_top]
    console.print(f"[bold cyan]Mapping attack surface for {domain}[/bold cyan]")
    async with aiohttp.ClientSession() as session:
        with Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True) as prog:
            t1=prog.add_task("Passive subdomain enumeration",total=None)
            subs=await passive_subdomains(domain,session,timeout)
            prog.update(t1,completed=1,total=1);prog.stop_task(t1)
            t2=prog.add_task("DNS resolution",total=None)
            ipmap=await resolve_batch(subs,threads,timeout)
            prog.update(t2,completed=1,total=1);prog.stop_task(t2)
            unique_ips={ip for ips in ipmap.values() for ip in ips}
            t3=prog.add_task("Port scanning",total=None)
            openmap=await portscan(unique_ips,ports,threads,timeout)
            prog.update(t3,completed=1,total=1);prog.stop_task(t3)
            t4=prog.add_task("HTTP fingerprinting",total=None)
            webmap=await web_fingerprints(subs,threads,timeout)
            prog.update(t4,completed=1,total=1);prog.stop_task(t4)
    sub_table=Table(title="Subdomains",header_style="bold magenta")
    sub_table.add_column("Subdomain",style="cyan");sub_table.add_column("IPs",style="yellow")
    for s,ips in ipmap.items(): sub_table.add_row(s,"\n".join(ips))
    console.print(sub_table)
    port_table=Table(title="Open Ports",header_style="bold magenta")
    port_table.add_column("IP",style="green");port_table.add_column("Ports",style="white")
    for ip,plist in openmap.items(): port_table.add_row(ip,",".join(map(str,plist)))
    console.print(port_table)
    web_t=Table(title="Web Fingerprints",header_style="bold magenta")
    web_t.add_column("Host");web_t.add_column("Code");web_t.add_column("Server");web_t.add_column("Title",overflow="fold")
    for h,d in webmap.items(): web_t.add_row(h,str(d["code"]),d["server"],d["title"])
    console.print(web_t)
    summ=f"Subs:{len(subs)}  IPs:{len(unique_ips)}  Web:{len(webmap)}"
    console.print(Panel(summ,title="Summary",style="bold white"))
    if EXPORT_SETTINGS.get("enable_txt_export"):
        out=os.path.join(RESULTS_DIR,clean_domain_input(domain))
        ensure_directory_exists(out)
        res={"subdomains":list(ipmap),"ips":list(unique_ips),"ports":openmap,"web":webmap,"ts":datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()}
        write_to_file(os.path.join(out,"attack_surface.json"),json.dumps(res,indent=2,ensure_ascii=False))
    return 0

def main():
    if len(sys.argv)<3: console.print("usage: <domain> <threads> [json-opts]");sys.exit(1)
    d=clean_domain_input(sys.argv[1]);thr=int(sys.argv[2]);
    try:
        opts=json.loads(sys.argv[3]) if len(sys.argv)>3 else {}
    except (TypeError,ValueError):
        opts={}
    asyncio.run(main_async(d,thr,opts))

if __name__=="__main__":
    main()
