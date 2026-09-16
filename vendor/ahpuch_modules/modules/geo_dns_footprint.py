#!/usr/bin/env python3
import os, sys, json, socket, dns.resolver, concurrent.futures, urllib3
from collections import defaultdict, Counter
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console=Console(); TEAL="#2EC4B6"

DEFAULT_RESOLVERS=[
 ("Google","US","8.8.8.8"),("Google2","US","8.8.4.4"),("Cloudflare","US","1.1.1.1"),
 ("Cloudflare2","US","1.0.0.1"),("Quad9","CH","9.9.9.9"),("Quad9Sec","CH","149.112.112.112"),
 ("OpenDNS","US","208.67.222.222"),("OpenDNS2","US","208.67.220.220"),("Comodo","US","8.26.56.26"),
 ("Comodo2","US","8.20.247.20"),("Yandex","RU","77.88.8.8"),("Yandex2","RU","77.88.8.1"),
 ("CleanBrowsing","US","185.228.168.9"),("Level3","US","4.2.2.1"),("Level3b","US","4.2.2.2"),
 ("Norton","US","199.85.126.10"),("AdGuard","CY","94.140.14.14"),("AdGuard2","CY","94.140.15.15"),
 ("DNSWatch","DE","84.200.69.80"),("DNSWatch2","DE","84.200.70.40"),("Dyn","US","216.146.35.35"),
 ("Dyn2","US","216.146.36.36"),("AliDNS","CN","223.5.5.5"),("AliDNS2","CN","223.6.6.6"),
 ("Baidu","CN","180.76.76.76"),("DNSSB","SG","185.222.222.222"),("Ultra","US","156.154.70.1"),
 ("Ultra2","US","156.154.71.1"),("Freenom","NL","80.80.80.80"),("Freenom2","NL","80.80.81.81")
]

def banner():
    bar="="*44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]         Ah-Puch – Geo-DNS Footprint")
    console.print(f"[{TEAL}]{bar}")

def resolve_with(server_ip, domain, t):
    if not str(domain or "").strip():
        return []
    r=dns.resolver.Resolver(configure=False)
    r.nameservers=[server_ip]; r.lifetime=t
    try:
        ans=r.resolve(domain,"A"); return [str(a) for a in ans]
    except: return []

def run(target, threads, opts):
    banner()
    t   = int(opts.get("timeout",DEFAULT_TIMEOUT))
    dom = clean_domain_input(target)
    console.print(f"[white]* Resolving A-records via {len(DEFAULT_RESOLVERS)} public resolvers[/white]")

    rows=[]
    ip_map=defaultdict(list)

    with Progress(SpinnerColumn(),TextColumn("Querying…"),BarColumn(),console=console,transient=True) as pg:
        task=pg.add_task("",total=len(DEFAULT_RESOLVERS))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures={pool.submit(resolve_with,ip,dom,t):(name,cc,ip) for name,cc,ip in DEFAULT_RESOLVERS}
            for fut in concurrent.futures.as_completed(futures):
                name,cc,ip_srv=futures[fut]; ips=fut.result()
                rows.append((name,cc,ip_srv,", ".join(ips) or "-"))
                for ip in ips: ip_map[ip].append(name)
                pg.advance(task)

    distribution=Counter({ip:len(names) for ip,names in ip_map.items()})
    table1=Table(title=f"Geo-DNS Footprint – {dom}",header_style="bold white")
    table1.add_column("Resolver"); table1.add_column("CC"); table1.add_column("DNS IP"); table1.add_column("Answer(s)",overflow="fold")
    for r in rows: table1.add_row(*r)

    table2=Table(title="Answer-IP Reach",header_style="bold white")
    table2.add_column("Answer IP"); table2.add_column("Seen-by (#)"); table2.add_column("Resolvers")
    for ip,count in distribution.most_common():
        table2.add_row(ip,str(count),", ".join(sorted(ip_map[ip][:8]))+"…")

    console.print(table1); console.print(table2)
    console.print("[green]* Geo-DNS footprint completed[/green]")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out=os.path.join(RESULTS_DIR,dom); ensure_directory_exists(out)
        export_console = Console(record=True, width=console.width)
        export_console.print(table1)
        export_console.print(table2)
        write_to_file(os.path.join(out,"geo_dns.txt"), export_console.export_text())

if __name__=="__main__":
    tgt=sys.argv[1]; thr=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 16
    opts={}
    if len(sys.argv)>3:
        try: opts=json.loads(sys.argv[3])
        except: pass
    run(tgt,thr,opts)
