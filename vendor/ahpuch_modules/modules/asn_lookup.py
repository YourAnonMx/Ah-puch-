#!/usr/bin/env python3
import sys, os, json, socket, concurrent.futures

import requests, urllib3
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from tabulate import tabulate
from ahpuch_modules.utils.util import resolve_to_ip, clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console=Console(); TEAL="#2EC4B6"

def banner():
    border = "=" * 44
    console.print(f"[{TEAL}]{border}")
    console.print(f"[{TEAL}] Ah-Puch – ASN Lookup")
    console.print(f"[{TEAL}]{border}")

def _ipapi(ip, timeout):
    try:
        r=requests.get(f"https://ip-api.com/json/{ip}?fields=as,name,country,city,org", timeout=timeout, verify=True); r.raise_for_status()
        j=r.json(); return j.get("as","-"),j.get("org") or j.get("name","-"),j.get("country","-"),j.get("city","-")
    except: return "-","-","-","-"

def _rdap(ip, timeout):
    try:
        r=requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=timeout, verify=True); r.raise_for_status()
        j=r.json(); asn=f"AS{j.get('handle','')}" or "-"
        ent=(j.get("entities") or [{}])[0]; org="-"
        try: org=ent["vcardArray"][1][1][3]
        except: pass
        c=j.get("country","-")
        return asn,org,c,"-"
    except: return "-","-","-","-"

def worker(ip, timeout, provider):
    if provider=="rdap": return _rdap(ip, timeout)
    if provider=="both":
        a1=_ipapi(ip,timeout); a2=_rdap(ip,timeout)
        return a2 if a2[0]!="-" else a1
    return _ipapi(ip, timeout)

def render(rows):
    return tabulate(rows, ["IP","ASN","Org","Country","City"], tablefmt="grid")

def export(dom, txt):
    if EXPORT_SETTINGS.get("enable_txt_export"):
        out=os.path.join(RESULTS_DIR,dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out,"asn_lookup.txt"), txt)

def run(target,threads,opts):
    banner()
    dom=clean_domain_input(target)
    if not dom:
        console.print("[yellow]No target[/yellow]")
        return
    timeout=int(opts.get("timeout",DEFAULT_TIMEOUT))
    provider=opts.get("provider","both")     # ipapi | rdap | both
    ips_file=opts.get("ips_file")
    ips=[]
    if ips_file and os.path.isfile(ips_file):
        with open(ips_file) as f: ips=[i.strip() for i in f if i.strip()]
    else:
        ip=resolve_to_ip(dom); ips=[ip] if ip else []
    if not ips: console.print("[red]No IPs[/red]"); return
    rows=[]
    with Progress(SpinnerColumn(),TextColumn("[cyan]Querying[/cyan]"),BarColumn(),console=console,transient=True) as p:
        t=p.add_task("", total=len(ips))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for res in pool.map(lambda ip: (ip,*worker(ip,timeout,provider)), ips):
                rows.append(res); p.advance(t)
    txt=render(rows); console.print(txt); console.print(f"[green]* {len(rows)} result(s)[/green]")
    export(dom, txt)

if __name__=="__main__":
    tgt=sys.argv[1]; thr=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 4
    opts={}
    if len(sys.argv)>3:
        try: opts=json.loads(sys.argv[3]);
        except: pass
    run(tgt,thr,opts)
