import os
import sys
import json
import requests
from urllib.parse import quote
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, API_KEYS
from ahpuch_modules.utils.util import clean_domain_input, resolve_to_ip

init(autoreset=True)
console = Console()
requests.packages.urllib3.disable_warnings()

FEEDS_ALL = ["otx","urlscan","abuseipdb","virustotal","urlhaus"]

def banner():
    console.print("""
    =============================================
        Ah-Puch - Threat Feed Correlator
    =============================================
    """)

def parse_opts(argv):
    feeds=FEEDS_ALL[:]
    i=3
    while i<len(argv):
        a=argv[i]
        if a=="--feeds" and i+1<len(argv):
            feeds=[x.strip().lower() for x in argv[i+1].split(",") if x.strip()]
            i+=2; continue
        i+=1
    return [f for f in feeds if f in FEEDS_ALL]

def otx_lookup(ind_type,indicator):
    if not indicator or not str(indicator).strip():
        return ("-","-","-")
    url=f"https://otx.alienvault.com/api/v1/indicators/{ind_type}/{quote(indicator)}/general"
    try:
        r=requests.get(url,timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        if r.status_code==200:
            j=r.json()
            pulses=j.get("pulse_info",{})
            cnt=pulses.get("count",0)
            return ("Y" if cnt else "-",str(cnt),pulses.get("name") or "-")
        return ("ERR","-","HTTP"+str(r.status_code))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return ("ERR","-","-")

def urlscan_lookup(indicator):
    if not indicator or not str(indicator).strip():
        return ("-","-","-")
    try:
        r=requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{indicator}",timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        if r.status_code==200:
            j=r.json()
            total=j.get("total",0)
            return ("Y" if total else "-",str(total),"-")
        return ("ERR","-","HTTP"+str(r.status_code))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return ("ERR","-","-")

def abuseipdb_lookup(ip):
    if not ip or not str(ip).strip():
        return ("-","-","-")
    key=API_KEYS.get("ABUSEIPDB_API_KEY")
    hdr={"Key":key,"Accept":"application/json"} if key else {}
    try:
        r=requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",headers=hdr,timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        if r.status_code==200:
            j=r.json().get("data",{})
            score=j.get("abuseConfidenceScore",0)
            return ("Y" if score else "-",str(score),str(j.get("totalReports","0")))
        if r.status_code==401: return ("NOAPI","-","-")
        return ("ERR","-","HTTP"+str(r.status_code))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return ("ERR","-","-")

def vt_lookup(ind_type,indicator):
    if not indicator or not str(indicator).strip():
        return ("-","-","-")
    key=API_KEYS.get("VIRUSTOTAL_API_KEY")
    if not key:
        return ("NOAPI","-","-")
    hdr={"x-apikey":key}
    url=f"https://www.virustotal.com/api/v3/{'domains' if ind_type=='domain' else 'ip_addresses'}/{indicator}"
    try:
        r=requests.get(url,headers=hdr,timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        if r.status_code==200:
            j=r.json().get("data",{}).get("attributes",{})
            rep=j.get("reputation",0)
            mal=j.get("last_analysis_stats",{}).get("malicious",0)
            return ("Y" if mal else "-",str(mal),str(rep))
        if r.status_code==401: return ("NOAPI","-","-")
        return ("ERR","-","HTTP"+str(r.status_code))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return ("ERR","-","-")

def urlhaus_lookup(indicator):
    if not indicator or not str(indicator).strip():
        return ("-","-","-")
    data={"host":indicator}
    try:
        r=requests.post("https://urlhaus.abuse.ch/api/host/",data=data,timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        if r.status_code==200:
            j=r.json()
            cnt=0
            if j.get("query_status")=="ok":
                cnt=len(j.get("urls",[]))
            return ("Y" if cnt else "-",str(cnt),"-")
        return ("ERR","-","HTTP"+str(r.status_code))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return ("ERR","-","-")

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain or IP.[/red]")
        sys.exit(1)
    raw=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    feeds=parse_opts(sys.argv)
    target=clean_domain_input(raw)
    if not target:
        sys.exit(2)
    ind_type="domain"
    ip=resolve_to_ip(target)
    if ip and target.replace(".","").isdigit():
        ind_type="ip"
        target=ip
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Querying feeds",total=len(feeds))
        for f in feeds:
            if f=="otx":
                st,c1,c2=otx_lookup("hostname" if ind_type=="domain" else "IPv4",target)
            elif f=="urlscan":
                st,c1,c2=urlscan_lookup(target)
            elif f=="abuseipdb":
                st,c1,c2=abuseipdb_lookup(ip or target)
            elif f=="virustotal":
                st,c1,c2=vt_lookup(ind_type,target)
            elif f=="urlhaus":
                st,c1,c2=urlhaus_lookup(target)
            else:
                st,c1,c2=("-","-","-")
            rows.append((f,st,c1,c2))
            progress.advance(task)
    table=Table(title="Threat Feed Correlator",show_header=True,header_style="bold magenta")
    table.add_column("Feed",style="cyan")
    table.add_column("Listed?",style="green")
    table.add_column("Count/Score",style="yellow")
    table.add_column("Detail",style="white")
    for r in rows:
        table.add_row(*r)
    console.print(table)
    console.print("[white][*] Threat feed correlation completed.[/white]")
