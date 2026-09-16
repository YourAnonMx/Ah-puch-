import os
import sys
import re
import json
import requests
import dns.resolver
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, API_KEYS
from ahpuch_modules.utils.util import clean_domain_input

init(autoreset=True)
console = Console()
requests.packages.urllib3.disable_warnings()

SECURITY_TXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
    "/.well-known/security",
]
DISCLOSURE_KEYWORDS = ("security","vulnerability","vuln","bug bounty","hackerone","bugcrowd","intigriti","yeswehack","report a vulnerability")
DISCLOSURE_RE = re.compile("|".join([re.escape(k) for k in DISCLOSURE_KEYWORDS]), re.I)

def banner():
    console.print("""
    =============================================
     Ah-Puch - Security Contact Gap Finder
    =============================================
    """)

def parse_opts(argv):
    fetch_site=True
    i=3
    while i<len(argv):
        a=argv[i]
        if a=="--no-site":
            fetch_site=False
            i+=1; continue
        i+=1
    return fetch_site

def get_whois_abuse(domain):
    if not domain or not str(domain).strip():
        return []
    try:
        r=requests.get(f"https://rdap.org/domain/{domain}",timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        if r.status_code==200:
            j=r.json()
            emails=set()
            for ent in j.get("entities",[]):
                roles=ent.get("roles") or []
                if any(x in roles for x in ("abuse","security","technical")):
                    v=ent.get("vcardArray")
                    if isinstance(v,list) and len(v)>1 and isinstance(v[1],list):
                        for item in v[1]:
                            if len(item)>=4 and item[0]=="email":
                                emails.add(item[3])
            abuse=j.get("port43") or "-"
            return list(emails) or ([abuse] if abuse and "@" in abuse else [])
        return []
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return []

def get_security_txt(domain):
    if not domain or not str(domain).strip():
        return []
    base="https://"+domain
    hits=[]
    for p in SECURITY_TXT_PATHS:
        url=urljoin(base,p)
        try:
            r=requests.get(url,timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
            if r.status_code<400 and r.text:
                hits.append((url,r.text))
        except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
            continue
    return hits

def parse_security_txt(text):
    if not isinstance(text, str):
        return []
    emails=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        if line.lower().startswith("contact:"):
            v=line.split(":",1)[1].strip()
            if v.lower().startswith("mailto:"):
                v=v[7:]
            emails.append(v)
    return emails

def fetch_root_html(domain):
    if not domain or not str(domain).strip():
        return ""
    url="https://"+domain
    try:
        r=requests.get(url,timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        if r.status_code<400:
            return r.text
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        pass
    return ""

def discover_disclosure_links(html,domain):
    hits=[]
    if not isinstance(html, str) or not html or not domain: return hits
    for m in re.finditer(r'href=[\'"]([^\'"]+)[\'"]',html,re.I):
        u=m.group(1)
        low=u.lower()
        if DISCLOSURE_RE.search(low):
            hits.append(u)
    return hits

def best_guess_abuse(domain):
    if not domain or not str(domain).strip():
        return []
    g=[]
    g.append(f"security@{domain}")
    g.append(f"abuse@{domain}")
    parts=domain.split(".")
    if len(parts)>2:
        apex=".".join(parts[-2:])
        g.append(f"security@{apex}")
        g.append(f"abuse@{apex}")
    return g

def score(has_sec_txt,has_whois,has_site,has_guess):
    s=0
    if has_sec_txt: s+=3
    if has_whois: s+=2
    if has_site: s+=1
    if has_guess: s+=0
    return s

if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No target provided. Please pass a domain.[/red]")
        sys.exit(1)
    raw=sys.argv[1]
    threads=sys.argv[2] if len(sys.argv)>2 else "1"
    fetch_site=parse_opts(sys.argv)
    domain=clean_domain_input(raw)
    if not domain:
        sys.exit(2)
    sec_txt_hits=get_security_txt(domain)
    sec_txt_contacts=[]
    for _,txt in sec_txt_hits:
        sec_txt_contacts.extend(parse_security_txt(txt))
    whois_contacts=get_whois_abuse(domain)
    site_contacts=[]
    site_links=[]
    if fetch_site:
        html=fetch_root_html(domain)
        site_links=discover_disclosure_links(html,domain)
        for l in site_links:
            if l.startswith("mailto:"):
                site_contacts.append(l[7:])
    guesses=best_guess_abuse(domain)
    all_contacts=[]
    for lst in (sec_txt_contacts,whois_contacts,site_contacts):
        for c in lst:
            if c not in all_contacts:
                all_contacts.append(c)
    rows=[]
    for c in all_contacts:
        srcs=[]
        if c in sec_txt_contacts: srcs.append("security.txt")
        if c in whois_contacts: srcs.append("whois")
        if c in site_contacts: srcs.append("site")
        rows.append((c,",".join(srcs)))
    if not rows:
        for g in guesses:
            rows.append((g,"guess"))
    tab=Table(title=f"Security Contact Gap Finder: {domain}",show_header=True,header_style="bold magenta")
    tab.add_column("Contact",style="cyan",overflow="fold")
    tab.add_column("Source",style="green")
    for r in rows:
        tab.add_row(*r)
    has_sec_txt=bool(sec_txt_contacts)
    has_whois=bool(whois_contacts)
    has_site=bool(site_links or site_contacts)
    sc=str(score(has_sec_txt,has_whois,has_site,True))
    console.print(tab)
    console.print(f"[white]Score:[/white] {sc}  (3=security.txt 2=whois 1=site)")
    if sec_txt_hits:
        console.print(f"[white]security.txt paths:[/white] {', '.join(x for x,_ in sec_txt_hits)}")
    if site_links:
        console.print(f"[white]disclosure links:[/white] {', '.join(site_links[:5])}")
    console.print("[white][*] Security contact gap analysis completed.[/white]")
