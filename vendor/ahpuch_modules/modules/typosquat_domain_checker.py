import os
import sys
import socket
import dns.resolver
from itertools import product
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init
from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
init(autoreset=True)
console = Console()
tld_swaps = ["com","net","org","co","io","ai","app","dev","info","biz","online","co.uk","de","fr","es","it","nl","ca"]
glyph_map = {
    "a":["a","4","@",],
    "b":["b","8"],
    "c":["c","k","s"],
    "d":["d"],
    "e":["e","3"],
    "f":["f"],
    "g":["g","9"],
    "h":["h"],
    "i":["i","1","l","!"],
    "j":["j"],
    "k":["k","c"],
    "l":["l","1","i"],
    "m":["m","rn"],
    "n":["n"],
    "o":["o","0"],
    "p":["p"],
    "q":["q"],
    "r":["r"],
    "s":["s","5","z"],
    "t":["t","7"],
    "u":["u","v"],
    "v":["v","u"],
    "w":["w","vv"],
    "x":["x"],
    "y":["y"],
    "z":["z","2"],
    "-":["","-"]
}
def banner():
    console.print("""
    =============================================
     Ah-Puch - Typosquat Domain Checker
    =============================================
    """)
def levenshtein(a,b):
    la,lb=len(a),len(b)
    if la>lb:
        a,b=b,a
        la,lb=lb,la
    prev=list(range(la+1))
    for i,c in enumerate(b,1):
        cur=[i]
        for j,d in enumerate(a,1):
            ins=prev[j]+1
            dele=cur[j-1]+1
            sub=prev[j-1]+(c!=d)
            cur.append(min(ins,dele,sub))
        prev=cur
    return prev[-1]
def gen_bitsquats(s):
    out=[]
    for i,ch in enumerate(s):
        for rep in glyph_map.get(ch.lower(),[ch]):
            if rep!=ch:
                out.append(s[:i]+rep+s[i+1:])
    return out
def gen_deletions(s):
    return [s[:i]+s[i+1:] for i in range(len(s))]
def gen_insertions(s):
    out=[]
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-"
    for i in range(len(s)+1):
        for ch in alphabet:
            out.append(s[:i]+ch+s[i:])
    return out
def gen_transpose(s):
    out=[]
    for i in range(len(s)-1):
        out.append(s[:i]+s[i+1]+s[i]+s[i+2:])
    return out
def gen_homoglyph(s):
    pools=[glyph_map.get(c.lower(),[c]) for c in s]
    combos=[]
    for tup in product(*pools):
        combos.append("".join(tup))
        if len(combos)>200:
            break
    return combos
def uniq_limited(seq,limit=300):
    seen=[]
    for x in seq:
        if x and x not in seen and len(seen)<limit:
            seen.append(x)
    return seen
def split_domain(domain):
    parts=domain.split(".")
    if len(parts)<2:
        return domain,""
    sld=".".join(parts[:-1])
    tld=parts[-1]
    if len(parts)>2 and parts[-2] in ("co","com","net","org"):
        sld=".".join(parts[:-2])
        tld=".".join(parts[-2:])
    return sld,tld
def build_domains(domain):
    sld,tld=split_domain(domain)
    cand=[]
    cand.extend(gen_bitsquats(sld))
    cand.extend(gen_deletions(sld))
    cand.extend(gen_transpose(sld))
    cand.extend(gen_homoglyph(sld))
    cand=[c for c in cand if c and c!=sld]
    out=[]
    for c in cand:
        out.append(c+"."+tld)
    for t in tld_swaps:
        out.append(sld+"."+t)
    out=uniq_limited(out,limit=500)
    return out
def resolve_host(host):
    if not host or not str(host).strip():
        return False,False,"-"
    a=False
    mx=False
    ip="-"
    try:
        ans=dns.resolver.resolve(host,"A",lifetime=DEFAULT_TIMEOUT)
        ips=[r.address for r in ans]
        if ips:
            a=True
            ip=",".join(ips[:3])
    except (dns.exception.DNSException, OSError, TypeError, ValueError):
        pass
    try:
        ans=dns.resolver.resolve(host,"MX",lifetime=DEFAULT_TIMEOUT)
        prefs=[str(r.exchange).rstrip(".") for r in ans]
        if prefs:
            mx=True
    except (dns.exception.DNSException, OSError, TypeError, ValueError):
        pass
    return a,mx,ip
if __name__ == "__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] No domain provided.[/red]")
        sys.exit(1)
    domain=clean_domain_input(sys.argv[1])
    candidates=build_domains(domain)
    console.print(f"[white][*] Generated {len(candidates)} candidate domains[/white]")
    rows=[]
    progress=Progress(SpinnerColumn(),TextColumn("{task.description}"),BarColumn(),console=console,transient=True)
    with progress:
        task=progress.add_task("Resolving",total=len(candidates))
        for cd in candidates:
            a,mx,ip=resolve_host(cd)
            dist=levenshtein(cd,domain)
            cat="Resolved" if a else "NX"
            rows.append((cd,str(dist),"Y" if a else "N","Y" if mx else "N",ip,cat))
            progress.advance(task)
    table=Table(title=f"Typosquat Candidates: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("Domain",style="cyan",overflow="fold")
    table.add_column("Dist",style="green")
    table.add_column("A",style="yellow")
    table.add_column("MX",style="white")
    table.add_column("IP",style="blue",overflow="fold")
    table.add_column("Cat",style="magenta")
    for r in rows:
        table.add_row(*r)
    console.print(table if rows else "[yellow][!] No candidates.[/yellow]")
    console.print("[white][*] Typosquat domain check completed.[/white]")
