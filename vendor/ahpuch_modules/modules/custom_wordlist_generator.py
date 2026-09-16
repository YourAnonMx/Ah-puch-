import os
import sys
import re
import requests
from urllib.parse import urljoin, urlparse
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from colorama import init
from ahpuch_modules.utils.util import clean_domain_input, validate_domain
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
init(autoreset=True)
console = Console()
TOK_SPLIT = re.compile(r"[^a-zA-Z0-9_-]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
def banner():
    console.print("""
    =============================================
      Ah-Puch - Custom Wordlist Generator
    =============================================
    """)
def fetch(url):
    if not url or not str(url).strip():
        return "ERR", "", url
    try:
        r=requests.get(url,timeout=DEFAULT_TIMEOUT,verify=True,allow_redirects=False)
        return r.status_code,r.text,r.url
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return "ERR","",url
def grab_root(domain):
    if not domain or not str(domain).strip():
        return None,""
    for scheme in ("https","http"):
        u=f"{scheme}://{domain}"
        code,txt,final=fetch(u)
        if code!="ERR":
            return final,txt
    return None,""
def grab_robots(base):
    if not base or not str(base).strip():
        return ""
    u=urljoin(base,"/robots.txt")
    code,txt,_=fetch(u)
    return txt if code==200 else ""
def grab_sitemap(base):
    if not base or not str(base).strip():
        return ""
    u=urljoin(base,"/sitemap.xml")
    code,txt,_=fetch(u)
    return txt if code==200 else ""
def tokens_from_text(text):
    if not isinstance(text, str):
        return []
    toks=[t.lower() for t in TOK_SPLIT.split(text) if 3<=len(t)<=32]
    return toks
def paths_from_robots(txt):
    if not isinstance(txt, str):
        return []
    out=[]
    for line in txt.splitlines():
        line=line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("disallow:") or line.lower().startswith("allow:") or line.lower().startswith("sitemap:"):
            parts=line.split(":",1)
            if len(parts)==2:
                seg=parts[1].strip()
                if seg.startswith("http"):
                    seg=urlparse(seg).path
                out.extend([p for p in TOK_SPLIT.split(seg) if p])
    return out
def paths_from_sitemap(txt):
    if not isinstance(txt, str):
        return []
    out=[]
    for m in re.finditer(r"<loc>(.*?)</loc>",txt,re.I):
        loc=m.group(1).strip()
        path=urlparse(loc).path
        out.extend([p for p in TOK_SPLIT.split(path) if p])
    return out
def emails_from_text(text,domain):
    if not isinstance(text, str) or not domain:
        return []
    out=[]
    for m in EMAIL_RE.finditer(text):
        dom=m.group(1).lower()
        if domain in dom:
            user=text[m.start():m.end()].split("@")[0]
            out.append(user)
    return out
def generate(domain,seed_words=None):
    if not domain or not str(domain).strip():
        return [],[]
    base,root_html=grab_root(domain)
    robots_txt=grab_robots(base) if base else ""
    sitemap_xml=grab_sitemap(base) if base else ""
    words=[]
    if seed_words:
        words.extend(seed_words)
    if root_html:
        words.extend(tokens_from_text(root_html))
        words.extend(emails_from_text(root_html,domain))
    if robots_txt:
        words.extend(paths_from_robots(robots_txt))
    if sitemap_xml:
        words.extend(paths_from_sitemap(sitemap_xml))
    words=[w for w in words if w and len(w)<=40]
    counts=Counter(words)
    uniq=sorted(counts,key=counts.get,reverse=True)
    prefixes=set()
    parts=domain.split(".")
    prefixes.add(parts[0])
    for w in uniq[:500]:
        if w not in prefixes and w.isalpha() and 2<len(w)<20:
            prefixes.add(w)
    return uniq[:1000],sorted(prefixes)
def save_lists(prefix,words,prefixes):
    if not prefix:
        return None,None
    wl_path=prefix+"_words.txt"
    pf_path=prefix+"_prefixes.txt"
    try:
        with open(wl_path,"w",encoding="utf-8") as f:
            for w in words:
                f.write(w+"\n")
    except (OSError, TypeError, ValueError):
        wl_path=None
    try:
        with open(pf_path,"w",encoding="utf-8") as f:
            for p in prefixes:
                f.write(p+"\n")
    except (OSError, TypeError, ValueError):
        pf_path=None
    return wl_path,pf_path
if __name__=="__main__":
    banner()
    if len(sys.argv)<2:
        console.print("[red][!] Usage: custom_wordlist_generator.py <domain> [seedfile] [outprefix][/red]")
        sys.exit(1)
    domain=clean_domain_input(sys.argv[1])
    if not domain:
        sys.exit(2)
    seed=None
    if len(sys.argv)>2 and os.path.isfile(sys.argv[2]):
        try:
            with open(sys.argv[2],"r",encoding="utf-8",errors="ignore") as f:
                seed=[l.strip() for l in f if l.strip()]
        except:
            seed=None
    words,prefixes=generate(domain,seed_words=seed)
    outpref=sys.argv[3] if len(sys.argv)>3 else None
    wl_path,pf_path=save_lists(outpref,words,prefixes)
    table=Table(title=f"Generated Wordlists: {domain}",show_header=True,header_style="bold magenta")
    table.add_column("Type",style="cyan")
    table.add_column("Count",style="green")
    table.add_column("Saved",style="yellow",overflow="fold")
    table.add_row("Words",str(len(words)),wl_path or "-")
    table.add_row("Prefixes/Subs",str(len(prefixes)),pf_path or "-")
    console.print(table)
    console.print("[white][*] Custom wordlist generation completed.[/white]")
