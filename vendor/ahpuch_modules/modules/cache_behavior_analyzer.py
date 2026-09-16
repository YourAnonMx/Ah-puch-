#!/usr/bin/env python3
import os, sys, json, re, uuid, random, concurrent.futures, requests, urllib3
from urllib.parse import urljoin, urlsplit, urlencode, parse_qsl
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

def banner():
    console.print("[cyan]" + "="*44)
    console.print("[cyan]   Ah-Puch – Cache Behavior Analyzer")
    console.print("[cyan]" + "="*44)

def bust(url):
    p = urlsplit(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q["_ah_puch"] = uuid.uuid4().hex[:6]
    return p._replace(query=urlencode(q)).geturl()

def fetch(url, hdr, t):
    if not str(url or "").strip():
        return "ERR","-","-",0
    try:
        r = requests.get(url, timeout=t, headers=hdr, verify=True, allow_redirects=False)
        size = int(r.headers.get("Content-Length", len(r.content)))
        return r.status_code, r.headers.get("Cache-Control","-"), r.headers.get("Age","-"), size
    except (requests.RequestException, OSError, ValueError):
        return "ERR","-","-",0

def analyze(url, t):
    base  = fetch(url, {}, t)
    noc   = fetch(url, {"Cache-Control":"no-cache"}, t)
    bustd = fetch(bust(url), {}, t)
    diff  = "Y" if len({base[3], noc[3], bustd[3]}) > 1 else "-"
    cach  = "Y" if "no-cache" not in base[1].lower() and "private" not in base[1].lower() else "-"
    return (url, base[0], base[1], base[2], base[3], cach, diff)

def crawl(seed, limit, t):
    if not str(seed or "").strip() or limit <= 0:
        return []
    q=[seed]; seen={seed}
    idx=0
    while idx<len(q) and len(seen)<limit:
        try:
            html=requests.get(q[idx],timeout=t,verify=True,allow_redirects=False).text
            for u in re.findall(r'href=["\']([^"\'#]+)',html):
                u=urljoin(q[idx],u)
                if u.startswith("http") and u not in seen:
                    seen.add(u); q.append(u)
        except (requests.RequestException, OSError, ValueError): pass
        idx+=1
    return list(seen)

def table_out(rows):
    tbl=Table(show_header=True,header_style="bold white")
    for h in ["URL","Code","Cache-Control","Age","Bytes","Cacheable?","Size Diff?"]:
        tbl.add_column(h,justify="left",no_wrap=True)
    for r in rows:
        tbl.add_row(*[str(x) for x in r])
    console.print(tbl)

def run(target, threads, opts):
    banner()
    dom=clean_domain_input(str(target or ""))
    if not dom:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        t=max(1,min(int(opts.get("timeout",DEFAULT_TIMEOUT)),120))
        pages=max(1,min(int(opts.get("max_pages",60)),500))
        ratio=max(0.0,min(float(opts.get("sample_ratio",0.25)),1.0))
        workers=max(1,min(int(threads),64))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid cache-analyzer options.[/red]")
        return 2
    seed=f"https://{dom}"
    console.print(f"[white][*] Crawling up to [yellow]{pages}[/yellow] pages on [cyan]{dom}")
    urls=crawl(seed,pages,t)
    sample_count=min(len(urls),max(1,int(len(urls)*ratio))) if urls else 0
    sample=random.sample(urls,sample_count) if sample_count else []
    console.print(f"[white][*] Analyzing [green]{len(sample)}[/green] URLs")
    rows=[]
    with Progress(SpinnerColumn(),TextColumn("Analyzing..."),BarColumn(),console=console,transient=True) as pg:
        task=pg.add_task("",total=len(sample))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for res in pool.map(lambda u: analyze(u,t),sample):
                rows.append(res); pg.advance(task)
    table_out(rows)
    console.print("[green][*] Cache behavior analysis completed")
    if EXPORT_SETTINGS["enable_txt_export"]:
        out=os.path.join(RESULTS_DIR,dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out,"cache_behavior.txt"),
                      "\n".join("\t".join(map(str,r)) for r in rows))
    return 0

if __name__=="__main__":
    tgt=sys.argv[1]
    thr=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 6
    opts={}
    if len(sys.argv)>3:
        try: opts=json.loads(sys.argv[3])
        except (TypeError, ValueError): pass
    run(tgt,thr,opts)
