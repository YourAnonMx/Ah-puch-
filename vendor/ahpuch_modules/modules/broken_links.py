# modules/broken_links_detection.py
import os, sys, json, random, concurrent.futures, requests, urllib3, re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

def banner():
    console.print("[cyan]" + "="*40)
    console.print("[cyan]    Ah-Puch – Broken Links Detection")
    console.print("[cyan]" + "="*40)

def fetch(url, t):
    try:
        # Preserve the operator-supplied scheme/authority and do not follow a
        # redirect to an unrelated host during a broken-link assessment.
        r = requests.get(url, timeout=t, verify=True, allow_redirects=False)
        return r.status_code, r.text
    except requests.RequestException:
        return "ERR", ""

def extract_links(html, base):
    out = set()
    for a in BeautifulSoup(html, "html.parser").find_all("a", href=True):
        u = urljoin(base, a["href"]).split("#")[0]
        if urlparse(u).scheme in ("http", "https"):
            out.add(u)
    return out

def table_out(broken):
    tbl = Table(show_header=True, header_style="bold white")
    tbl.add_column("Broken Link", justify="left")
    for b in broken:
        tbl.add_row(b)
    console.print(tbl)

def run(target, threads, opts):
    banner()
    t = int(opts.get("timeout", DEFAULT_TIMEOUT))
    maxp = int(opts.get("max_pages", 200))
    ratio = float(opts.get("sample_ratio", 0.15))
    dom = clean_domain_input(target)
    parsed_target = urlparse(str(target).strip())
    root = (
        f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path or '/'}"
        if parsed_target.scheme in {"http", "https"} and parsed_target.netloc
        else f"https://{dom}"
    )
    authority = urlparse(root).netloc
    console.print(f"[white][*] Crawling up to [yellow]{maxp}[/yellow] pages on [cyan]{dom}")
    seen, queue, collected = {root}, [root], set()
    with Progress(SpinnerColumn(), TextColumn("Crawling…"), BarColumn(), console=console, transient=True) as p:
        task = p.add_task("", total=maxp)
        while queue and len(seen) < maxp:
            url = queue.pop(0)
            code, html = fetch(url, t)
            if code == "ERR" or not html:
                p.advance(task); continue
            for link in extract_links(html, url):
                collected.add(link)
                if link not in seen and urlparse(link).netloc == authority:
                    seen.add(link); queue.append(link)
            p.advance(task)
    console.print(f"[white][*] Total unique links collected: [cyan]{len(collected)}")
    sample_size = min(len(collected), max(5, int(len(collected)*ratio)))
    sample = random.sample(list(collected), sample_size) if sample_size else []
    broken = []
    with Progress(SpinnerColumn(), TextColumn("Validating…"), BarColumn(), console=console, transient=True) as p:
        task = p.add_task("", total=len(sample))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(requests.head, l, timeout=t, allow_redirects=False, verify=True): l for l in sample}
            for f in concurrent.futures.as_completed(futs):
                link = futs[f]
                ok = False
                try:
                    r = f.result()
                    ok = r.status_code < 400
                    if r.status_code in (405, 501):
                        ok = requests.get(link, timeout=t, verify=True, allow_redirects=False).status_code < 400
                except requests.RequestException:
                    pass
                if not ok:
                    broken.append(link)
                p.advance(task)
    console.print(f"[white][*] Broken links found: [red]{len(broken)}")
    if broken:
        table_out(broken)
    else:
        console.print("[green]No broken links detected")
    console.print("[green][*] Broken links detection completed")
    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out, "broken_links.txt"), "\n".join(broken))

if __name__ == "__main__":
    tgt = sys.argv[1]
    thr = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8
    opts = {}
    if len(sys.argv) > 3:
        try: opts = json.loads(sys.argv[3])
        except: pass
    run(tgt, thr, opts)
