#!/usr/bin/env python3
import os, sys, json, time, random, concurrent.futures, requests, urllib3
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from colorama import Fore, Style, init
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
console = Console()

def banner():
    console.print(f"""
{Fore.GREEN}=============================================
          Ah-Puch - Directory Finder
============================================={Style.RESET_ALL}
""")

def load_wordlist(path):
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [w.strip() for w in f if w.strip()]
    return ["admin","login","uploads","api","backup","test","old","dev"]

def probe(url, timeout, wanted):
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, verify=True)
        if r.status_code in wanted:
            size = r.headers.get("Content-Length","-")
            redir = r.headers.get("Location","-")
            return url, r.status_code, size, redir
    except:
        pass
    return None

def run(target, threads, opts):
    banner()
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    wl_path = opts.get("wordlist", "")
    wanted = set(map(int, opts.get("status_keep","200,301,302,403").split(",")))
    words = load_wordlist(wl_path)
    dom = clean_domain_input(target)
    base = f"https://{dom}/"
    console.print(f"{Fore.WHITE}[*] Target: {base}{Style.RESET_ALL}")
    console.print(f"{Fore.WHITE}[*] Wordlist size: {len(words)} | Threads: {threads}{Style.RESET_ALL}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = [pool.submit(probe, urljoin(base,w), timeout, wanted) for w in words]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r: results.append(r)

    table = Table(show_header=True, header_style="bold white")
    for h in ("Path","Status","Bytes","Redirect"): table.add_column(h)
    for row in sorted(results, key=lambda x: x[0]): table.add_row(*map(str,row))
    console.print(table)
    console.print(f"{Fore.CYAN}[*] Total hits: {len(results)}{Style.RESET_ALL}")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, dom); ensure_directory_exists(out)
        write_to_file(os.path.join(out,"directory_finder.txt"),
                      "\n".join("\t".join(map(str,r)) for r in results))

if __name__=="__main__":
    tgt=sys.argv[1]; thr=int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 8
    opts=json.loads(sys.argv[3]) if len(sys.argv)>3 else {}
    run(tgt,thr,opts)
