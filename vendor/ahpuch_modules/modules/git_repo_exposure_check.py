#!/usr/bin/env python3
import os, sys, json, requests, urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console(); TEAL = "#2EC4B6"

DOT_GIT_PATHS = (
    "/.git/HEAD",
    "/.git/config",
    "/.git/index",
    "/.git/packed-refs",
    "/.git/description",
    "/.git/info/refs",
    "/.git/info/exclude",
    "/.git/logs/HEAD",
    "/.git/logs/refs/heads/master",
    "/.git/logs/refs/heads/main",
    "/.git/objects/info/packs",
    "/.git/objects/pack/pack-.pack",
    "/.git/objects/pack/pack-.idx",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/refs/stash",
    "/.git/refs/remotes/origin/HEAD",
    "/.git/refs/remotes/origin/master",
    "/.git/refs/remotes/origin/main",
    "/.git/ORIG_HEAD",
    "/.git/FETCH_HEAD",
    "/.git/COMMIT_EDITMSG",
    "/.git/refs/tags/latest",
    "/.git/hooks/pre-commit.sample",
    "/.git/hooks/post-update.sample",
    "/.git/hooks/pre-rebase.sample",
    "/.git/hooks/pre-receive.sample",
    "/.git/hooks/update.sample",
    "/.gitignore",
    "/.gitmodules",
    "/.git/rr-cache",
    "/.git/svn/refs/heads/master",
    "/.git/svn/refs/remotes/origin/trunk",
    "/.git/branches",
    "/.git/refs/heads/develop",
    "/.git/refs/heads/release",
    "/.git/refs/heads/production",
    "/.git/refs/heads/staging",
    "/.git/refs/heads/hotfix",
    "/.git/refs/remotes/origin/develop"
)

def banner():
    bar = "="*44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]   Ah-Puch – Git Repository Exposure Check")
    console.print(f"[{TEAL}]{bar}")

def probe(url, t):
    try:
        r = requests.get(url, timeout=t, verify=True, allow_redirects=False)
        return r.status_code, len(r.content)
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        return "ERR", 0

def run(target, threads, opts):
    banner()
    if not target or not str(target).strip():
        return 2
    opts = opts if isinstance(opts, dict) else {}
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 60))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    try:
        threads = max(1, min(int(threads), 32))
    except (TypeError, ValueError):
        threads = 1
    dom     = clean_domain_input(target)
    if not dom:
        return 2
    base    = f"https://{dom}"
    console.print(f"[white]* Probing {len(DOT_GIT_PATHS)} .git artefact paths on [cyan]{dom}[/cyan][/white]")

    rows = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(probe, base+p, timeout): p for p in DOT_GIT_PATHS}
        for f in as_completed(futs):
            p            = futs[f]
            code, size   = f.result()
            exposed_flag = "Yes" if isinstance(code,int) and code < 400 and size > 0 else "-"
            rows.append((p, str(code), str(size), exposed_flag))

    try:
        rdir = requests.get(base+"/.git/", timeout=timeout, verify=True, allow_redirects=False)
        if rdir.status_code == 200 and b"Index of" in rdir.content:
            rows.append(("/.git/ (listing)","200",str(len(rdir.content)),"Index"))
    except (AttributeError, OSError, requests.exceptions.RequestException, TypeError, ValueError):
        pass

    tbl = Table(title=f".git Exposure – {dom}", header_style="bold white")
    for h in ("Path","Status","Bytes","Exposed?"): tbl.add_column(h, overflow="fold")
    for r in rows: tbl.add_row(*r)
    console.print(tbl)
    console.print("[green]* Git repo exposure check completed[/green]")

    if EXPORT_SETTINGS["enable_txt_export"]:
        out = os.path.join(RESULTS_DIR, dom); ensure_directory_exists(out)
        export_console = Console(record=True, width=160)
        export_console.print(tbl)
        write_to_file(os.path.join(out, "git_exposure.txt"), export_console.export_text())
    return 0 if any(str(row[1]).isdigit() for row in rows) else 1

if __name__ == "__main__":
    tgt  = sys.argv[1]
    thr  = int(sys.argv[2]) if len(sys.argv)>2 and sys.argv[2].isdigit() else 12
    opts = {}
    if len(sys.argv)>3:
        try: opts = json.loads(sys.argv[3])
        except (TypeError, ValueError): pass
    raise SystemExit(run(tgt, thr, opts))
