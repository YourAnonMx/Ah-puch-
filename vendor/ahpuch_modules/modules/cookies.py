#!/usr/bin/env python3
import os, sys, json, math, re, urllib.parse, urllib3, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, EXPORT_SETTINGS, RESULTS_DIR

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
TRACKER_RE = re.compile(r"(ga|gid|utm|fbp|gcl|mixpanel|_pk_)", re.I)
SESSION_RE = re.compile(r"(sess|token|auth|jwt|sid|php)", re.I)
SEVERITY_COLORS = {"high": "bold red", "medium": "yellow", "info": "cyan"}

def entropy(s):
    if not s:
        return 0.0
    l = len(s)
    freq = Counter(s)
    return -sum((c / l) * math.log2(c / l) for c in freq.values())

def build_path_list(base, timeout, extra_paths=None):
    paths = extra_paths[:] if extra_paths else []
    try:
        r = requests.get(urllib.parse.urljoin(base, "/robots.txt"), timeout=timeout, verify=True, headers={"User-Agent": UA})
        for line in r.text.splitlines():
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p and p != "/":
                    paths.append(p)
    except requests.RequestException:
        pass
    return ["/"] + sorted(set(paths))

def fetch_cookies(url, follow, timeout):
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.get(url, timeout=timeout, verify=True, allow_redirects=follow)
    return list(s.cookies)

def classify(name, value):
    if TRACKER_RE.search(name):
        return "Tracker"
    if SESSION_RE.search(name):
        return "SessionToken"
    if entropy(value) > 3.5 and len(value) > 15:
        return "RandomID"
    return "Other"

def flag_issues(c, base_domain):
    issues = []
    if not c.secure:
        issues.append(("medium", "missing Secure"))
    if not c.has_nonstandard_attr("HttpOnly"):
        issues.append(("medium", "missing HttpOnly"))
    ss = c.get_nonstandard_attr("SameSite") or "-"
    if ss.lower() not in ("lax", "strict", "none"):
        issues.append(("info", f"SameSite={ss}"))
    if ss.lower() == "none" and not c.secure:
        issues.append(("high", "SameSite=None without Secure"))
    if len(c.value or "") > 4096:
        issues.append(("info", f"large value {len(c.value)}"))
    dom = c.domain.lstrip(".").rstrip(".").lower()
    base = base_domain.lstrip(".").rstrip(".").lower()
    if dom != base and not dom.endswith("." + base):
        issues.append(("high", f"third-party {dom}"))
    return issues

def analyse(url, cookies, base_domain):
    rows, findings = [], []
    for ck in cookies:
        ctype = classify(ck.name, ck.value or "")
        for sev, msg in flag_issues(ck, base_domain):
            findings.append((sev, f"{ck.name}: {msg}"))
        rows.append({
            "Name": ck.name,
            "Type": ctype,
            "Len": len(ck.value or ""),
            "Ent": f"{entropy(ck.value or ''):.2f}",
            "Domain": ck.domain.lstrip("."),
            "Path": ck.path or "/",
            "Secure": ck.secure,
            "HttpOnly": ck.has_nonstandard_attr("HttpOnly"),
            "SameSite": ck.get_nonstandard_attr("SameSite") or "-",
            "Expire": datetime.fromtimestamp(ck.expires, timezone.utc).isoformat() if ck.expires else "-",
        })
    return rows, findings

def render_table(rows, url):
    tbl = Table(title=f"Cookies -> {url}", header_style="bold white", box=None)
    for h in ("Name", "Type", "Len", "Ent", "Domain", "Path", "Secure", "HttpOnly", "SameSite", "Expire"):
        tbl.add_column(h, overflow="fold", style="cyan" if h in ("Name", "Domain") else "white")
    for r in rows:
        tbl.add_row(
            r["Name"], r["Type"], str(r["Len"]), r["Ent"], r["Domain"], r["Path"],
            "[green]Y[/]" if r["Secure"] else "[red]N[/]",
            "[green]Y[/]" if r["HttpOnly"] else "[red]N[/]",
            r["SameSite"], r["Expire"]
        )
    console.print(tbl)

def render_findings(findings):
    if not findings:
        console.print("[green]No issues found[/]")
        return
    cargo = defaultdict(list)
    for sev, msg in findings:
        cargo[sev].append(msg)
    for sev, msgs in cargo.items():
        console.print(Panel("\n".join(msgs), title=f"{sev.upper()} ({len(msgs)})", style=SEVERITY_COLORS[sev]))

def dump_to_disk(target, results):
    if not EXPORT_SETTINGS.get("enable_txt_export"):
        return
    odir = os.path.join(RESULTS_DIR, clean_domain_input(target))
    ensure_directory_exists(odir)
    write_to_file(os.path.join(odir, "cookie_analysis.json"), json.dumps(results, indent=2, ensure_ascii=False))

def main():
    if len(sys.argv) < 3:
        console.print("Usage: <target> <threads> [json-opts]")
        sys.exit(1)
    target_raw = sys.argv[1]
    threads = int(sys.argv[2])
    opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    target_dom = clean_domain_input(target_raw)
    base_url = target_raw if target_raw.startswith(("http://", "https://")) else f"https://{target_dom}"
    timeout = int(opts.get("timeout", DEFAULT_TIMEOUT))
    follow_redir = bool(int(opts.get("follow", 0)))
    extra_paths = opts.get("paths", [])
    urls = [urllib.parse.urljoin(base_url, p) for p in build_path_list(base_url, timeout, extra_paths)]
    console.print(f"Hitting {len(urls)} paths with {threads} threads...")
    aggregated, cache = [], []
    with Progress(SpinnerColumn(), TextColumn("{task.fields[url]}"), BarColumn(), console=console, transient=True) as prog:
        t = prog.add_task("", total=len(urls), url="")
        with ThreadPoolExecutor(max_workers=threads) as pool:
            fut_map = {pool.submit(fetch_cookies, u, follow_redir, timeout): u for u in urls}
            for fut in as_completed(fut_map):
                u = fut_map[fut]
                prog.update(t, advance=1, url=u)
                try:
                    cookies = fut.result()
                except Exception as e:
                    console.print(f"error: {u} -> {e}")
                    continue
                rows, findings = analyse(u, cookies, target_dom)
                aggregated.append({"url": u, "cookies": rows, "findings": findings})
                render_table(rows, u)
                render_findings(findings)
                cache.extend(findings)
    high = sum(1 for s, _ in cache if s == "high")
    med = sum(1 for s, _ in cache if s == "medium")
    info = sum(1 for s, _ in cache if s == "info")
    console.print(Panel(f"Scanned {len(aggregated)} URLs | {sum(len(a['cookies']) for a in aggregated)} cookies\nIssues high:{high} / medium:{med} / info:{info}", title="SUMMARY", style="bold white"))
    dump_to_disk(target_raw, aggregated)

if __name__ == "__main__":
    main()
