#!/usr/bin/env python3
import os
import sys
import json
import re
import requests
import concurrent.futures
import urllib3
from urllib.parse import urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
TEAL = "#2EC4B6"

from ahpuch_modules.utils.util import clean_domain_input, ensure_directory_exists, write_to_file
from ahpuch_modules.config.settings import DEFAULT_TIMEOUT, RESULTS_DIR, EXPORT_SETTINGS

SIG_MAP = {
    "CanvasFingerprint":      r"(?:HTMLCanvasElement|OffscreenCanvas).*\.toDataURL\(",
    "WebGLFingerprint":       r"getContext\(\s*['\"](?:webgl|experimental-webgl)['\"]",
    "AudioFingerprint":       r"(?:AudioContext|webkitAudioContext)",
    "WebRTCLeak":             r"(?:RTCPeerConnection|webkitRTCPeerConnection)",
    "BatteryAPI":             r"\.getBattery\(",
    "DeviceMotion":           r"DeviceMotionEvent",
    "DeviceOrientation":      r"DeviceOrientationEvent",
    "DeviceMemory":           r"\bnavigator\.deviceMemory",
    "HardwareConcurrency":    r"\bnavigator\.hardwareConcurrency",
    "SpeechSynthesis":        r"\bspeechSynthesis\b",
    "Geolocation":            r"\bnavigator\.geolocation\b",
    "NetworkInformation":     r"navigator\.connection\.",
    "PersistentStorage":      r"navigator\.storage\.persist\(",
    "WebBluetooth":           r"\bnavigator\.bluetooth\b",
    "WebUSB":                 r"\bnavigator\.usb\b",
    "WebSerial":              r"\bnavigator\.serial\b",
    "GamepadAPI":             r"\bnavigator\.getGamepads",
    "IdleDetector":           r"\bIdleDetector\b",
    "ClipboardAPI":           r"navigator\.clipboard\.",
}

PAT_SCRIPT_SRC = re.compile(r"<script[^>]+src=['\"]([^'\"#]+)['\"]", re.I)

def banner():
    bar = "=" * 44
    console.print(f"[{TEAL}]{bar}")
    console.print("[cyan]     Ah-Puch – HTML5 Feature Abuse Detector")
    console.print(f"[{TEAL}]{bar}\n")

def fetch(url, timeout):
    target = str(url or "").strip()
    if not target:
        return "ERR", ""
    try:
        r = requests.get(target, timeout=timeout, verify=True, allow_redirects=False)
        return r.status_code, r.text
    except (requests.RequestException, OSError, ValueError):
        return "ERR", ""

def extract_scripts(html, base):
    seen = []
    for m in PAT_SCRIPT_SRC.finditer(html):
        full = urljoin(base, m.group(1).strip())
        if full not in seen:
            seen.append(full)
        if len(seen) >= 100:
            break
    return seen

def scan(text):
    hits = {}
    for name, rx in SIG_MAP.items():
        count = len(re.findall(rx, text, re.I))
        if count:
            hits[name] = count
    return hits

def run(target, threads, opts):
    banner()
    raw_target = str(target or "").strip()
    dom = clean_domain_input(raw_target)
    if not dom:
        console.print("[red]✖ No target provided.[/red]")
        return 2
    try:
        timeout = max(1, min(int(opts.get("timeout", DEFAULT_TIMEOUT)), 120))
        workers = max(1, min(int(threads), 64))
    except (TypeError, ValueError):
        console.print("[red]✖ Invalid HTML5 options.[/red]")
        return 2
    base    = f"https://{dom}"

    console.print(f"[white]* Fetching landing page for [cyan]{dom}[/cyan][/white]")
    code, html = fetch(base, timeout)
    if code == "ERR" or not html:
        console.print("[red]✖ Could not reach domain[/red]")
        return 1

    scripts = extract_scripts(html, base)
    console.print(f"[white]* Found [cyan]{len(scripts)}[/cyan] external scripts[/white]\n")

    payloads = [(base, html)]
    if scripts:
        with Progress(SpinnerColumn(), TextColumn("Downloading scripts…"), BarColumn(), console=console, transient=True) as pg:
            task = pg.add_task("", total=len(scripts))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                for content in pool.map(lambda u: fetch(u, timeout)[1], scripts):
                    payloads.append((None, content))
                    pg.advance(task)

    total_hits = {}
    detail     = []
    for src, txt in payloads:
        hits = scan(txt)
        detail.append((src or base, hits))
        for k, v in hits.items():
            total_hits[k] = total_hits.get(k, 0) + v

    if total_hits:
        tbl = Table(title=f"HTML5-API Signals – {dom}", header_style="bold white")
        tbl.add_column("Feature", style="cyan")
        tbl.add_column("Hits", style="green", justify="right")
        for k, v in sorted(total_hits.items(), key=lambda x: (-x[1], x[0])):
            tbl.add_row(k, str(v))
        console.print(tbl)

        det = Table(title="Per-Source Detail", header_style="bold white")
        det.add_column("Source", style="cyan", overflow="fold")
        det.add_column("Feature", style="green")
        det.add_column("Count", style="yellow", justify="right")
        for src, hits in detail:
            for feature, count in hits.items():
                det.add_row(src, feature, str(count))
        console.print(det)
    else:
        console.print("[yellow]No HTML5 API abuse patterns detected.[/yellow]")

    console.print("[green]* Feature-abuse scan completed[/green]\n")

    if EXPORT_SETTINGS.get("enable_txt_export"):
        out = os.path.join(RESULTS_DIR, dom)
        ensure_directory_exists(out)
        recorder = Console(record=True, width=console.width)
        if total_hits:
            recorder.print(tbl)
            recorder.print(det)
        text = recorder.export_text()
        write_to_file(os.path.join(out, "html5_feature_abuse.txt"), text)
    return 0

if __name__ == "__main__":
    tgt  = sys.argv[1]
    thr  = sys.argv[2] if len(sys.argv)>2 else "12"
    opts = json.loads(sys.argv[3]) if len(sys.argv)>3 else {}
    run(tgt, thr, opts)
