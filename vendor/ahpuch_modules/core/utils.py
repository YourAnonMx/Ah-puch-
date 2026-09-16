from rich.console import Console
import logging, pathlib, os, json, sys, subprocess, requests, importlib.metadata as _meta
from multiprocessing import cpu_count
try:
    from slugify import slugify as _slugify
except ImportError:
    def _slugify(text):
        return "".join(c if c.isalnum() else "_" for c in text)


DEFAULT_THREAD_CAP = min(32, cpu_count() * 5)

def banner():
    console.rule("[bold cyan]Ah-Puch – Recon Swiss‑Army Knife", style="cyan")

def safe_filename(name: str) -> str:
    return _slugify(name)

from rich.theme import Theme
THEMES = {
    "default": None,
    "blueprint": Theme({
        "info": "cyan",
        "warning": "bright_yellow",
        "danger": "bright_red",
        "success": "bright_green"
    })
}

def make_console(theme_name="default", log_file=None, quiet=False):
    chosen = THEMES.get(theme_name, None)
    log_level = logging.INFO if quiet else logging.DEBUG
    if log_file:
        logging.basicConfig(filename=log_file, level=log_level, format="%(asctime)s %(levelname)s %(message)s")
    else:
        logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
    return Console(theme=chosen, quiet=quiet)
_DISABLED_FILE = pathlib.Path.home() / ".ah_puch_disabled"

def load_disabled():
    if _DISABLED_FILE.exists():
        return set(json.loads(_DISABLED_FILE.read_text()))
    return set()

def disable_module(module_id):
    disabled = load_disabled()
    disabled.add(module_id)
    _DISABLED_FILE.write_text(json.dumps(list(disabled)))

def enable_module(module_id):
    disabled = load_disabled()
    disabled.discard(module_id)
    _DISABLED_FILE.write_text(json.dumps(list(disabled)))
def check_updates(current_version: str, repo="p3pperpot/ahpuch_modules"):
    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            latest = resp.json().get("tag_name", "")
            if latest and latest != current_version:
                console.print(f"[yellow]⚠ New version available: {latest}[/]")
    except Exception:
        pass

console = make_console(os.getenv("AH_PUCH_THEME", "default"))
