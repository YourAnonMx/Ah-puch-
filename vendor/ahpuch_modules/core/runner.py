import os, sys, json, subprocess, time, re, contextlib, signal
from dataclasses import dataclass
from typing import Dict, List, Tuple
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from ahpuch_modules.utils.report_generator import generate_report
from ahpuch_modules.utils.util import clean_domain_input
from ahpuch_modules.core.catalog_cache import (
    tools_mapping,
)
from ahpuch_modules.core.invocation import build_module_command

console = Console()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "modules")

SEVERITY_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bcritical\b|\bsevere\b|\bexploit\b|\bcompromise\b", re.I), "ALERT"),
    (re.compile(r"\bhigh\b|\balert\b|\bvulnerable\b|\bexpired\b", re.I), "ALERT"),
    (re.compile(r"\bwarn\b|\bwarning\b|\brisk\b|\bexposed\b", re.I), "WARN"),
    (re.compile(r"\bok\b|\bsecure\b|\bvalid\b", re.I), "OK"),
]

@dataclass
class ScriptResult:
    output: str
    error: str
    exit_code: int
    timed_out: bool
    duration: float
    status: str

    def __bool__(self) -> bool:
        return bool(self.output or self.error or self.exit_code != 0)


def execute_script(script_name: str, target: str, threads: int = 1, module_opts: Dict | None = None, show_status: bool = True, quiet: bool = False, timeout: int = 60) -> ScriptResult:
    script_path = os.path.join(MODULES_DIR, script_name)
    started = time.monotonic()
    if not os.path.isfile(script_path):
        console.print(f"[bold red]Missing script {script_name}[/bold red]")
        return ScriptResult("", f"missing script: {script_name}\n", 127, False, 0.0, "failed")
    ctx = console.status(f"[bold green]Running {script_name}[/bold green]", spinner="dots") if show_status else contextlib.nullcontext()
    with ctx:
        cmd = build_module_command(script_name, target, threads, module_opts or {})
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        timed_out = False
        try:
            out, err = proc.communicate(timeout=max(1, int(timeout)))
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                out, err = proc.communicate(timeout=5)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
                out, err = proc.communicate()
            rc = 124
            out = out or (exc.stdout or "")
            err = err or (exc.stderr or "")
        else:
            rc = proc.returncode
        out = out or ""
        err = err or ""
        if not quiet:
            for line in out.splitlines():
                console.print(line)
            for line in err.splitlines():
                console.print(line, style="red")
        if rc and not quiet:
            console.print(f"[bold red]Script {script_name} exited {rc}[/bold red]")
    status = "timeout" if timed_out else ("success" if rc == 0 else "failed")
    return ScriptResult(out, err, rc, timed_out, time.monotonic() - started, status)

def parse_output_severity(text: str) -> str:
    sev = "INFO"
    for rx, label in SEVERITY_PATTERNS:
        if rx.search(text):
            if label == "ALERT":
                return "ALERT"
            if label == "WARN" and sev not in ("ALERT", "WARN"):
                sev = "WARN"
            if label == "OK" and sev == "INFO":
                sev = "OK"
    return sev

def run_modules(mod_ids: List[str], api_status: Dict[str, bool], target: str, threads: int, mode_name: str, cli_ctx) -> None:
    data: Dict[str, str] = {}
    runtimes: List[Tuple[str, str, float]] = []
    total = len(mod_ids)
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.fields[module]}"),
        BarColumn(bar_width=None),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("run", total=total, module="…")
        for mid in mod_ids:
            start = time.time()
            tool = tools_mapping.get(mid)
            name = tool["name"] if tool else mid
            prog.update(task, module=name)
            if tool and tool["script"]:
                allow = [o.replace("-", "_").lower() for o in (tool.get("options_meta") or [])]
                merged = _merge_options(cli_ctx.global_option_overrides, cli_ctx.module_options.get(mid), allow) if cli_ctx else {}
                result = execute_script(tool["script"], target, threads, merged, show_status=False, quiet=getattr(cli_ctx, "quiet_mode", False))
                if cli_ctx:
                    cli_ctx._record_recent(mid)
                if result:
                    data[name] = result.output or result.error
                    sev = "ALERT" if result.status != "success" else parse_output_severity(result.output)
                    runtimes.append((name, sev, result.duration))
            prog.advance(task)
    tag = mode_name if mode_name else "multi"
    generate_report(data, target, [tag])
    if cli_ctx:
        cli_ctx.last_run_outputs = data
        cli_ctx.last_run_runtimes = runtimes

def _merge_options(global_over: Dict | None, module_opts: Dict | None, allowed: List[str]) -> Dict:
    combined: Dict = {}
    if global_over:
        for k, v in global_over.items():
            if k in allowed and k not in combined:
                combined[k] = _coerce_option(k, v)
    if module_opts:
        combined.update({key: _coerce_option(key, value) for key, value in module_opts.items()})
    return combined


BOOLEAN_OPTION_NAMES = {"check_subdomains", "follow", "include_subdomains", "include_subs", "verify_ssl", "follow_redirects", "export_txt", "json", "log", "include_wildcard", "verify"}


def _coerce_option(key: str, value):
    if not isinstance(value, str):
        return value
    lowered = value.strip().lower()
    if key in BOOLEAN_OPTION_NAMES and lowered in {"0", "1", "true", "false", "yes", "no"}:
        return lowered in {"1", "true", "yes"}
    if re.fullmatch(r"-?\d+", value.strip()) and key not in {"port", "paths", "selectors", "types", "status_filter"}:
        return int(value)
    return value
