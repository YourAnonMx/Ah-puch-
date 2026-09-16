#!/usr/bin/env python3
"""Canonical Phase-2 catalog/menu surface for Ah-Puch.

The execution engine remains ``runtime.py``/``runner.py``.  This module only
normalizes the public catalog and interactive UX before the production entry
calls that engine.  It deliberately distinguishes mapping/dispatch from E2E
selector completion evidence.
"""
from __future__ import annotations

import argparse
import builtins
import json
import shlex
from pathlib import Path
from typing import Any

_BASE: Any = None

FAMILY_SELECTOR_MENU = {
    "135": "network",
    "136": "web",
    "137": "threat",
    "138": "all",
}
LOCAL_SELECTOR_IDS = {"155", "170", "171", "177"}


def input(prompt: str = "") -> str:
    """Read one menu answer and exit cleanly when stdin is closed."""
    try:
        return builtins.input(prompt)
    except EOFError:
        print()
        raise SystemExit(0) from None


class InteractiveCLIRequest(RuntimeError):
    """Translate an interactive choice back into the canonical CLI parser."""

    def __init__(self, argv: list[str]):
        super().__init__("interactive CLI request")
        self.argv = argv


def _base() -> Any:
    if _BASE is None:
        raise RuntimeError("catalog_frontend.install(base) must run before use")
    return _BASE


def _activity_class(section: str, item: dict[str, Any], execution_kind: str) -> str:
    """Classify activity from explicit catalog facts, never from display names."""
    base = _base()
    if execution_kind == "family-selector":
        return "family-selector"
    if execution_kind == "native-selector":
        return "native-selector"
    script = str(item.get("script", ""))
    if script in getattr(base, "EXPLICIT_ONLY_NAMES", set()):
        return "explicit-only"
    if script in base.ACTIVE_NAMES:
        return "active-explicit"
    if script in base.API_ENV_BY_SCRIPT:
        return "optional-api"
    # Unknown web behavior is conservative: explicit selection or Full/Deep.
    # Baseline no longer depends on words such as checker/analyzer in a label.
    if section == "web_application_analysis":
        return "explicit-only"
    return "automatic-passive"


def _menu_families(module_id: int) -> list[str]:
    base = _base()
    families = [
        name
        for name, group in base.CAPABILITY_GROUPS.items()
        if module_id in set(group.get("ids", []))
    ]
    selector = FAMILY_SELECTOR_MENU.get(str(module_id))
    if selector:
        families.append(selector)
    return list(dict.fromkeys(["catalog", *families]))


def load_catalog() -> list[dict[str, Any]]:
    """Return the public IDs with explicit surface/activity metadata."""
    base = _base()
    raw = json.loads(base.CATALOG.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for section, records in raw.items():
        for record in records:
            item = dict(record)
            module_id = str(item.get("id", ""))
            if not module_id or module_id in seen:
                raise ValueError(f"duplicate or empty public catalog id: {module_id!r}")
            seen.add(module_id)
            if section in {"run_all", "special"}:
                execution_kind = "family-selector"
            elif item.get("native_capability"):
                execution_kind = "native-selector"
            else:
                execution_kind = "executable"
            item["section"] = section
            item["execution_kind"] = execution_kind
            item["activity_class"] = _activity_class(section, item, execution_kind)
            item["menu_families"] = _menu_families(int(module_id))
            rows.append(item)
    # v10 restores the four legacy gaps while preserving every existing ID.
    expected = {str(value) for value in range(1, 178)}
    if seen != expected:
        raise ValueError(
            f"public catalog id drift: missing={sorted(expected - seen)} extra={sorted(seen - expected)}"
        )
    return rows


def load_modules() -> list[dict[str, Any]]:
    """Return executable/native rows only; 135-138 are dispatch selectors."""
    return [row for row in load_catalog() if row["execution_kind"] != "family-selector"]


def module_class(item: dict[str, Any]) -> str:
    """Read explicit activity metadata; labels never change execution policy."""
    value = str(item.get("activity_class", "")).strip()
    if value:
        return value
    section = str(item.get("section", ""))
    execution_kind = (
        "native-selector"
        if item.get("native_capability")
        else "family-selector"
        if section in {"run_all", "special"}
        else "executable"
    )
    return _activity_class(section, item, execution_kind)


def choose_target_input(
    args: argparse.Namespace,
    *,
    initial: str = "",
    prompt: str = "Target domain, HTTP(S) URL, IP/IPv6, host:port, CIDR range, or @targets-file: ",
) -> bool:
    """Expose a single target or -T/--targets-file equivalent interactively."""
    value = initial.strip() or input(prompt).strip()
    if not value:
        print("A target/input is required.")
        return False
    if value.casefold() in {"file", "target-file", "targets-file"}:
        value = input("Targets file path: ").strip()
        if not value:
            print("A targets-file path is required.")
            return False
        args.target = None
        args.targets_file = value
        return True
    if value.startswith("@"):
        path = value[1:].strip()
        if not path:
            print("A targets-file path is required after @.")
            return False
        args.target = None
        args.targets_file = path
        return True
    args.target = value
    args.targets_file = None
    return True


def _local_selector_request(selector: str) -> None:
    if selector == "155":
        raise InteractiveCLIRequest(["--modules", "155"])
    run_dir = input("Saved run directory: ").strip()
    if not run_dir:
        print("A saved run directory is required.")
        return
    if selector == "170":
        raise InteractiveCLIRequest(["--modules", "170", "--local-run", run_dir])
    if selector == "171":
        action = input("Integrity action [seal/verify, default seal]: ").strip().lower() or "seal"
        if action not in {"seal", "verify"}:
            print("Invalid integrity action.")
            return
        raise InteractiveCLIRequest(["--modules", "171", "--local-run", run_dir, "--local-action", action])
    if selector == "177":
        store = input("Offline advisory store directory: ").strip()
        if not store:
            print("An advisory store is required.")
            return
        raise InteractiveCLIRequest([
            "--modules", "177", "--local-run", run_dir, "--advisory-store", store,
        ])


def _route_selected_input(args: argparse.Namespace, values: list[str], initial: str = "") -> bool:
    selected = list(dict.fromkeys(str(value) for value in values))
    local = [value for value in selected if value in LOCAL_SELECTOR_IDS]
    if local:
        if len(selected) != 1:
            print("Local-only and network selectors use different input contracts; choose one local selector or a network-only set.")
            return False
        _local_selector_request(local[0])
        return False
    return choose_target_input(args, initial=initial)


def print_tool_info() -> None:
    base = _base()
    print("Core pipeline")
    for name, description in (
        ("discovery", "subdomains, historical URLs, and address attribution"),
        ("dns", "record types and resolved addresses"),
        ("http", "live services and HTTP metadata"),
        ("crawl", "bounded crawling and directory discovery"),
        ("endpoints", "parameters, APIs, forms, and consumer queues"),
        ("analysis", "secrets, technologies, assets, and ICS indicators"),
        ("network", "range, ports, services, TLS, and web checks"),
        ("camera", "camera, video, recorder, RTSP, ONVIF, and device surface detection"),
        ("consumers", "SQLMap, Nmap, Nikto, Arachni, Wapiti, ZAP, and Nuclei"),
    ):
        print(f"  {name:<12} {description}")
    rows = load_catalog()
    counts: dict[str, int] = {}
    for row in rows:
        kind = str(row["execution_kind"])
        counts[kind] = counts.get(kind, 0) + 1
    print(
        f"\nPublic catalog: {len(rows)} entries "
        f"({counts.get('executable', 0)} executable, "
        f"{counts.get('family-selector', 0)} family selectors, "
        f"{counts.get('native-selector', 0)} native selectors)"
    )
    base._print_catalog_rows(rows, detailed=True)
    print("\nFamily selectors: 135=network, 136=web, 137=security, 138=all runnable modules")
    print(f"\n{base.tool_option_help()}")
    print(f"\n{base.preset_help()}")


def catalog_browser(args: argparse.Namespace) -> bool:
    """Browse all public IDs and return execution to the production runtime."""
    base = _base()
    modules = {str(item["id"]): item for item in load_catalog()}
    state = base.load_browser_state()
    favorites = [value for value in state.get("favorites", []) if value in modules]
    recent = [value for value in state.get("recent", []) if value in modules]
    last = [value for value in state.get("last", []) if value in modules]
    selected: list[str] = []

    def persist() -> None:
        base.save_browser_state(favorites=favorites, recent=recent, last=last)

    def select(values: list[str]) -> bool:
        nonlocal selected
        invalid = [value for value in values if value not in modules]
        selected = list(dict.fromkeys(value for value in values if value in modules))
        if invalid:
            print("invalid IDs: " + ",".join(invalid))
        if not selected:
            print("No valid module IDs selected.")
            return False
        print("selected: " + ",".join(selected))
        return True

    def prepare_run(values: list[str], target: str = "") -> bool:
        nonlocal last, recent
        if not select(values):
            return False
        if not _route_selected_input(args, selected, target):
            return False
        args.catalog_modules = ",".join(selected)
        recent = (recent + selected)[-20:]
        last = list(selected)
        persist()
        return True

    print("Native catalog browser. Type 'help' for commands; execution returns through the unified runtime.")
    while True:
        try:
            words = shlex.split(input("catalog> ").strip())
        except ValueError as exc:
            print(f"invalid command: {exc}")
            continue
        if not words:
            continue
        command, tail = words[0].casefold(), words[1:]
        if command in {"back", "quit", "exit"}:
            persist()
            return False
        if command == "help":
            if tail and tail[0] in modules:
                base._print_catalog_rows([modules[tail[0]]], detailed=True)
            else:
                print("list [detail] | search TEXT | use ID[,ID] | help ID | options [full]")
                print("set KEY=VALUE | set [ID.]KEY=VALUE | set ID KEY=VALUE | unset [ID.]KEY | run [TARGET|@FILE]")
                print("runall infra|web|security|all [TARGET|@FILE]")
                print("fav add|del|list|run [IDs] | recent | rerun [TARGET|@FILE] | view RUN [module|runner]")
                print("grep RUN QUERY | doctor | api | back")
            continue
        if command == "list":
            base._print_catalog_rows(list(modules.values()), detailed=bool(tail and tail[0] == "detail"))
            continue
        if command == "search":
            query = " ".join(tail).casefold()
            base._print_catalog_rows([
                item for item in modules.values()
                if query in " ".join((
                    str(item.get("id", "")), str(item.get("name", "")),
                    str(item.get("description", "")), str(item.get("script", "")),
                )).casefold()
            ], detailed=True)
            continue
        if command == "use":
            select([value for token in tail for value in token.split(",")])
            continue
        if command == "options":
            rows = [modules[value] for value in selected]
            if not rows:
                print("Select modules first with 'use'.")
                continue
            for item in rows:
                options = item.get("options", [])
                print(f"{item['id']} {item.get('name')}: {', '.join(options) if options else 'no module options'}")
            if tail and tail[0] == "full":
                print(base.tool_option_help())
            continue
        if command == "set":
            if len(tail) >= 2 and tail[0].isdigit() and "=" in tail[1]:
                assignment = f"{tail[0]}.{tail[1]}"
            else:
                assignment = tail[0] if tail else ""
            if not selected or "=" not in assignment:
                print("usage: set [ID.]KEY=VALUE (or set ID KEY=VALUE) after selecting modules")
                continue
            owner_and_key = assignment.split("=", 1)[0]
            owner, key = owner_and_key.split(".", 1) if "." in owner_and_key else ("", owner_and_key)
            if owner and owner not in selected:
                print(f"module {owner!r} is not selected.")
                continue
            allowed = {option for value in selected for option in modules[value].get("options", [])}
            if key not in allowed:
                print(f"{key!r} is not declared by the selected modules.")
                continue
            if key in {"advisory_store", "device_data"}:
                value = assignment.split("=", 1)[1].strip()
                if not value or any(character in value for character in ("\x00", "\r", "\n")):
                    print("local artifact path is invalid")
                    continue
                setattr(args, key, value)
                print(f"accepted: {key}=<local-artifact>")
                continue
            try:
                base.parse_option_assignments([assignment])
            except ValueError as exc:
                print(exc)
                continue
            args.module_options = [value for value in args.module_options if value.split("=", 1)[0] != owner_and_key]
            args.module_options.append(assignment)
            print(f"accepted: {owner_and_key}")
            continue
        if command == "unset":
            if not tail:
                print("usage: unset KEY")
                continue
            key = tail[0]
            args.module_options = [value for value in args.module_options if value.split("=", 1)[0] != key]
            if key in {"advisory_store", "device_data"}:
                setattr(args, key, "")
            print(f"unset: {key}")
            continue
        if command == "run":
            if prepare_run(selected, " ".join(tail)):
                return True
            continue
        if command == "runall":
            family = tail[0].casefold() if tail else ""
            selector = {"infra": "135", "infrastructure": "135", "web": "136", "security": "137", "all": "138"}.get(family)
            if not selector:
                print("usage: runall infra|web|security|all [TARGET|@FILE]")
                continue
            if prepare_run([selector], " ".join(tail[1:])):
                return True
            continue
        if command == "fav":
            action = tail[0].casefold() if tail else "list"
            values = [value for token in tail[1:] for value in token.split(",") if value in modules]
            if action == "add":
                favorites = list(dict.fromkeys(favorites + (values or selected)))
                persist()
            elif action in {"del", "remove"}:
                favorites = [value for value in favorites if value not in set(values or selected)]
                persist()
            elif action == "run":
                if prepare_run(favorites, ""):
                    return True
            elif action != "list":
                print("usage: fav add|del|list|run [IDs]")
                continue
            print("favorites: " + (",".join(favorites) if favorites else "none"))
            continue
        if command == "recent":
            print("recent: " + (",".join(recent) if recent else "none"))
            continue
        if command in {"rerun", "last"}:
            if prepare_run(last, " ".join(tail)):
                return True
            continue
        if command == "view":
            if not tail:
                print("usage: view RUN [module|runner]")
                continue
            operation = {"module": "view-module", "runner": "view-runner"}.get(tail[1].casefold(), "view") if len(tail) > 1 else "view"
            try:
                print(json.dumps(base.inspect_saved_run(Path(tail[0]), operation), ensure_ascii=False, indent=2))
            except (OSError, ValueError) as exc:
                print(exc)
            continue
        if command == "grep":
            if len(tail) < 2:
                print("usage: grep RUN QUERY")
                continue
            try:
                print(json.dumps(base.inspect_saved_run(Path(tail[0]), "grep", query=" ".join(tail[1:])), ensure_ascii=False, indent=2))
            except (OSError, ValueError) as exc:
                print(exc)
            continue
        if command == "doctor":
            try:
                from .runner_registry import RUNNERS, inspect_runner
            except ImportError:
                from runner_registry import RUNNERS, inspect_runner
            for name in sorted(RUNNERS):
                row = inspect_runner(name)
                print(f"{name}: {'available' if row.get('available') else 'dependency unavailable'} contract={'ok' if row.get('contract_ok') else 'unverified'}")
            continue
        if command == "api":
            for name in base.API_KEY_NAMES:
                print(f"{name}: {'configured' if base.os.environ.get(name) else 'not configured'}")
            continue
        print("Unknown catalog command. Type 'help'.")


def choose_preset_menu(args: argparse.Namespace) -> None:
    base = _base()
    print("\nPreset runs — depth is selected here; detailed flags remain available on the CLI")
    choices = base.preset_choices()
    for index, preset in enumerate(choices, start=1):
        mode = "active" if preset.active else "passive"
        print(f"{index:02d} {preset.label:<34} [{mode}] {preset.description}")
    print("B  Back")
    choice = input("Select preset: ").strip().lower()
    if choice in {"b", "back", "00"}:
        return
    try:
        preset = choices[int(choice) - 1]
    except (ValueError, IndexError):
        print("invalid preset selection")
        return
    base.apply_preset(args, preset.key)
    if input("Customize this preset? [y/N]: ").strip().lower() in {"y", "yes"}:
        base.choose_custom_options(args)
    if not choose_target_input(args):
        return
    base.choose_wordlist_tier(args)


def _finish_group(args: argparse.Namespace, ids: str, *, wordlist: bool = True) -> bool:
    base = _base()
    values = [value for value in ids.split(",") if value]
    if not _route_selected_input(args, values):
        return False
    if wordlist:
        base.choose_wordlist_tier(args)
    args.run = "full"
    args.profile = "full"
    args.catalog_modules = ids
    return True


INTEGRATED_CAPABILITY_GROUPS = {
    "1": ("Web and evidence", ("complete-web-evidence", "range-http-verification")),
    "2": ("Discovery and infrastructure", ("subdomain-infrastructure", "complete-assessment")),
    "3": ("Industrial, devices and SSH", ("industrial-protocol-followup", "device-inventory", "ssh-credential-audit")),
    "4": ("Intelligence and data", ("intelligence-catalog", "advisory-correlation", "knowledge-index", "dictionary-corpus")),
    "5": ("Complete integrated cycle", ("complete-recon",)),
}


def choose_integrated_capability(args: argparse.Namespace) -> bool:
    """Route the visible menu to the same functional integrated selector."""
    while True:
        print("\nIntegrated Ah-Puch capabilities")
        for key, (label, _values) in INTEGRATED_CAPABILITY_GROUPS.items():
            print(f"{key} {label}")
        print("0 Back")
        group = input("Select group: ").strip()
        if group in {"0", "b", "back"}:
            return False
        if group not in INTEGRATED_CAPABILITY_GROUPS:
            print("invalid group")
            continue
        label, values = INTEGRATED_CAPABILITY_GROUPS[group]
        print(f"\n{label}")
        for index, value in enumerate(values, 1):
            print(f"{index} {value}")
        print("0 Back")
        selected = input("Select capability: ").strip()
        if selected in {"0", "b", "back"}:
            continue
        if not selected.isdigit() or not 1 <= int(selected) <= len(values):
            print("invalid capability")
            continue
        args.integrated_capabilities = values[int(selected) - 1]
        if not choose_target_input(args):
            continue
        args.profile = "deep"
        args.pipeline_mode = "all"
        args.active = True
        args.passive = False
        return True


def pipeline_options_menu(args: argparse.Namespace) -> None:
    """Interactive submenu projecting the exact long-flag pipeline controls."""
    while True:
        print("\nTyped recon pipeline")
        print(f"Mode: {args.pipeline_mode} | rounds: {args.recon_max_rounds} | barrier: {'on' if args.phase_barrier else 'off'}")
        print(f"Partial results: {'continue' if args.continue_on_partial else 'stop'} | HTTP verifier: {args.http_verifier}")
        print(f"Dictionaries: {'off' if getattr(args, 'no_dictionaries', False) else args.wordlist_tier}")
        print("1  Automatic mode for the selected profile")
        print("2  Every applicable method")
        print("3  Inventory-only method set")
        print("4  Disable typed pipeline")
        print("5  Change convergence rounds")
        print("6  Toggle phase barrier")
        print("7  Toggle partial-result continuation")
        print("8  Change HTTP verifier set")
        print("9  Change workers and input limit")
        print("A  Allow explicit intrusive validation methods")
        print("C  Toggle dictionary-backed methods")
        print("B  Back")
        choice = input("Select pipeline option: ").strip().lower()
        if choice in {"b", "back", "00", ""}:
            return
        if choice == "1":
            args.pipeline_mode = "auto"
        elif choice == "2":
            args.pipeline_mode = "all"
        elif choice == "3":
            args.pipeline_mode = "inventory"
        elif choice == "4":
            args.pipeline_mode = "off"
        elif choice == "5":
            raw = input(f"Maximum rounds [1-10, {args.recon_max_rounds}]: ").strip()
            if raw:
                try:
                    value = int(raw)
                    if 1 <= value <= 10:
                        args.recon_max_rounds = value
                except ValueError:
                    print("invalid round count")
        elif choice == "6":
            args.phase_barrier = not args.phase_barrier
        elif choice == "7":
            args.continue_on_partial = not args.continue_on_partial
        elif choice == "8":
            value = input("HTTP verifier [all/native/wget/curl/httpx]: ").strip().lower()
            if value in {"all", "native", "wget", "curl", "httpx"}:
                args.http_verifier = value
        elif choice == "9":
            for field, label, minimum, maximum in (("pipeline_workers", "Workers", 1, 64), ("pipeline_input_limit", "Input limit", 1, 10000)):
                raw = input(f"{label} [{getattr(args, field)}]: ").strip()
                if not raw:
                    continue
                try:
                    value = int(raw)
                except ValueError:
                    print(f"invalid value for {field}")
                    continue
                if minimum <= value <= maximum:
                    setattr(args, field, value)
                else:
                    print(f"value outside {minimum}-{maximum}")
        elif choice == "a":
            args.allow_intrusive_validation = not args.allow_intrusive_validation
        elif choice == "c":
            args.no_dictionaries = not getattr(args, "no_dictionaries", False)
        else:
            print("invalid pipeline option")


def interactive_capability_menu(args: argparse.Namespace) -> None:
    base = _base()
    menu = {
        "02": "recon", "03": "dns", "04": "http", "05": "crawling",
        "06": "content", "07": "endpoints", "08": "secrets",
        "09": "network", "10": "web", "11": "threat", "12": "advisories",
    }
    while True:
        print(f"\n{base.PROGRAM} 2.0 — capability menu")
        print("01 Full analysis")
        for number, key in menu.items():
            print(f"{number} {base.CAPABILITY_GROUPS[key]['label']}")
        print("13 Camera and video-device surfaces")
        print("14 Analyze saved results and rebuild queues")
        print("15 Dictionary inventory")
        print("16 Tool and orchestration catalog")
        print("17 Preset runs by depth")
        print("18 Saved configurations")
        print("19 Advanced configuration")
        print("20 Help and flags")
        print("21 Native orchestration adapters")
        print("22 Typed recon pipeline")
        print("23 Integrated Ah-Puch capabilities")
        print("00 Exit")
        choice = input("Select: ").strip().lower()
        if choice in {"0", "00", "exit", "quit"}:
            raise SystemExit(0)
        if choice == "15":
            base.print_dictionary_info()
            raise SystemExit(0)
        if choice == "16":
            print_tool_info()
            if not catalog_browser(args):
                continue
            args.run = "full"
            args.profile = "full"
            return
        if choice == "17":
            choose_preset_menu(args)
            if args.target or args.targets_file:
                return
            continue
        if choice == "18":
            base.saved_config_menu(args)
            continue
        if choice == "19":
            base.choose_custom_options(args)
            continue
        if choice == "20":
            print(base.parser().format_help())
            print(base.tool_option_help())
            continue
        if choice == "14":
            print("Saved-run operations: verify, rebuild, view-module, view-runner, grep, inventory, receipts, compare, resume")
            operation = input("Operation [view]: ").strip().lower() or "view"
            path = input("Saved run directory: ").strip()
            if operation == "verify":
                raise InteractiveCLIRequest(["--verify-run", path])
            if operation == "rebuild":
                raise InteractiveCLIRequest(["--rebuild-run", path])
            if operation in {"view", "view-module", "view-runner", "inventory", "receipts", "resume"}:
                raise InteractiveCLIRequest(["--saved-run", path, "--saved-operation", operation])
            if operation == "grep":
                query = input("Search text: ").strip()
                raise InteractiveCLIRequest(["--saved-run", path, "--saved-operation", "grep", "--saved-query", query])
            if operation == "compare":
                second = input("Second saved run directory: ").strip()
                raise InteractiveCLIRequest(["--saved-run", path, "--saved-operation", "compare", "--compare-run", second])
            print("invalid saved-run operation")
            continue
        if choice == "13":
            ids = base.choose_capability_group("device", args)
            if not ids:
                continue
            if not _finish_group(args, ids, wordlist=False):
                continue
            base.choose_device_options(args)
            return
        if choice == "21":
            ids = base.choose_capability_group("orchestration", args)
            if not ids:
                continue
            if _finish_group(args, ids, wordlist=False):
                return
            continue
        if choice == "23":
            if choose_integrated_capability(args):
                return
            continue
        if choice == "22":
            pipeline_options_menu(args)
            continue
        if choice == "01":
            if not choose_target_input(args):
                continue
            base.choose_wordlist_tier(args)
            args.run = "full"
            args.profile = "full"
            return
        if choice in menu:
            ids = base.choose_capability_group(menu[choice], args)
            if not ids:
                continue
            if _finish_group(args, ids):
                return
            continue
        print("invalid menu selection")


def install(base: Any) -> Any:
    """Install the Phase-2 surface into the already composed production base."""
    global _BASE
    _BASE = base
    overrides = {
        "load_catalog": load_catalog,
        "load_modules": load_modules,
        "module_class": module_class,
        "choose_target_input": choose_target_input,
        "print_tool_info": print_tool_info,
        "catalog_browser": catalog_browser,
        "choose_preset_menu": choose_preset_menu,
        "pipeline_options_menu": pipeline_options_menu,
        "choose_integrated_capability": choose_integrated_capability,
        "interactive_capability_menu": interactive_capability_menu,
        "interactive_menu": interactive_capability_menu,
    }
    for name, value in overrides.items():
        setattr(base, name, value)
    return base
