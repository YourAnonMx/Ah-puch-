"""Internal depth presets for the interactive menu and command line runner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Preset:
    key: str
    label: str
    capability: str
    description: str
    profile: str = "full"
    active: bool = True
    passive: bool = False
    max_inputs: int = 0
    module_timeout: int = 60
    native_timeout: int = 3600
    wordlist_tier: str = "micro"
    follow_up: bool = False
    follow_up_rounds: int = 0
    range_ports: str = "80,443,554,8000,8080,8554,502,102,20000,47808"
    range_rate: int = 500
    range_host_limit: int = 256


PRESETS: dict[str, Preset] = {
    "recon-quick": Preset("recon-quick", "Recon — Quick", "recon", "Passive discovery with practical bounded input sets.", "baseline", False, True, 50, 45, 1200, "short"),
    "recon-complete": Preset("recon-complete", "Recon — Complete", "recon", "Full discovery, resolution, history, certificates, and asset mapping.", "full", True, False, 0, 60, 3600, "short", True, 1),
    "recon-deep": Preset("recon-deep", "Recon — Deep", "recon", "Extended discovery with all available passive sources and follow-up analysis.", "deep", True, False, 0, 90, 7200, "long", True, 2),
    "crawl-quick": Preset("crawl-quick", "Website crawling — Quick", "crawling", "Bounded crawl with practical paths and page coverage.", "baseline", False, True, 50, 45, 1800, "short"),
    "crawl-complete": Preset("crawl-complete", "Website crawling — Complete", "crawling", "Historical URLs, live pages, JavaScript, forms, endpoints, and content paths.", "full", True, False, 0, 60, 3600, "short", True, 1),
    "crawl-deep": Preset("crawl-deep", "Website crawling — Deep", "crawling", "Largest practical crawl budgets, long dictionaries, and endpoint follow-up.", "deep", True, False, 0, 120, 10800, "long", True, 2),
    "range-quick": Preset("range-quick", "Range discovery — Quick", "network", "Passive range inventory with practical service coverage.", "baseline", False, True, 0, 45, 1200, "short", False, 0, "80,443,554,8000,8080,8554,502,102,20000,47808", 250, 128),
    "range-complete": Preset("range-complete", "Range discovery — Complete", "network", "Bounded service discovery with HTTP, camera, and industrial fan-out.", "full", True, False, 0, 60, 3600, "short", True, 2, "80,443,554,8000,8080,8554,8899,9000,37777,502,102,20000,44818,47808", 500, 256),
    "range-deep": Preset("range-deep", "Range discovery — Deep", "network", "Extended range service, protocol, web, camera, and intelligence follow-up.", "deep", True, False, 0, 90, 10800, "long", True, 3, "1-1024,2000,5000,554,8000,8080,8554,8899,9000,37777,44818,47808", 750, 512),
    "ics-detect": Preset("ics-detect", "Industrial indicators — Detect", "ics", "Passive industrial evidence collection and alerting.", "baseline", False, True, 0, 45, 1800, "short", False, 0, range_host_limit=64),
    "ics-followup": Preset("ics-followup", "Industrial indicators — Follow-up", "ics", "Detect, alert, queue, and execute bounded protocol follow-up.", "full", True, False, 0, 60, 3600, "short", True, 2),
    "camera-detect": Preset("camera-detect", "Camera surfaces — Detect", "cameras", "Passive camera, recorder, RTSP, and ONVIF evidence correlation.", "baseline", False, True, 0, 45, 1800, "short", False, 0, range_host_limit=64),
    "camera-followup": Preset("camera-followup", "Camera surfaces — Follow-up", "cameras", "Detect, alert, queue, and inspect bounded camera service candidates.", "full", True, False, 0, 60, 3600, "short", True, 2),
    "web-complete": Preset("web-complete", "Web analysis — Complete", "web", "Full web catalog, content, endpoint, secret, and security analysis.", "full", True, False, 0, 60, 5400, "short", True, 2),
    "web-deep": Preset("web-deep", "Web analysis — Deep", "web", "Broadest web analysis with extended consumers and follow-up rounds.", "deep", True, False, 0, 120, 10800, "long", True, 3),
    "full-adaptive": Preset("full-adaptive", "Full analysis — Adaptive", "full", "All stages plus event-driven finding dispatch and follow-up rounds.", "deep", True, False, 0, 90, 10800, "long", True, 3),
}


MENU_PRESETS: tuple[str, ...] = (
    "recon-quick", "recon-complete", "recon-deep",
    "crawl-quick", "crawl-complete", "crawl-deep",
    "range-quick", "range-complete", "range-deep",
    "ics-detect", "ics-followup", "camera-detect", "camera-followup",
    "web-complete", "web-deep", "full-adaptive",
)


PRESET_OPTION_OVERRIDES: dict[str, tuple[str, ...]] = {
    "recon-quick": ("max_hosts=50", "samples=2", "limit=100"),
    "recon-complete": ("max_hosts=50", "samples=3", "limit=100", "timeout=60"),
    "recon-deep": ("max_hosts=200", "samples=5", "limit=500", "timeout=90"),
    "crawl-quick": ("max_pages=25", "depth=3", "max_scripts=40", "sample_ratio=2", "max_params=50"),
    "crawl-complete": ("max_pages=50", "depth=3", "max_scripts=50", "sample_ratio=2", "max_params=60"),
    "crawl-deep": ("max_pages=200", "depth=5", "max_scripts=150", "sample_ratio=5", "max_params=200"),
    "range-quick": ("max_hosts=128", "limit=100", "timeout=45"),
    "range-complete": ("max_hosts=256", "limit=100", "timeout=60"),
    "range-deep": ("max_hosts=512", "limit=500", "timeout=90"),
    "ics-detect": ("max_hosts=32", "timeout=45"),
    "ics-followup": ("max_hosts=128", "timeout=60", "samples=3"),
    "camera-detect": ("max_hosts=32", "timeout=45"),
    "camera-followup": ("max_hosts=128", "timeout=60", "samples=3"),
    "web-complete": ("max_pages=50", "depth=3", "max_scripts=50", "max_params=60", "sample_ratio=2"),
    "web-deep": ("max_pages=200", "depth=5", "max_scripts=150", "max_params=200", "sample_ratio=5"),
    "full-adaptive": ("max_pages=200", "depth=5", "max_scripts=150", "max_params=200", "max_hosts=512", "sample_ratio=5"),
}


def preset_choices() -> list[Preset]:
    return [PRESETS[key] for key in MENU_PRESETS]


def get_preset(key: str) -> Preset:
    normalized = key.strip().lower()
    if normalized not in PRESETS:
        raise KeyError(f"unknown preset: {key}")
    return PRESETS[normalized]


def apply_preset(args: Any, key: str) -> Preset:
    """Apply one preset without inheriting routing state from a prior preset/menu path."""
    preset = get_preset(key)

    # Routing flags are derived state, not sticky user preferences. Interactive
    # sessions reuse one argparse namespace, so a prior camera/catalog choice
    # must not leak into the next preset. Explicit CLI/saved-config values are
    # re-applied by runner.main after preset defaults where appropriate.
    args.camera_only = False
    args.no_native = False
    args.no_catalog = False
    args.catalog_modules = ""

    args.preset = preset.key
    args.profile = preset.profile
    args.active = preset.active
    args.passive = preset.passive
    args.module_timeout = preset.module_timeout
    args.native_timeout = preset.native_timeout
    args.max_inputs = preset.max_inputs
    args.wordlist_tier = preset.wordlist_tier
    args.follow_up = preset.follow_up
    args.follow_up_rounds = preset.follow_up_rounds
    args.range_ports = preset.range_ports
    args.range_rate = preset.range_rate
    args.range_host_limit = preset.range_host_limit
    args.module_options = list(getattr(args, "module_options", [])) + list(PRESET_OPTION_OVERRIDES.get(preset.key, ()))
    if preset.capability == "cameras":
        args.run = "cameras"
        args.camera_only = True
        args.no_native = False
        args.no_catalog = True
    elif preset.capability == "ics":
        args.run = "network"
    elif preset.capability == "full":
        args.run = "full"
    else:
        args.run = preset.capability
    return preset


def preset_help() -> str:
    lines = ["Available depth presets:"]
    for preset in preset_choices():
        mode = "active" if preset.active else "passive"
        lines.append(f"  {preset.key:<18} {mode:<7} {preset.description}")
    return "\n".join(lines)
