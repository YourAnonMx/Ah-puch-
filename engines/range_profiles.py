#!/usr/bin/env python3
"""First-class bounded network profile planning."""
from __future__ import annotations

import json
from pathlib import Path

TCP_PROFILES = {
    "quick": "80,443,554,8000,8080,8554,502,102,20000,47808",
    "standard": "1-1024,1433,1521,2049,2375,2376,3000,3306,3389,5432,5900,6379,8000,8080,8443,8554,9000,9200,11211,27017",
    "full-tcp": "1-65535",
    "full-tcp-udp": "1-65535",
}
DEFAULT_UDP = "53,67,68,69,123,137,138,161,162,500,514,520,623,1900,4500,47808"


def plan(mode: str, custom_tcp: str = "", udp_ports: str = DEFAULT_UDP) -> dict[str, str | bool]:
    selected = mode.strip().lower()
    if selected == "custom":
        if not custom_tcp.strip():
            raise ValueError("custom range mode requires an explicit TCP port expression")
        tcp = custom_tcp.strip()
    elif selected in TCP_PROFILES:
        tcp = TCP_PROFILES[selected]
    else:
        raise ValueError(f"unknown range mode: {mode}")
    return {
        "mode": selected,
        "tcp_ports": tcp,
        "udp_enabled": selected == "full-tcp-udp",
        "udp_ports": udp_ports.strip() if selected == "full-tcp-udp" else "",
    }


def write_plan(root: Path, value: dict) -> Path:
    path = root / "network-profile.json"
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path
