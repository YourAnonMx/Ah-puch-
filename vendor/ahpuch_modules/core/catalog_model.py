"""Compatibility catalog data model used by the retained module runner."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

SECTION_NAMES = {
    "network_infrastructure": "Network & Infrastructure",
    "web_application_analysis": "Web Application Analysis",
    "security_threat_intelligence": "Security & Threat Intelligence",
    "run_all": "Run All Scripts",
    "special": "Special Mode",
}


@dataclass
class Tool:
    number: str
    name: str
    script: str
    section: str
    description: str = ""
    primary_input: str = ""
    options_meta: List[str] = field(default_factory=list)
    options_help: Dict[str, str] = field(default_factory=dict)


def normalize_catalog_ids(catalog: Dict) -> Dict:
    seen: set[str] = set()
    for modules in catalog.values():
        if not isinstance(modules, list):
            continue
        for module in modules:
            module_id = str(module.get("id", "")).strip()
            if not module_id or module_id in seen:
                module_id = str(max([int(value) for value in seen] + [0]) + 1)
                module["id"] = int(module_id)
            seen.add(module_id)
    return catalog


def catalog_to_tools(catalog: Dict) -> List[Tool]:
    result: List[Tool] = []
    seen: set[str] = set()
    for key, section_name in SECTION_NAMES.items():
        for module in catalog.get(key, []):
            module_id = str(module.get("id", "")).strip()
            if not module_id or module_id in seen:
                module_id = str(max([int(value) for value in seen] + [0]) + 1)
            seen.add(module_id)
            result.append(
                Tool(
                    number=module_id,
                    name=module.get("name", f"Module{module_id}"),
                    script=module.get("script", ""),
                    section=section_name,
                    description=module.get("description", ""),
                    primary_input=module.get("primary_input", ""),
                    options_meta=module.get("options", []),
                    options_help=module.get("options_help", {}),
                )
            )
    return result


def compute_tags(tool: Tool) -> Set[str]:
    tags: Set[str] = set()
    name = tool.name.lower()
    description = tool.description.lower()
    section = tool.section.lower()
    if "dns" in name or "dns" in description:
        tags.add("dns")
    if "tls" in name or "ssl" in name or "certificate" in name or "cert" in description:
        tags.add("tls")
    if any(value in name or value in description for value in ("email", "spf", "dmarc", "dkim", "mail")):
        tags.add("email")
    if "cloud" in name or "s3" in description or "bucket" in description:
        tags.add("cloud")
    if "web" in section or tool.section == "Web Application Analysis":
        tags.add("web")
    if any(value in name for value in ("recon", "enum")) or "enumeration" in description:
        tags.add("recon")
    if "scan" in name or "scanner" in name:
        tags.add("fast")
    if any(value in name for value in ("deep", "changelog", "inventory", "history")):
        tags.add("heavy")
    return tags
