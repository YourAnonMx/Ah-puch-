"""Load the compatibility catalog from an explicit or packaged path."""
from __future__ import annotations

import json
import os
from typing import Dict

from rich.prompt import Prompt

CATALOG_FILENAME = "modules.json"
ENV = "AH_PUCH_CATALOG_PATH"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def candidate_paths():
    env = os.environ.get(ENV)
    if env:
        yield env
    project_root = os.path.dirname(BASE_DIR)
    yield os.path.join(project_root, "config", CATALOG_FILENAME)
    yield os.path.join(BASE_DIR, "config", CATALOG_FILENAME)
    yield os.path.join(BASE_DIR, CATALOG_FILENAME)
    yield os.path.join(os.getcwd(), CATALOG_FILENAME)
    path = BASE_DIR
    for _ in range(3):
        path = os.path.dirname(path)
        yield os.path.join(path, CATALOG_FILENAME)


def minimal_fallback() -> Dict:
    return {
        "network_infrastructure": [],
        "web_application_analysis": [],
        "security_threat_intelligence": [],
    }


def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def load() -> Dict:
    for path in candidate_paths():
        if path and os.path.isfile(path):
            data = _load_json(path)
            if data is not None:
                return data
    path = Prompt.ask(f"Path to {CATALOG_FILENAME}", default="").strip()
    if path and os.path.isfile(path):
        data = _load_json(path)
        if data is not None:
            return data
    return minimal_fallback()


__all__ = ["load", "minimal_fallback"]
