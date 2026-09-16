#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import collections
import json
import sys
import urllib.parse
from pathlib import Path

import aiohttp
import bs4
import requests
from rich.console import Console
from rich.table import Table

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input, web_target_base

console = Console()
PARTIAL_EXIT_CODE = 3


def banner():
    console.print("[bold green]=============================================[/bold green]")
    console.print("[bold green]        Ah-Puch – Content Discovery         [/bold green]")
    console.print("[bold green]=============================================[/bold green]")


def same_scope(root, u, include_subdomains=False):
    root_host = (urllib.parse.urlparse(root).hostname or "").lower().rstrip(".")
    candidate_host = (urllib.parse.urlparse(u).hostname or "").lower().rstrip(".")
    if not root_host or not candidate_host:
        return False
    if include_subdomains:
        return candidate_host == root_host or candidate_host.endswith("." + root_host)
    return urllib.parse.urlparse(root).netloc.lower() == urllib.parse.urlparse(u).netloc.lower()


async def fetch(session, u, timeout=DEFAULT_TIMEOUT):
    try:
        # Do not let an HTTP redirect silently widen the operator-supplied
        # origin. A 3xx is recorded as a completed HTTP-negative observation;
        # discovered Location values are not contacted by this module.
        async with session.get(u, timeout=timeout, allow_redirects=False) as response:
            if response.status == 200 and "text/html" in response.headers.get("content-type", ""):
                return {"url": u, "state": "success", "html": await response.text()}
            return {"url": u, "state": "http-negative", "status": int(response.status), "html": ""}
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        return {"url": u, "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "html": ""}


def extract(u, html):
    soup = bs4.BeautifulSoup(html, "html.parser")
    links = set()
    assets_css = set()
    assets_js = set()
    for tag in soup.find_all("a", href=True):
        links.add(urllib.parse.urljoin(u, tag["href"]))
    for link in soup.find_all("link", href=True):
        if link.get("rel") == ["stylesheet"]:
            assets_css.add(urllib.parse.urljoin(u, link["href"]))
    for script in soup.find_all("script", src=True):
        assets_js.add(urllib.parse.urljoin(u, script["src"]))
    return links, assets_css, assets_js


async def crawl(start, page_limit, include_subdomains, timeout=DEFAULT_TIMEOUT):
    queue = collections.deque([start])
    seen = {start}
    internal = set()
    external = set()
    css = set()
    js = set()
    observations = []
    async with aiohttp.ClientSession() as session:
        processed = 0
        while queue and processed < page_limit:
            url = queue.popleft()
            processed += 1
            observation = await fetch(session, url, timeout)
            observations.append({key: value for key, value in observation.items() if key != "html"})
            html = str(observation.get("html", ""))
            if observation.get("state") != "success" or not html:
                continue
            links, new_css, new_js = extract(url, html)
            css.update(new_css)
            js.update(new_js)
            for link in links:
                if link in seen:
                    continue
                in_scope = same_scope(start, link, include_subdomains)
                (internal if in_scope else external).add(link)
                if in_scope and len(seen) < page_limit:
                    seen.add(link)
                    queue.append(link)
    return internal, external, css, js, observations


def show(base, robots, sitemaps, internal, external, css, js):
    table = Table(title=f"Summary – {base}", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    table.add_row("robots.txt", "Yes" if robots else "No")
    table.add_row("Sitemap Links", str(len(sitemaps)))
    table.add_row("Internal Links", str(len(internal)))
    table.add_row("External Links", str(len(external)))
    table.add_row("CSS", str(len(css)))
    table.add_row("JS", str(len(js)))
    console.print(table)


def _text_probe(url: str, timeout: float) -> dict:
    try:
        # requests follows redirects by default; disable that so robots/sitemap
        # probes cannot contact a different origin without an explicit scoped
        # handoff from the canonical artifact bus.
        response = requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        return {"url": url, "state": "transport-error", "error": f"{type(exc).__name__}: {exc}", "text": ""}
    if not response.ok:
        return {"url": url, "state": "http-negative", "status": int(response.status_code), "text": ""}
    return {"url": url, "state": "success", "status": int(response.status_code), "text": response.text}


async def main_async(target, page_limit=100, include_subdomains=False, timeout=DEFAULT_TIMEOUT):
    banner()
    try:
        base = web_target_base(target, default_scheme="http")
    except ValueError as exc:
        console.print(f"[red]Invalid web target: {exc}[/red]")
        return 2
    internal, external, css, js, crawl_rows = await crawl(base, page_limit, include_subdomains, timeout)

    robots_probe = _text_probe(f"{base}/robots.txt", timeout)
    sitemap_probe = _text_probe(f"{base}/sitemap.xml", timeout)
    robots = str(robots_probe.get("text", "")) if robots_probe.get("state") == "success" else ""
    sitemap = []
    if sitemap_probe.get("state") == "success":
        soup = bs4.BeautifulSoup(str(sitemap_probe.get("text", "")), "xml")
        sitemap = [loc.text for loc in soup.find_all("loc")]

    show(base, robots, sitemap, internal, external, css, js)
    probes = [*crawl_rows, {key: value for key, value in robots_probe.items() if key != "text"}, {key: value for key, value in sitemap_probe.items() if key != "text"}]
    payload = {
        "target": base,
        "probes": probes,
        "internal_links": sorted(internal),
        "external_links": sorted(external),
        "css": sorted(css),
        "javascript": sorted(js),
        "sitemap_links": sorted(set(sitemap)),
        "robots_present": bool(robots),
    }
    Path("content_discovery.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    completed = sum(row.get("state") in {"success", "http-negative"} for row in probes)
    errors = sum(row.get("state") == "transport-error" for row in probes)
    if completed == 0 and errors:
        return 2
    if completed and errors:
        return PARTIAL_EXIT_CODE
    return 0


def main(target):
    try:
        opts = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        opts = {}
    try:
        page_limit = max(1, int(opts.get("max_pages", 100)))
    except (TypeError, ValueError):
        page_limit = 100
    include_subdomains = str(opts.get("include_subdomains", 0)).lower() not in {"0", "false", "no", "off"}
    try:
        timeout = max(1, float(opts.get("timeout", DEFAULT_TIMEOUT)))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    return asyncio.run(main_async(target, page_limit, include_subdomains, timeout))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
