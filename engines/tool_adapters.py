#!/usr/bin/env python3
"""Argument-vector-only adapters for every external recon inventory method."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

try:
    from .content_fuzz_policy import dirsearch_args, feroxbuster_args, ffuf_args, gobuster_args
    from .runner_registry import TOOL_BY_ID
    from .service_routing import http_probe_target, parse_service
    from .target_contract import target_domain_seed, target_http_origin_seeds, target_ip_seed, target_network_seeds, target_seed_ports
    from .tool_options import WAPITI_DEFAULT_MODULES
except ImportError:
    from content_fuzz_policy import dirsearch_args, feroxbuster_args, ffuf_args, gobuster_args
    from runner_registry import TOOL_BY_ID
    from service_routing import http_probe_target, parse_service
    from target_contract import target_domain_seed, target_http_origin_seeds, target_ip_seed, target_network_seeds, target_seed_ports
    from tool_options import WAPITI_DEFAULT_MODULES


@dataclass(frozen=True)
class Invocation:
    tool_id: str
    command: tuple[str, ...]
    native_artifact: Path
    stdin_path: Path | None = None
    label: str = "default"


def _domain(target: str) -> str:
    return target_domain_seed(target)


def _domains(values: Iterable[str], target: str, limit: int) -> list[str]:
    seeds = [target_domain_seed(target)]
    seeds.extend(target_domain_seed(str(value)) for value in values)
    return list(dict.fromkeys(seed for seed in seeds if seed))[:max(1, limit)]


def _ips(values: Iterable[str], target: str, limit: int) -> list[str]:
    seeds = [target_ip_seed(target)]
    seeds.extend(target_ip_seed(str(value)) for value in values)
    return list(dict.fromkeys(seed for seed in seeds if seed))[:max(1, limit)]


def _first(values: Iterable[str], fallback: str) -> str:
    return next((str(value) for value in values if str(value).strip()), fallback)


def _origin(values: Iterable[str], target: str) -> str:
    value = _first(values, target)
    if value.startswith(("http://", "https://")):
        parsed = urlsplit(value)
        return f"{parsed.scheme}://{parsed.netloc}/"
    return f"https://{value}/"


def _input_file_values(path: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def _canonical_http_url(value: str) -> str:
    parsed = urlsplit(str(value).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    path = parsed.path or "/"
    url = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        url = f"{url}?{parsed.query}"
    return url


def _origin_urls(values: Iterable[str]) -> list[str]:
    origins: list[str] = []
    for value in values:
        parsed = urlsplit(str(value).strip())
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            origins.append(f"{parsed.scheme}://{parsed.netloc}/")
    return list(dict.fromkeys(origins))


def _query_urls(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(
        url
        for value in values
        if (url := _canonical_http_url(str(value))) and urlsplit(url).query
    ))


def _candidate_urls(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(
        url for value in values if (url := _canonical_http_url(str(value)))
    ))


def _service_endpoint(value: str) -> tuple[str, int, str] | None:
    """Parse canonical services while accepting saved pre-canonical evidence."""
    endpoint = parse_service(value)
    return (endpoint.host, endpoint.port, endpoint.protocol) if endpoint else None


def _ports_with_target(ports: str, target: str) -> str:
    tokens = [token.strip() for token in str(ports).split(",") if token.strip()]
    present = set(tokens)
    for port in target_seed_ports(target):
        text = str(port)
        if text not in present:
            tokens.append(text)
            present.add(text)
    return ",".join(tokens)


def _per_url(
    tool_id: str,
    binary: str,
    urls: list[str],
    output_dir: Path,
    timeout: int,
    wordlist: Path,
    options: dict[str, Any] | None = None,
) -> list[Invocation]:
    invocations: list[Invocation] = []
    for index, url in enumerate(urls, start=1):
        native = output_dir / f"native-{index:04d}.json"
        text_native = output_dir / f"native-{index:04d}.txt"
        label = f"url-{index:04d}"
        if tool_id == "wget":
            command = (binary, "--server-response", "--spider", "--max-redirect=0", f"--timeout={timeout}", "--tries=1", "--no-verbose", url)
            native = text_native
        elif tool_id == "curl":
            command = (binary, "--silent", "--show-error", "--max-redirs", "0", "--max-time", str(timeout), "--output", "/dev/null", "--write-out", "%{http_code}\t%{url_effective}\t%{redirect_url}\n", url)
            native = text_native
        elif tool_id == "gospider":
            command = (binary, "-s", url, "-d", "3", "-c", "4", "-t", "4", "--other-source", "-o", str(output_dir / f"gospider-{index:04d}"))
            native = text_native
        elif tool_id == "hakrawler":
            command = (binary, "-url", url, "-d", "3", "-timeout", str(timeout), "-plain")
            native = text_native
        elif tool_id == "playwright":
            command = (binary, "screenshot", "--wait-for-timeout", str(min(timeout, 30) * 1000), url, str(output_dir / f"page-{index:04d}.png"))
            native = output_dir / f"page-{index:04d}.png"
        elif tool_id == "ffuf":
            fuzz = url.rstrip("/") + "/FUZZ"
            command = tuple([
                binary, "-noninteractive", "-s", "-u", fuzz, "-w", str(wordlist),
                "-of", "json", "-o", str(native),
                *ffuf_args(options, timeout=timeout, threads=20),
            ])
        elif tool_id == "dirsearch":
            command = tuple([
                binary, "-u", url, "-w", str(wordlist),
                *dirsearch_args(options, timeout=timeout, threads=20),
                "--format", "json", "-o", str(native),
            ])
        elif tool_id == "gobuster":
            native = text_native
            command = tuple([
                binary, "dir", "--no-error", "-u", url, "-w", str(wordlist),
                *gobuster_args(options, timeout=timeout, threads=20), "-o", str(native),
            ])
        elif tool_id == "feroxbuster":
            command = tuple([
                binary, "--url", url, "--wordlist", str(wordlist),
                *feroxbuster_args(options, timeout=timeout, threads=20),
                "--json", "--output", str(native),
            ])
        elif tool_id == "linkfinder":
            native = text_native
            command = (binary, "-i", url, "-o", "cli")
        elif tool_id == "secretfinder":
            native = text_native
            command = (binary, "-i", url, "-o", "cli")
        elif tool_id == "jsfscan":
            native = text_native
            command = (binary, "-u", url)
        elif tool_id == "paraminer":
            native = text_native
            command = (binary, "-u", url)
        elif tool_id == "arjun":
            command = (binary, "-u", url, "-oJ", str(native), "--stable")
        elif tool_id == "whatweb":
            command = (binary, "--no-errors", "--log-json", str(native), url)
        elif tool_id == "wafw00f":
            command = (binary, "--format", "json", "--output", str(native), url)
        elif tool_id == "testssl":
            command = (binary, "--warnings", "batch", "--color", "0", "--jsonfile", str(native), url)
        elif tool_id == "sslscan":
            native = output_dir / f"native-{index:04d}.xml"
            command = (binary, "--no-colour", "--xml", str(native), urlsplit(url).netloc)
        elif tool_id == "openssl":
            native = text_native
            host = urlsplit(url).hostname or _domain(url)
            port = urlsplit(url).port or 443
            command = (binary, "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief")
        elif tool_id == "nikto":
            native = text_native
            command = (binary, "-ask", "no", "-h", url, "-timeout", str(timeout), "-Format", "txt", "-o", str(native))
        elif tool_id == "wapiti":
            command = (binary, "-u", url, "--scope", "url", "-m", WAPITI_DEFAULT_MODULES, "-f", "json", "-o", str(output_dir / f"wapiti-{index:04d}"))
        elif tool_id == "arachni":
            native = output_dir / f"native-{index:04d}.afr"
            command = (binary, url, "--report-save-path", str(native), "--audit-links", "--audit-forms", "--audit-headers", "--scope-include-pattern", url)
        elif tool_id == "zap_baseline":
            command = (binary, "-t", url, "-J", str(native), "-I")
        elif tool_id == "zap_full":
            command = (binary, "-t", url, "-J", str(native), "-I")
        elif tool_id == "sqlmap":
            native = text_native
            command = (binary, "-u", url, "--batch", "--level", "1", "--risk", "1", "--timeout", str(timeout), "--output-dir", str(output_dir / f"sqlmap-{index:04d}"))
        elif tool_id == "ssrfmap":
            native = text_native
            command = (binary, "-r", url)
        elif tool_id == "dalfox":
            native = text_native
            command = (binary, "url", url, "--silence", "--timeout", str(timeout))
        elif tool_id == "nosqlmap":
            native = text_native
            command = (binary, "--url", url)
        else:
            raise KeyError(f"no per-URL command adapter for {tool_id}")
        invocations.append(Invocation(tool_id, command, native, label=label))
    return invocations


PER_URL_TOOLS = frozenset({
    "wget", "curl", "gospider", "hakrawler", "playwright",
    "ffuf", "dirsearch", "gobuster", "feroxbuster", "linkfinder",
    "secretfinder", "jsfscan", "paraminer", "arjun", "whatweb", "wafw00f",
    "testssl", "sslscan", "openssl", "nikto", "wapiti", "arachni",
    "zap_baseline", "zap_full", "sqlmap", "ssrfmap", "dalfox", "nosqlmap",
})
ORIGIN_SCOPED_TOOLS = frozenset({
    "gospider", "hakrawler", "playwright", "ffuf", "dirsearch", "gobuster",
    "feroxbuster", "whatweb", "wafw00f", "testssl", "sslscan", "openssl",
    "nikto", "wapiti", "arachni", "zap_baseline", "zap_full",
})
QUERY_SCOPED_TOOLS = frozenset({"sqlmap", "ssrfmap", "dalfox", "nosqlmap"})


def build_invocations(
    tool: dict[str, Any],
    binary: str,
    target: str,
    inputs: dict[str, list[str]],
    input_file: Path,
    output_dir: Path,
    *,
    timeout: int,
    threads: int,
    wordlist: Path,
    resolver_file: Path,
    ports: str,
    rate: int,
    input_limit: int,
    local_run: Path | None = None,
    tool_options: dict[str, dict[str, Any]] | None = None,
) -> list[Invocation]:
    """Build bounded argument vectors; no shell, install, update or download."""
    tool_id = str(tool["id"])
    if not binary:
        return []
    domain_values = _domains(inputs.get("host", []), target, input_limit)
    ip_values = _ips(inputs.get("ip", []), target, input_limit)
    domain = domain_values[0] if domain_values else ""
    raw_input_values = _input_file_values(input_file)
    fallback_urls = list(dict.fromkeys(inputs.get("url", []) + inputs.get("origin", [])))
    if tool_id in ORIGIN_SCOPED_TOOLS:
        urls = _origin_urls(raw_input_values) or _origin_urls(fallback_urls)
    elif tool_id in QUERY_SCOPED_TOOLS:
        urls = _query_urls(raw_input_values) or _query_urls(inputs.get("url", []))
    else:
        urls = _candidate_urls(raw_input_values) or _candidate_urls(fallback_urls)
    urls = urls[:max(1, input_limit)]
    if not urls and domain and tool_id not in QUERY_SCOPED_TOOLS:
        urls = target_http_origin_seeds(target)[:max(1, input_limit)]
    hosts = list(dict.fromkeys(inputs.get("host", []) + inputs.get("ip", [])))[:max(1, input_limit)]
    if not hosts:
        hosts = target_network_seeds(target)[:max(1, input_limit)] or ([domain] if domain else [])
    scan_ports = _ports_with_target(ports, target)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    native_json = output_dir / "native.json"
    native_text = output_dir / "native.txt"
    native_xml = output_dir / "native.xml"
    if tool_id == "nmap_tls":
        invocations: list[Invocation] = []
        for index, raw_service in enumerate(inputs.get("service", [])[:max(1, input_limit)], start=1):
            endpoint = _service_endpoint(raw_service)
            if endpoint is None:
                continue
            host, port, protocol = endpoint
            if protocol != "tcp":
                continue
            native = output_dir / f"native-{index:04d}.xml"
            command = (
                binary, "-Pn", "-n", "-p", str(port),
                "--script", "ssl-cert,ssl-enum-ciphers", "-oX", str(native), host,
            )
            invocations.append(Invocation(tool_id, command, native, label=f"service-{index:04d}"))
        return invocations
    if tool_id in PER_URL_TOOLS:
        options = tool_options.get(tool_id, {}) if isinstance(tool_options, dict) else {}
        return _per_url(tool_id, binary, urls, output_dir, timeout, wordlist, options)
    command: tuple[str, ...]
    stdin: Path | None = None
    native = native_text
    if tool_id == "subfinder":
        if not domain:
            return []
        command, native = (binary, "-silent", "-d", domain, "-o", str(native_text)), native_text
    elif tool_id == "assetfinder":
        if not domain:
            return []
        command = (binary, "--subs-only", domain)
    elif tool_id == "amass":
        if not domain:
            return []
        command = (binary, "enum", "-passive", "-d", domain, "-o", str(native_text))
    elif tool_id == "findomain":
        if not domain:
            return []
        command = (binary, "-t", domain, "-u", str(native_text), "-q")
    elif tool_id == "chaos":
        if not domain:
            return []
        command = (binary, "-d", domain, "-silent", "-o", str(native_text))
    elif tool_id == "ctfr":
        if not domain:
            return []
        command = (binary, "-d", domain)
    elif tool_id == "dig":
        if not domain:
            return []
        command = (binary, domain, "A", domain, "AAAA", "+short")
    elif tool_id == "dnsx":
        command, native, stdin = (binary, "-silent", "-json", "-o", str(native_json)), native_json, input_file
    elif tool_id == "puredns":
        command, native = (binary, "resolve", str(input_file), "--resolvers", str(resolver_file), "--write", str(native_text), "--quiet"), native_text
    elif tool_id == "shuffledns":
        command = (binary, "-list", str(input_file), "-r", str(resolver_file), "-silent", "-o", str(native_text))
    elif tool_id == "massdns":
        command, native = (binary, "-r", str(resolver_file), "-o", "J", "-w", str(native_json), str(input_file)), native_json
    elif tool_id == "dnsrecon":
        if not domain:
            return []
        command, native = (binary, "-d", domain, "-j", str(native_json)), native_json
    elif tool_id == "dnsenum":
        if not domain:
            return []
        command = (binary, "--noreverse", domain)
    elif tool_id == "dnsmap":
        if not domain:
            return []
        command = (binary, domain, "-r", str(native_text))
    elif tool_id == "altdns":
        command = (binary, "-i", str(input_file), "-o", str(native_text), "-r", "-s", str(output_dir / "resolved.txt"))
    elif tool_id == "knockpy":
        if not domain:
            return []
        command = (binary, domain, "--json", str(native_json), "--no-local")
    elif tool_id == "dnstwist":
        if not domain:
            return []
        command, native = (binary, "--format", "json", "--output", str(native_json), domain), native_json
    elif tool_id == "nmap":
        command, native = (binary, "-Pn", "-n", "-sV", "--open", "-p", scan_ports, "-iL", str(input_file), "-oX", str(native_xml)), native_xml
    elif tool_id == "naabu":
        command, native = (binary, "-silent", "-list", str(input_file), "-p", scan_ports, "-json", "-o", str(native_json), "-rate", str(rate)), native_json
    elif tool_id == "masscan":
        command, native = (binary, "-iL", str(input_file), "-p", scan_ports, "--max-rate", str(rate), "-oJ", str(native_json)), native_json
    elif tool_id in {"httpx", "httpx_tech"}:
        service_targets = [
            target
            for value in inputs.get("service", [])
            if (target := http_probe_target(value))
        ]
        http_targets = list(dict.fromkeys([*urls, *service_targets, *hosts]))[:max(1, input_limit)]
        http_input = output_dir / "httpx-inputs.txt"
        http_input.write_text("\n".join(http_targets) + ("\n" if http_targets else ""), encoding="utf-8")
        http_input.chmod(0o600)
        extras = ("-tech-detect", "-title", "-server") if tool_id == "httpx_tech" else ("-status-code", "-title", "-server", "-tech-detect")
        command, native = (binary, "-silent", "-json", "-l", str(http_input), "-o", str(native_json), "-timeout", str(timeout), *extras), native_json
    elif tool_id == "gau":
        if not domain:
            return []
        command = (binary, "--subs", "--threads", str(threads), "--o", str(native_text), domain)
    elif tool_id == "waybackurls":
        command, stdin = (binary,), input_file
    elif tool_id == "waymore":
        if not domain:
            return []
        command = (binary, "-i", domain, "-mode", "U", "-oU", str(native_text))
    elif tool_id == "katana":
        command = (binary, "-list", str(input_file), "-d", "3", "-c", str(threads), "-silent", "-o", str(native_text))
    elif tool_id == "paramspider":
        if not domain:
            return []
        command = (binary, "-d", domain, "--output", str(native_text), "--quiet")
    elif tool_id == "nuclei":
        command, native = (binary, "-l", str(input_file), "-jsonl", "-timeout", str(timeout), "-rate-limit", str(rate), "-o", str(native_json)), native_json
    elif tool_id == "subzy":
        command, native = (binary, "run", "--targets", str(input_file), "--hide_fails", "--output", str(native_text)), native_text
    elif tool_id == "gitleaks":
        if local_run is None:
            return []
        command, native = (binary, "detect", "--no-banner", "--no-git", "--source", str(local_run), "--report-format", "json", "--report-path", str(native_json)), native_json
    elif tool_id == "trufflehog":
        if local_run is None:
            return []
        command, native = (binary, "filesystem", str(local_run), "--json", "--no-update"), native_json
    elif tool_id == "gowitness":
        command, native = (binary, "scan", "file", "-f", str(input_file), "--write-jsonl", "--write-jsonl-file", str(native_json), "--screenshot-path", str(output_dir / "screenshots")), native_json
    elif tool_id == "cloudunflare":
        if not domain:
            return []
        command = (binary, domain)
    elif tool_id == "shodan":
        if domain:
            command = (binary, "domain", domain)
        elif ip_values:
            command = (binary, "host", ip_values[0])
        else:
            return []
    elif tool_id == "censys":
        query = domain or (ip_values[0] if ip_values else "")
        if not query:
            return []
        command = (binary, "search", query, "--format", "json")
    elif tool_id == "greynoise":
        if not ip_values:
            return []
        command = (binary, "ip", ip_values[0])
    elif tool_id == "virustotal":
        urls_for_vt = [value for value in urls if str(value).startswith(("http://", "https://"))]
        if domain:
            command = (binary, "domain", domain)
        elif ip_values:
            command = (binary, "ip", ip_values[0])
        elif urls_for_vt:
            command = (binary, "url", urls_for_vt[0])
        else:
            return []
    elif tool_id == "hunter":
        if not domain:
            return []
        command = (binary, "domain-search", domain)
    elif tool_id == "fofa":
        query = f'domain="{domain}"' if domain else (f'ip="{ip_values[0]}"' if ip_values else "")
        if not query:
            return []
        command = (binary, "--query", query, "--json")
    else:
        raise KeyError(f"no command adapter for external tool {tool_id}")
    return [Invocation(tool_id, command, native, stdin_path=stdin)]


def unsupported_external_tools() -> list[str]:
    """Return inventory methods lacking an explicit command builder."""
    supported = set(PER_URL_TOOLS) | {
        "subfinder", "assetfinder", "amass", "findomain", "chaos", "ctfr",
        "dig", "dnsx", "puredns", "shuffledns", "massdns", "dnsrecon",
        "dnsenum", "dnsmap", "altdns", "knockpy", "dnstwist", "nmap",
        "naabu", "masscan", "httpx", "httpx_tech", "gau", "waybackurls",
        "waymore", "katana", "paramspider", "nmap_tls", "nuclei", "subzy",
        "gitleaks", "trufflehog", "gowitness", "cloudunflare", "shodan",
        "censys", "greynoise", "virustotal", "hunter", "fofa",
    }
    return sorted(tool_id for tool_id, row in TOOL_BY_ID.items() if row.get("binary") and tool_id not in supported)
