import os
import sys
import socket
import ipaddress
import itertools
import dns.resolver
import random
import struct
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from colorama import init

from ahpuch_modules.config.settings import DEFAULT_TIMEOUT
from ahpuch_modules.utils.util import clean_domain_input

init(autoreset=True)
console = Console()

DEFAULT_PORTS = [53, 123, 161, 500, 514, 69]
DEFAULT_MAX_HOSTS = 256
MAX_RETRIES = 5
DNS_QUERY_ID_MAX = 65535


def banner():
    console.print("""
    =============================================
          Ah-Puch - UDP Service Sampler
    =============================================
    """)


def parse_ports(value):
    text = str(value or "").strip()
    if not text:
        raise ValueError("port expression is empty")
    ports = set()
    for raw in text.split(","):
        token = raw.strip()
        if not token:
            raise ValueError("empty port token")
        if "-" in token:
            fields = token.split("-")
            if len(fields) != 2 or not all(field.isdigit() for field in fields):
                raise ValueError(f"invalid port range: {token}")
            start, end = (int(field) for field in fields)
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"invalid port: {token}")
            port = int(token)
            if not 1 <= port <= 65535:
                raise ValueError(f"port outside 1-65535: {token}")
            ports.add(port)
    return sorted(ports)


def parse_opts(argv):
    ports = list(DEFAULT_PORTS)
    retries = 1
    max_hosts = DEFAULT_MAX_HOSTS
    i = 3
    while i < len(argv):
        option = argv[i]
        if option == "--ports":
            if i + 1 >= len(argv):
                raise ValueError("--ports requires a value")
            ports = parse_ports(argv[i + 1])
            i += 2
            continue
        if option == "--retries":
            if i + 1 >= len(argv):
                raise ValueError("--retries requires a value")
            try:
                retries = int(argv[i + 1])
            except ValueError as exc:
                raise ValueError("--retries must be an integer") from exc
            if not 1 <= retries <= MAX_RETRIES:
                raise ValueError(f"--retries must be 1-{MAX_RETRIES}")
            i += 2
            continue
        if option == "--max-hosts":
            if i + 1 >= len(argv):
                raise ValueError("--max-hosts requires a value")
            try:
                max_hosts = int(argv[i + 1])
            except ValueError as exc:
                raise ValueError("--max-hosts must be an integer") from exc
            if not 1 <= max_hosts <= 65536:
                raise ValueError("--max-hosts must be 1-65536")
            i += 2
            continue
        # Ignore unknown historical tokens so old wrappers do not become a
        # second parser surface; recognized endpoint controls remain strict.
        i += 1
    return ports, retries, max_hosts


def resolve_domain(domain):
    if not str(domain or "").strip():
        return []
    ips = []
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=DEFAULT_TIMEOUT)
        for row in answers:
            ips.append(row.address)
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "AAAA", lifetime=DEFAULT_TIMEOUT)
        for row in answers:
            ips.append(row.address)
    except Exception:
        pass
    return list(dict.fromkeys(ips))


def expand_target(target, max_hosts=DEFAULT_MAX_HOSTS):
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("target must be a domain, IP, or CIDR")
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        network = None
    if network is not None:
        hosts = list(itertools.islice(network.hosts(), int(max_hosts) + 1))
        if len(hosts) > int(max_hosts):
            raise ValueError(f"CIDR expands beyond --max-hosts={max_hosts}")
        return [str(host) for host in hosts]
    if any(character.isalpha() for character in raw):
        domain = clean_domain_input(raw)
        values = resolve_domain(domain) or [domain]
        if len(values) > int(max_hosts):
            raise ValueError(f"resolved target count exceeds --max-hosts={max_hosts}")
        return values
    try:
        return [str(ipaddress.ip_address(raw.strip("[]")))]
    except ValueError as exc:
        raise ValueError("target must be a domain, IP, or CIDR") from exc


def build_dns_probe():
    tid = random.randint(0, DNS_QUERY_ID_MAX)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"\x07ahpuch01\x03net\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def build_ntp_probe():
    return b"\x1b" + b"\x00" * 47


def build_snmp_probe():
    return b"0\x1b\x02\x01\x01\x04\x06public\xa0\x0e\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x00"


def build_ike_probe():
    return os.urandom(28)


def build_syslog_probe():
    return b"<134>AhPuchTest"


def build_tftp_probe():
    return b"\x00\x01test\x00octet\x00"


def classify_resp(port, data):
    if not data:
        return "-"
    length = len(data)
    if port == 53 and length >= 12:
        return "DNS"
    if port == 123 and length >= 48:
        return "NTP"
    if port == 161:
        return "SNMP"
    if port == 500 and length >= 28:
        return "IKE"
    if port == 514:
        return "Syslog"
    if port == 69:
        return "TFTP"
    return "RESP" if length > 0 else "-"


def udp_send(ip, port, payload, retries):
    if not str(ip or "").strip():
        return None
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = None
    data = None
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        for _ in range(max(1, int(retries))):
            try:
                sock.sendto(payload, (ip, port))
                data, _ = sock.recvfrom(2048)
                break
            except socket.timeout:
                continue
    except OSError:
        data = None
    finally:
        try:
            if sock:
                sock.close()
        except OSError:
            pass
    return data


def payload_for_port(port):
    if port == 53:
        return build_dns_probe()
    if port == 123:
        return build_ntp_probe()
    if port == 161:
        return build_snmp_probe()
    if port == 500:
        return build_ike_probe()
    if port == 514:
        return build_syslog_probe()
    if port == 69:
        return build_tftp_probe()
    return b"\x00"


def main(argv=None):
    values = list(sys.argv if argv is None else argv)
    banner()
    if len(values) < 2:
        console.print("[red][!] No target provided. Please pass a domain, IP, or CIDR.[/red]")
        return 2
    raw = values[1]
    try:
        ports, retries, max_hosts = parse_opts(values)
        targets = expand_target(raw, max_hosts)
    except ValueError as exc:
        console.print(f"[red][!] Invalid UDP sampler input: {exc}[/red]")
        return 2

    rows = []
    total = len(targets) * len(ports)
    progress = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console, transient=True)
    with progress:
        task = progress.add_task("Sampling UDP", total=total)
        for ip in targets:
            for port in ports:
                payload = payload_for_port(port)
                response = udp_send(ip, port, payload, retries)
                service = classify_resp(port, response)
                size = str(len(response)) if response else "-"
                rows.append((ip, str(port), service, size))
                progress.advance(task)

    table = Table(title="UDP Service Sampler", show_header=True, header_style="bold magenta")
    table.add_column("IP", style="cyan")
    table.add_column("Port", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Bytes", style="white")
    for row in rows:
        table.add_row(*row)
    console.print(table)
    console.print("[white][*] UDP service sampling completed.[/white]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
