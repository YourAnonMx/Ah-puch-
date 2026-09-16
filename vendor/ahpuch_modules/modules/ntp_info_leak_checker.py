# modules/ntp_info_leak.py
import os
import sys
import socket
import struct
from rich.console import Console
from rich.table import Table
from colorama import init

from ahpuch_modules.utils.util import resolve_to_ip

init(autoreset=True)
console = Console()

def banner():
    console.print("""
    =============================================
     Ah-Puch - NTP Information Leak Checker
    =============================================
    """)

def query_version(ip, port=123, timeout=3):
    if not str(ip or "").strip():
        return b""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(b"\x1b" + 47*b"\0", (ip, port))
    try:
        data, _ = sock.recvfrom(1024)
        return data
    except:
        return b""
    finally:
        sock.close()

def query_monlist(ip, port=123, timeout=3):
    if not str(ip or "").strip():
        return b""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    pkt = struct.pack(">B B H H H H", (0<<6)|(3<<3)|7, 2, 0, 0, 0, 0)
    sock.sendto(pkt, (ip, port))
    try:
        data, _ = sock.recvfrom(4096)
        return data
    except:
        return b""
    finally:
        sock.close()

def parse_version(data):
    if len(data) >= 48:
        vn = (data[0] >> 3) & 0x07
        stratum = data[1]
        return vn, stratum
    return None, None

def display_ntp_info(ip, version, stratum, monlist):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Test", style="cyan")
    table.add_column("Result", style="green")
    table.add_row("NTP Version", str(version) if version is not None else "N/A")
    table.add_row("Stratum", str(stratum) if stratum is not None else "N/A")
    table.add_row("Monlist Bytes", str(len(monlist)))
    console.print(table)

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        console.print("[red][!] No target provided. Please pass a hostname or IP.[/red]")
        sys.exit(1)
    target = sys.argv[1]
    console.print(f"[white][*] Resolving and querying NTP at: {target}[/white]")
    ip = resolve_to_ip(target)
    if not ip:
        console.print("[red][!] Could not resolve target to IP[/red]")
        sys.exit(1)
    ver_data = query_version(ip)
    version, stratum = parse_version(ver_data)
    mon_data = query_monlist(ip)
    display_ntp_info(ip, version, stratum, mon_data)
    console.print("[white][*] NTP information leak check completed.[/white]")
