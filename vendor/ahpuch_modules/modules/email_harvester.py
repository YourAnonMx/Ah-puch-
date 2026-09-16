#!/usr/bin/env python3
import os
import sys
import threading
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse, urlsplit
from collections import deque
from rich.console import Console
from rich.table import Table
from colorama import init

from ahpuch_modules.config.settings import HEADERS, DEFAULT_TIMEOUT

init(autoreset=True)
console = Console()

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

def banner():
    console.print("""
[green]
=============================================
       Ah-Puch - Email Harvesting Module
=============================================
[/green]
""")

class EmailHarvester:
    def __init__(self, base_url, max_pages=100, num_threads=10):
        self.base_url = base_url
        self.max_pages = max_pages
        self.num_threads = num_threads
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.to_crawl = deque([base_url])
        self.visited = set()
        self.found = set()
        self.lock = threading.Lock()
        self.page_count = 0

    def normalize(self, url):
        parts = urlsplit(url)
        if not parts.scheme:
            return "http://" + url
        return url

    def worker(self):
        while True:
            with self.lock:
                if not self.to_crawl or self.page_count >= self.max_pages:
                    return
                url = self.to_crawl.popleft()
                self.page_count += 1
            url = self.normalize(url)
            try:
                r = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=True)
                html = r.text if r.status_code == 200 else ""
            except Exception as e:
                console.print(f"[red][!] Error crawling {url}: {e}[/red]")
                continue

            for email in set(EMAIL_REGEX.findall(html)):
                with self.lock:
                    if email not in self.found:
                        self.found.add(email)
                        console.print(f"[green][+] Found email: {email}[/green]")

            base_netloc = urlparse(self.base_url).netloc
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                parsed = urlparse(link)
                if parsed.scheme in ("http", "https") and parsed.netloc == base_netloc:
                    with self.lock:
                        if link not in self.visited:
                            self.to_crawl.append(link)

            console.print(f"[cyan][*] Crawled: {url}[/cyan]")

    def crawl(self):
        threads = []
        for _ in range(self.num_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def display(self):
        if not self.found:
            console.print("[yellow][!] No email addresses found.[/yellow]")
            return
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Email Address", style="cyan", overflow="fold")
        for e in sorted(self.found):
            table.add_row(e)
        console.print(table)
        console.print(f"[white][*] Email harvesting completed. Total found: [green]{len(self.found)}[/green][/white]")

def main(target):
    banner()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    console.print(f"[white][*] Starting email harvesting on [cyan]{target}[/cyan]...[/white]")
    harvester = EmailHarvester(target)
    harvester.crawl()
    harvester.display()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            main(sys.argv[1])
        except KeyboardInterrupt:
            console.print("\n[red][!] Script interrupted by user.[/red]")
            sys.exit(1)
    else:
        console.print("[red][!] No target provided. Please pass a domain or URL.[/red]")
        sys.exit(1)
