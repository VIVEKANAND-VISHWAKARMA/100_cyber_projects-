#!/usr/bin/env python3
"""
Passive intelligence & historical discovery.

Combines several free / API-backed OSINT sources to expand the attack
surface beyond what live subdomain brute-forcing finds:

- crt.sh Certificate Transparency logs (subdomains)
- Wayback Machine CDX API (historical URLs/endpoints)
- Shodan (if SHODAN_API_KEY is set) for exposed services, banners, and open ports

All of these run *passively* (no direct requests to the target), so they are
safe to run continuously and within program rate limits.
"""

import json
import re
import time
from urllib.parse import urlparse

import requests

import memory
from config import env


USER_AGENT = "BugBountyReconAgent/1.0 (+in-scope research)"


def crtsh_subdomains(target: str) -> list[str]:
    """Enumerate subdomains from Certificate Transparency logs via crt.sh."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{target}&output=json",
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] crt.sh failed: {e}")
        return []

    subs = set()
    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        # crt.sh sometimes returns HTML / plain-text on errors
        return []

    for entry in data:
        for name in [entry.get("name_value", "")]:
            for part in name.split("\n"):
                part = part.strip().strip("*.").lower()
                if part.endswith(target) and re.match(r"^[a-z0-9.*_-]+$", part):
                    subs.add(part)
    return sorted(subs)


def wayback_urls(target: str, limit: int = 2000) -> list[str]:
    """Fetch historical URLs for the target from the Wayback CDX API."""
    params = {
        "url": target,
        "matchType": "domain",
        "output": "json",
        "fl": "original,statuscode,mimetype,timestamp",
        "collapse": "urlkey",
        "limit": limit,
    }
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params=params,
            headers={"User-Agent": USER_AGENT},
            timeout=60,
        )
        r.raise_for_status()
        rows = r.json()
    except (requests.RequestException, ValueError) as e:
        print(f"[!] Wayback CDX failed: {e}")
        return []

    urls = []
    if rows:
        header = rows[0]
        for row in rows[1:]:
            try:
                urls.append(row[header.index("original")])
            except (ValueError, IndexError):
                continue
    return sorted(set(urls))


def wayback_js_files(target: str, limit: int = 500) -> list[str]:
    """Collect historical JS bundle URLs (for later JS diffing)."""
    js = []
    for u in wayback_urls(target, limit=limit * 4):
        if u.lower().endswith((".js", ".js?ver=")) or ".js" in uparse_path(u.lower()):
            js.append(u)
    return sorted(set(js))


def uparse_path(url: str) -> str:
    return urlparse(url).path


def shodan_host_info(target: str) -> list[dict]:
    """Passive Shodan lookup per subdomain. Needs SHODAN_API_KEY."""
    api_key = env("SHODAN_API_KEY")
    if not api_key:
        return []
    results = []
    known_ips = set()
    # First fetch subdomains we already know to gather IPs
    subdomains = memory.get_all_subdomains(target)
    candidates = [target] + [d for d in subdomains if subdomains[d].get("ip")]
    for host in candidates:
        ip = subdomains.get(host, {}).get("ip") if host in subdomains else None
        if not ip or ip in known_ips:
            continue
        known_ips.add(ip)
        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
                timeout=20,
            )
            if r.status_code == 200:
                results.append(r.json())
            time.sleep(1.1)  # Shodan free-tier rate limit: 1 req/sec
        except requests.RequestException as e:
            print(f"[!] Shodan lookup for {ip} failed: {e}")
    return results


def shodan_ports(results: list[dict]) -> dict[str, list[int]]:
    """Extract open ports per host from Shodan host responses."""
    ports_by_ip = {}
    for r in results:
        ip = r.get("ip_str", "")
        if ip:
            ports_by_ip[ip] = [p.get("port") for p in r.get("data", []) if p.get("port")]
    return ports_by_ip
