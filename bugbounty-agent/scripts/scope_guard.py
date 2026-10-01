#!/usr/bin/env python3
"""
Scope guard: the safety rail before any tool runs.

Ensures every domain we're about to scan is inside the in-scope root domain
for the target, and that we're not about to hit unrelated hosts. Protects
against:

- Wildcard DNS collisions (resolving *.target.com to an IP owned by someone
  else and scanning a third party)
- Typo'd / copied subdomains leaking out of scope
- Subdomains that resolve to a private/reserved range (RFC 1918 etc.) that
  we almost certainly shouldn't be touching

Audit database: the `out_of_scope_hits` table records any time a discovered
domain failed the guard, so you can review what got skipped.
"""

import ipaddress
import re
from urllib.parse import urlparse

import memory


# RFC 1918 + link-local + loopback + CGNAT (RFC 6598) + multicast + reserved
PRIVATE_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "0.0.0.0/8",
    "192.0.0.0/24",
    "224.0.0.0/4",
]
PRIVATE_NETWORKS = [ipaddress.ip_network(r) for r in PRIVATE_RANGES]


def _is_root_domain_or_sub(target_root: str, candidate: str) -> bool:
    """True if `candidate` equals target_root or is a subdomain of it."""
    candidate = str(candidate).strip().lower().rstrip(".")
    target_root = str(target_root).strip().lower().lstrip("www.").rstrip(".")
    return candidate == target_root or candidate.endswith("." + target_root)


def validate_domain_in_scope(target_root: str, domain: str) -> bool:
    """Check a single subdomain is in-scope for the target root domain."""
    if not _is_root_domain_or_sub(target_root, domain):
        memory.record_out_of_scope(
            target_root, host=domain, reason=f"not under root domain {target_root}"
        )
        return False
    return True


def validate_url_in_scope(target_root: str, url: str) -> bool:
    """Validate that a URL's host is in-scope for the target root domain."""
    host = (urlparse(url).hostname or "").strip().lower()
    if not host:
        return False
    # Strip a leading www. or subdomain-based CIDR annotations if present
    return validate_domain_in_scope(target_root, host)


def validate_ip_in_private_range(ip: str) -> bool:
    """True if the resolved IP is in a private/reserved range we shouldn't scan."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split(",")[0].strip())
    except ValueError:
        return False
    for net in PRIVATE_NETWORKS:
        if addr in net:
            return True
    return False


def filter_in_scope_domains(target_root: str, domains: list[str]) -> list[str]:
    """Return only domains that are in-scope for the target."""
    in_scope = set()
    for d in domains:
        d = str(d).strip().lower()
        if not d:
            continue
        if validate_domain_in_scope(target_root, d):
            in_scope.add(d)
    return sorted(in_scope)


def filter_in_scope_urls(target_root: str, urls: list[str]) -> list[str]:
    in_scope = set()
    for u in urls:
        u = str(u).strip()
        if not u:
            continue
        if validate_url_in_scope(target_root, u) and not _is_asset_url(u):
            in_scope.add(u)
    return sorted(in_scope)


# URLs that are never interesting to scan (static asset hosts etc.)
IGNORED_HOST_KEYWORDS = [
    "gravatar",
    "google-analytics",
    "googleapis",
    "gstatic",
    "cloudfront",
    "amazonaws.com",
    "akamai",
    "fastly",
    "jsdelivr",
    "unpkg",
    "cdnjs",
    "githubusercontent",
    "cloudflare",
    "doubleclick",
    "facebook",
    "chartbeat",
    "adservice",
    "1password",
    "zendesk",
    "intercom",
    "segment",
    "mixpanel",
]


def _is_asset_url(url: str) -> bool:
    return any(k in url.lower() for k in IGNORED_HOST_KEYWORDS)


def detect_wildcard(domain: str) -> bool:
    """Heuristic wildcard-DNS check: resolve a random subdomain.

    If it resolves, the target uses wildcard DNS and scanning bare subdomains
    would produce false positives. We return True and orchestrator skips the
    naive live-host probe of every string, instead relying on discovered
    subdomains from certificate/passive sources.
    """
    if "@" not in domain and "." in domain:
        # Only check if we have python-dns or can use socket; keep it simple:
        import random
        import string
        import socket

        rand = "".join(random.choices(string.ascii_lowercase, k=14))
        candidate = f"{rand}.{domain}"
        try:
            socket.getaddrinfo(candidate, None)
            return True
        except (socket.gaierror, socket.timeout):
            return False
    return False


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else ""
    domains = [d for d in sys.argv[2:]] if len(sys.argv) > 2 else []
    if not target:
        print("Usage: scope_guard.py <target-root> [domain ...]")
        sys.exit(1)
    print("In-scope:", filter_in_scope_domains(target, domains))
