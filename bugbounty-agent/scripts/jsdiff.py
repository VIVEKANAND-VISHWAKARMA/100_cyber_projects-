#!/usr/bin/env python3
"""
JS file change detection.

Downloads JS bundles referenced on live hosts, stores an SHA-256 hash in
memory, and re-checks them periodically. When a hash changes, it means the
target pushed new frontend code — frequently the highest-signal moment to
find fresh API routes, parameter names, or auth logic.

By default we only refetch files older than `refetch_interval_days` to avoid
hammering the target.

NOTE: We only *download and hash* JS files for change detection, never to
extract secrets for exploitation. If hashes change we just flag the changed
URLs + report the diff. This is standard recon, but be mindful of program
rules about asset downloading.
"""

import hashlib
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

import memory


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """Naive but effective: find <script src=...> and regex JS references."""
    urls = set()
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1)
        urls.add(join_url(base, base_url, src))
    for m in re.finditer(r'<(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, re.I):
        src = m.group(1)
        urls.add(join_url(base, base_url, src))
    return sorted(urls)


def join_url(base, page, src: str) -> str:
    if src.startswith("http"):
        return src
    if src.startswith("//"):
        return "https:" + src
    if src.startswith("/"):
        parsed = urlparse(page)
        return f"{parsed.scheme}://{parsed.netloc}{src}"
    parsed = urlparse(page)
    path = parsed.path.rsplit("/", 1)[0] if "/" in parsed.path else ""
    return f"{parsed.scheme}://{parsed.netloc}{path}/{src}"


def fetch_with_retry(url: str, timeout: int = 30, max_attempts: int = 2) -> bytes | None:
    headers = {"User-Agent": "BugBountyReconAgent/1.0 (+recon)"}
    for attempt in range(max_attempts):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                return r.content
            return None  # non-200; don't hammer
        except requests.RequestException:
            time.sleep(2 * (attempt + 1))
    return None


def check_js_files(target: str, live_urls: list[str], config: dict) -> list[dict]:
    """Download JS files from live hosts, store hash, flag changed/added ones.

    Returns list of dicts: {url, status: 'new'|'changed', hash}
    """
    if not config.get("enabled", True):
        return []
    refetch_days = config.get("refetch_interval_days", 3)
    min_kb = config.get("min_size_kb", 1)
    ignore_patterns = config.get("ignore_patterns", [])
    live_js_index = {}

    known = memory.get_all_js_files(target)
    for url in [u for u in live_urls if "://" in u]:
        try:
            base_page = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
            if base_page.status_code != 200:
                continue
            js_urls = extract_js_urls(base_page.text, url)
        except requests.RequestException:
            continue
        for js in js_urls:
            if any(p in js.lower() for p in ignore_patterns):
                continue
            live_js_index.setdefault(js, set()).add(url)

    changes = []
    for js_url, found_on in live_js_index.items():
        prev = known.get(js_url)
        if prev:
            # Only refetch if it's been a while
            try:
                last = datetime.fromisoformat(prev["last_fetched"])
                age_days = (datetime.now(timezone.utc) - last).days
            except Exception:
                age_days = refetch_days + 1
            if age_days < refetch_days:
                continue
        data = fetch_with_retry(js_url)
        if not data:
            continue
        if len(data) < min_kb * 1024:
            continue
        digest = _sha256(data)
        status = "changed" if (prev and prev["hash"] != digest) else "new" if not prev else "unchanged"
        if status != "unchanged":
            memory.upsert_js_file(target, js_url, digest, status=status)
            changes.append(
                {"url": js_url, "status": status, "hash": digest, "found_on": list(found_on)}
            )
            print(f"[+] JS {status}: {js_url}")
    return changes
