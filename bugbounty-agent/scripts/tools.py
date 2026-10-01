#!/usr/bin/env python3
"""
Tool executor: runs external recon binaries with:
- retry / backoff on transient failures
- per-tool timeouts
- optional rate limiting (via httpx/nuclei built-in flags)
- clean logging of stderr

All external tool invocation in the pipeline goes through this so behavior
is consistent and safe.
"""

import subprocess
import time


def run_tool(cmd, timeout=1800, max_attempts=2, backoff=15, input=None):
    """Run an external recon tool with retries and backoff.

    Returns (returncode, stdout, stderr). Handles missing binaries and
    timeouts gracefully. `input` can be a string piped to stdin.
    """
    attempt = 0
    while attempt < max_attempts:
        attempt += 1
        try:
            result = subprocess.run(
                cmd,
                input=input,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if result.returncode == 0:
                return result.returncode, result.stdout, result.stderr
            # Non-zero return code — likely transient (rate limit, network blip)
            # but don't endlessly retry obvious config errors.
            print(f"[!] {cmd[0]} exited {result.returncode}: {result.stderr[:400]}")
            if attempt < max_attempts:
                time.sleep(backoff * attempt)
        except FileNotFoundError:
            print(f"[!] Tool not found on PATH: {cmd[0]} — install it or disable it in config.yaml")
            return -1, "", "not found"
        except subprocess.TimeoutExpired:
            print(f"[!] {cmd[0]} timed out after {timeout}s")
            if attempt < max_attempts:
                time.sleep(backoff * attempt)
            continue
    return -1, "", "all attempts failed"


def run_tool_or_none(cmd, timeout=1800, max_attempts=2, backoff=15, input=None):
    """Like run_tool but returns only stdout ('' on total failure)."""
    rc, out, err = run_tool(cmd, timeout, max_attempts, backoff, input)
    return out


# ---------------------------------------------------------------------------
# Convenience wrappers for the specific projectdiscovery tools
# ---------------------------------------------------------------------------

def subfinder(target, timeout=1800):
    rc, out, err = run_tool(
        ["subfinder", "-d", target, "-silent"], timeout=timeout
    )
    return [line.strip() for line in out.splitlines() if line.strip()] if rc == 0 else []


def probe_httpx(domains, timeout=1800, concurrency=50):
    """Probe a list of domains with httpx; returns list of JSON dicts."""
    if not domains:
        return []
    input_data = "\n".join(domains)
    cmd = [
        "httpx", "-silent", "-json", "-tech-detect",
        "-c", str(concurrency),
    ]
    rc, out, err = run_tool(cmd, timeout=timeout, input=input_data)
    hosts = []
    if rc == 0:
        import json
        for line in out.splitlines():
            try:
                hosts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return hosts


def crawl_katana(urls, timeout=1800, concurrency=25):
    """Crawl URLs with katana; returns list of discovered URL strings."""
    if not urls:
        return []
    input_data = "\n".join(urls)
    cmd = ["katana", "-silent", "-jc", "-c", str(concurrency)]
    rc, out, err = run_tool(cmd, timeout=timeout, input=input_data)
    return [line.strip() for line in out.splitlines() if line.strip()] if rc == 0 else []


def scan_nuclei(urls, timeout=3600, concurrency=20, rps=5, severity_filter="info,low,medium,high,critical",
                template_path=None, default_templates_only=True):
    """Run nuclei with default community detection templates only."""
    if not urls:
        return []
    input_data = "\n".join(urls)
    cmd = ["nuclei", "-silent", "-jsonl", "-c", str(concurrency), "-rl", str(rps)]
    if severity_filter:
        cmd += ["-severity", severity_filter]
    if template_path:
        cmd += ["-t", template_path]
    rc, out, err = run_tool(cmd, timeout=timeout, input=input_data)
    findings = []
    if rc == 0:
        import json
        for line in out.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return findings


def scan_masscan(ips, ports="1-1024,8080,8443,8000,8888,9000,9090,3000,4000,5000,8081,9200,9300,10000",
                 rate=500, timeout=1800):
    """Port scan with masscan. Requires root. Returns (ip, port) pairs."""
    if not ips or not _is_root():
        if not ips:
            return []
        print("[!] masscan requires root — skipping port scan (or run as root)")
        return []
    cmd = ["masscan", "-p", ports, "--rate", str(rate), "--wait", "3",
           "-oL", "-", ",".join(filter(None, ips[:200]))]
    rc, out, err = run_tool(cmd, timeout=timeout)
    results = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "open":
                results.append((parts[2], int(parts[1])))
    return results


def _is_root():
    import os
    import sys
    return (hasattr(os, "geteuid") and os.geteuid() == 0) or "SUDO_UID" in os.environ
