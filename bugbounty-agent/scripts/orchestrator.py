#!/usr/bin/env python3
"""
Main entrypoint. Chains subfinder -> httpx -> katana -> nuclei for each
target, feeds results into memory, builds a diff against prior state,
optionally triages via Claude, and sends a notification.

New in this advanced build:
- Passive discovery: crt.sh + Wayback + (optional) Shodan
- Scope guard: rejects anything not under the target root domain
- Wildcard-DNS detection
- Parallel subdomain enumeration (subfinder + crtsh merged)
- Per-target config override in targets/<name>.yaml
- Dead-host tracking (hosts that stopped responding)
- JS bundle change detection
- Optional port scanning (masscan) + Shodan-derived ports
- Rate limiting / retries via tools.py

Usage:
    python3 orchestrator.py --target-file targets/scope.txt [--workers N]
    python3 orchestrator.py --target example.com   # scan an ad-hoc single target
    python3 orchestrator.py --schedule 6h --target-file targets/scope.txt   # OPTIONAL: periodic

Requires subfinder, httpx, katana, nuclei to be installed and on PATH.
Run only against in-scope targets you are authorized to test.

Scheduling is OPTIONAL: by default each run is a one-shot scan. Pass
--schedule to loop periodically (also possible via external cron).
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parent))
import memory
import diff_engine
import tools
import scope_guard
import passive
import jsdiff
import notifier
from config import load_target_config, env

try:
    import triage
except ImportError:
    triage = None


def run_phase_timed(name, fn, *args, **kwargs):
    """Run fn with timing, best-effort."""
    t0 = time.time()
    try:
        result = fn(*args, **kwargs)
    except Exception as e:
        print(f"[!] Phase {name} failed: {e}")
        result = None
    dt = round(time.time() - t0, 1)
    print(f"[=] {name}: {dt}s")
    return result, dt


def enumerate_subdomains_parallel(target, cfg):
    """Merge subfinder + crtsh subdomains in parallel."""
    tools_cfg = cfg["recon"]["tools"]
    subs = set()
    futures = {}

    with ThreadPoolExecutor(max_workers=2) as ex:
        if tools_cfg.get("subfinder", True):
            futures["subfinder"] = ex.submit(
                tools.subfinder, target, timeout=cfg["recon"]["timeout"].get("subfinder", 1800)
            )
        if tools_cfg.get("crtsh", True):
            futures["crtsh"] = ex.submit(passive.crtsh_subdomains, target)

        for name, fut in futures.items():
            try:
                result = fut.result(timeout=cfg["recon"]["timeout"].get("subfinder", 1800) + 60)
                subs.update(result)
                print(f"[+] {name}: {len(result)} subdomains")
            except Exception as e:
                print(f"[!] {name} failed: {e}")

    return sorted(subs)


def process_target(target, cfg):
    print(f"\n{'='*60}\n=== Scanning target: {target} ===\n{'='*60}")
    run_id = memory.start_scan_run(target)
    phases = {}
    live_urls = []
    subdomain_results = []
    endpoint_results = []
    finding_results = []
    js_changes = []
    port_results = []

    # ---------------------------------------------------------------
    # 1. Wildcard DNS detection — skip naive probing if wildcard present
    # ---------------------------------------------------------------
    is_wildcard, dt = run_phase_timed("wildcard_detect", scope_guard.detect_wildcard, target)
    phases["wildcard_detect"] = dt
    if is_wildcard:
        print("[+] Wildcard DNS detected — relying on passive/cert sources only")

    # ---------------------------------------------------------------
    # 2. Subdomain enumeration (parallel: subfinder + crtsh + optional shodan)
    # ---------------------------------------------------------------
    candidates, dt = run_phase_timed(
        "subdomain_enum", enumerate_subdomains_parallel, target, cfg
    )
    phases["subdomain_enum"] = dt

    # Optional Shodan-derived hosts merged in
    if cfg["recon"]["tools"].get("shodan", True) and env("SHODAN_API_KEY"):
        shodan_extra, dt2 = run_phase_timed("shodan_lookup", passive.shodan_host_info, target)
        phases["shodan_lookup"] = dt2
        # store ports from shodan into memory
        for host in shodan_extra:
            for datum in host.get("data", []):
                ip = host.get("ip_str", "")
                port = datum.get("port")
                service = (datum.get("product") or datum.get("service") or "")
                if ip and port:
                    memory.upsert_port(target, ip, int(port), service or None)

    # Scope guard — drop anything not under our root domain
    in_scope_domains = scope_guard.filter_in_scope_domains(target, candidates)
    dropped = len(candidates) - len(in_scope_domains)
    if dropped:
        print(f"[!] Scope guard dropped {dropped} out-of-scope candidate(s)")
    print(f"[+] {len(in_scope_domains)} in-scope subdomains")

    # ---------------------------------------------------------------
    # 3. Live host probing
    # ---------------------------------------------------------------
    alive_domains = set()
    httpx_host_ips = set()
    if in_scope_domains:
        live_hosts, dt = run_phase_timed(
            "httpx", tools.probe_httpx, in_scope_domains,
            timeout=cfg["recon"]["timeout"].get("httpx", 1800),
            concurrency=cfg["recon"]["rate_limit"].get("httpx_concurrency", 50),
        )
        phases["httpx"] = dt

        for host in live_hosts:
            domain = (host.get("input") or host.get("host") or "").lower()
            url = host.get("url", "")
            ip = host.get("host", "")
            tech = ",".join(host.get("tech", [])) if host.get("tech") else None
            if ip:
                httpx_host_ips.add(ip)

            if not scope_guard.validate_domain_in_scope(target, domain):
                continue

            prev = memory.get_all_subdomains(target).get(domain)
            prev_status = prev["status"] if prev else None

            is_new = memory.upsert_subdomain(target, domain, ip=ip, status="alive", tech_stack=tech)
            subdomain_results.append((domain, is_new, "alive", prev_status))
            alive_domains.add(domain)
            if url:
                live_urls.append(url)

    # ---------------------------------------------------------------
    # 4. Detect hosts that went offline (were alive last run, not alive now)
    # ---------------------------------------------------------------
    previous = memory.get_all_subdomains(target)
    for dom, rec in previous.items():
        if rec["status"] == "alive" and dom not in alive_domains:
            memory.mark_subdomain_dead(target, dom)
            subdomain_results.append((dom, False, "dead", "alive"))
            print(f"[.] Host went offline: {dom}")

    # ---------------------------------------------------------------
    # 5. Endpoint crawling (katana) 
    # ---------------------------------------------------------------
    if not is_wildcard and cfg["recon"]["tools"].get("katana", True) and live_urls:
        crawled, dt = run_phase_timed(
            "katana", tools.crawl_katana, live_urls,
            timeout=cfg["recon"]["timeout"].get("katana", 1800),
            concurrency=cfg["recon"]["rate_limit"].get("katana_concurrency", 25),
        )
        phases["katana"] = dt
        crawled_in_scope = scope_guard.filter_in_scope_urls(target, crawled)
        for url in crawled_in_scope[:cfg["recon"]["rate_limit"].get("endpoints_per_run", 1000)]:
            from urllib.parse import urlparse, parse_qs
            params = ",".join(parse_qs(urlparse(url).query).keys()) or None
            is_new = memory.upsert_endpoint(target, url, source="katana", params=params)
            endpoint_results.append((url, is_new))
    # ---------------------------------------------------------------
    # 5b. Wayback historical URL discovery
    # ---------------------------------------------------------------
    if cfg["recon"]["tools"].get("wayback", True):
        wb_urls, wb_dt = run_phase_timed(
            "wayback", passive.wayback_urls, target,
            limit=cfg["recon"]["rate_limit"].get("endpoints_per_run", 1000) * 2,
        )
        phases["wayback"] = wb_dt
        for url in scope_guard.filter_in_scope_urls(target, wb_urls):
            from urllib.parse import urlparse, parse_qs
            params = ",".join(parse_qs(urlparse(url).query).keys()) or None
            is_new = memory.upsert_endpoint(target, url, source="wayback", params=params)
            endpoint_results.append((url, is_new))

    # ---------------------------------------------------------------
    # 6. JS bundle change detection
    # ---------------------------------------------------------------
    if cfg["recon"]["tools"].get("jsdiff", True) and live_urls:
        js_changes, dt = run_phase_timed(
            "jsdiff", jsdiff.check_js_files, target, live_urls, cfg.get("jsdiff", {})
        )
        phases["jsdiff"] = dt

    # ---------------------------------------------------------------
    # 7. Port scanning (masscan) — offline fallback uses Shodan ports
    # ---------------------------------------------------------------
    if cfg["recon"]["tools"].get("masscan", False):
        ips = sorted(httpx_host_ips)
        if ips:
            masscan_results, dt = run_phase_timed(
                "masscan", tools.scan_masscan, ips,
                rate=cfg["recon"]["rate_limit"].get("masscan_rate", 500),
                timeout=cfg["recon"]["timeout"].get("masscan", 1800),
            )
            phases["masscan"] = dt
            for host, port in masscan_results:
                is_new = memory.upsert_port(target, host, port)
                port_results.append((host, port, None, is_new))

    # ---------------------------------------------------------------
    # 8. Vulnerability scanning (default nuclei templates only)
    # ---------------------------------------------------------------
    if cfg["recon"]["tools"].get("nuclei", True) and live_urls:
        findings, dt = run_phase_timed(
            "nuclei", tools.scan_nuclei, live_urls,
            timeout=cfg["recon"]["timeout"].get("nuclei", 3600),
            concurrency=cfg["recon"]["rate_limit"].get("nuclei_concurrency", 20),
            rps=cfg["recon"]["nuclei"].get("rate_limit_rps", 5),
            severity_filter=cfg["recon"]["nuclei"].get("severity_filter", "info,low,medium,high,critical"),
            template_path=env("NUCLEI_TEMPLATES_PATH") or None,
            default_templates_only=cfg["recon"]["nuclei"].get("default_templates_only", True),
        )
        phases["nuclei"] = dt
        for f in findings:
            template_id = f.get("template-id", "unknown")
            url = f.get("matched-at", f.get("host", ""))
            severity = (f.get("info") or {}).get("severity", "info")
            is_new = memory.upsert_finding(target, template_id, url, severity=severity)
            finding_results.append((template_id, url, severity, is_new))

    # ---------------------------------------------------------------
    # 8b. VULNERABILITY CANDIDATE DETECTION (DAST)
    # ---------------------------------------------------------------
    candidate_cnt = 0
    if cfg["vuln_scanner"].get("enabled", True) and (live_urls or memory.get_all_endpoints(target)):
        import vuln_scanner
        vscan, dt = run_phase_timed(
            "vuln_scanner", vuln_scanner.scan_target, target, cfg
        )
        phases["vuln_scanner"] = dt
        if vscan:
            candidate_cnt = vscan.get("added", 0)

    # ---------------------------------------------------------------
    # 9. Build diff + log scan
    # ---------------------------------------------------------------
    diff = diff_engine.build_diff(
        target, subdomain_results, endpoint_results, finding_results,
        js_changes=js_changes, port_results=port_results, phases=phases,
    )
    memory.finish_scan_run(
        run_id,
        new_subdomains=len(diff["new_subdomains"]),
        new_endpoints=len(diff["new_endpoints"]),
        new_findings=len(diff["new_findings"]),
    )
    diff["new_candidates"] = candidate_cnt

    # ---------------------------------------------------------------
    # 10. Optional triage + notification
    # ---------------------------------------------------------------
    summary = None
    if diff["has_changes"]:
        if triage:
            try:
                summary = triage.summarize_diff(diff)
            except Exception as e:
                print(f"[!] Triage step failed, falling back to raw diff: {e}")
        notifier.notify(diff, triage_summary=summary)
    else:
        print("[+] No changes since last scan — staying quiet")

    return diff


def process_target_safe(target, cfg):
    return process_target(target, cfg)


def _run_targets(targets, workers):
    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(process_target_safe, t, load_target_config(t)): t for t in targets}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    fut.result()
                except Exception as e:
                    print(f"[!] Target {t} failed: {e}")
    else:
        for target in targets:
            process_target_safe(target, load_target_config(target))


def _parse_interval(value: str) -> int:
    """Parse a --schedule value like '30s', '10m', '6h', '1d' into seconds."""
    value = value.strip().lower()
    if not value:
        return 3600
    if value[-1] in "smhd":
        num, unit = value[:-1], value[-1]
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    else:
        num, mult = value, 3600  # bare number = hours
    try:
        return max(int(float(num) * mult), 1)
    except ValueError:
        print(f"[!] Invalid --schedule value '{value}', using 1h")
        return 3600


def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon agent")
    parser.add_argument("--target-file", help="Path to a file with one root domain per line")
    parser.add_argument("--target", help="Scan an ad-hoc single target")
    parser.add_argument("--workers", type=int, default=2, help="Parallel target workers")
    parser.add_argument("--schedule", metavar="INTERVAL", default=None,
                        help="OPTIONAL: re-run every INTERVAL (e.g. '6h', '30m', '1d'). "
                             "Omit for a single run.")
    args = parser.parse_args()

    if args.target:
        targets = [args.target]
    elif args.target_file:
        target_file = Path(args.target_file)
        if not target_file.exists():
            print(f"[!] Target file not found: {target_file}")
            sys.exit(1)
        targets = [
            line.strip()
            for line in target_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        print("[!] Provide --target-file or --target")
        sys.exit(1)

    if not targets:
        print("[!] No targets found")
        sys.exit(1)

    workers = args.workers
    if len(targets) == 1:
        workers = 1

    interval = _parse_interval(args.schedule) if args.schedule else None
    if interval:
        print(f"[+] OPTIONAL scheduler enabled: re-running every {args.schedule} (Ctrl-C to stop)")

    try:
        _run_targets(targets, workers)
        while interval:
            next_at = time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(time.time() + interval))
            print(f"[+] Scheduler: next scan at {next_at} (--schedule {args.schedule})")
            time.sleep(interval)
            _run_targets(targets, workers)
    except KeyboardInterrupt:
        print("\n[+] Scheduler stopped.")


if __name__ == "__main__":
    main()
