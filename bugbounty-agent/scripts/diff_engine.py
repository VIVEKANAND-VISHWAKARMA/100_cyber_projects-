#!/usr/bin/env python3
"""
Diff engine: pure comparison logic, no side effects on the database itself
(memory.py already recorded the upserts before this runs — this just figures
out, from the booleans/data memory.py returned, what the human-readable diff
looks like for this run).
"""


def build_diff(target, subdomain_results, endpoint_results, finding_results,
               js_changes=None, port_results=None, phases=None):
    """
    Each *_results argument is a list of tuples/data produced by the orchestrator:
        subdomain_results: [(domain, is_new, status, prev_status), ...]
        endpoint_results:  [(url, is_new), ...]
        finding_results:   [(template_id, url, severity, is_new), ...]
        js_changes:        [{'url','status','hash'}, ...]  (optional)
        port_results:      [(host, port, service, is_new), ...] (optional)
        phases:            dict with per-phase timing if desired

    Returns a plain dict summarizing what changed this run.
    """
    diff = {
        "target": target,
        "new_subdomains": [],
        "new_endpoints": [],
        "new_findings": [],
        "revived_hosts": [],
        "dead_hosts": [],
        "js_changes": [],
        "new_ports": [],
        "phases": phases or {},
    }

    for domain, is_new, status, prev_status in subdomain_results:
        if is_new:
            diff["new_subdomains"].append(domain)
        elif prev_status == "dead" and status == "alive":
            diff["revived_hosts"].append(domain)
        elif prev_status is not None and prev_status == "alive" and status == "dead":
            diff["dead_hosts"].append(domain)

    for url, is_new in endpoint_results:
        if is_new:
            diff["new_endpoints"].append(url)

    for template_id, url, severity, is_new in finding_results:
        if is_new:
            diff["new_findings"].append(
                {"template_id": template_id, "url": url, "severity": severity}
            )

    if js_changes:
        diff["js_changes"] = js_changes

    if port_results:
        for host, port, service, is_new in port_results:
            if is_new:
                diff["new_ports"].append({"host": host, "port": port, "service": service})

    # Count severities of new findings for quick triage
    sev_counts = {}
    for f in diff["new_findings"]:
        s = f["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1
    diff["new_finding_severities"] = sev_counts

    diff["has_changes"] = bool(
        diff["new_subdomains"]
        or diff["new_endpoints"]
        or diff["new_findings"]
        or diff["revived_hosts"]
        or diff["dead_hosts"]
        or diff["js_changes"]
        or diff["new_ports"]
    )

    return diff
