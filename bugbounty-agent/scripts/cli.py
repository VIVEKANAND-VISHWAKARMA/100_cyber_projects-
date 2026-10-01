#!/usr/bin/env python3
"""
CLI for managing the recon database and findings.

Usage examples:
    python3 cli.py targets                      # list all targets
    python3 cli.py stats                        # overall stats
    python3 cli.py findings [target]            # list new findings (optionally filtered)
    python3 cli.py findings --all               # all findings regardless of status
    python3 cli.py findings --severity high     # only high/critical
    python3 cli.py status <id> reported --note "Reported as #12345"
    python3 cli.py status <id> false_positive --note "WAF noise"
    python3 cli.py js [target]                  # list tracked JS files
    python3 cli.py ports [target]               # list open ports
    python3 cli.py subdomains [target]          # list subdomains
    python3 cli.py history [target]             # scan run history
    python3 cli.py out-of-scope                 # audit log of blocked hosts
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import memory

from rich.console import Console
from rich.table import Table
from rich import box


console = Console()

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def list_targets():
    conn = memory._connect()
    try:
        rows = conn.execute("SELECT DISTINCT target FROM subdomains").fetchall()
        targets = sorted(r["target"] for r in rows)
    finally:
        conn.close()
    table = Table(title="Targets", box=box.SIMPLE_HEAVY)
    table.add_column("Target")
    for t in targets:
        st = memory.get_stats(t)
        table.add_row(f"{t}  ({st['subdomains']} subs, {st['findings']} findings, {st['open_findings']} open)")
    console.print(table)


def cmd_stats(target=None):
    if target:
        st = memory.get_stats(target)
        console.print(f"[bold]{target}[/bold] stats:")
        _print_stats(st)
    else:
        conn = memory._connect()
        try:
            targets = [r["target"] for r in conn.execute(
                "SELECT DISTINCT target FROM subdomains ORDER BY target").fetchall()]
        finally:
            conn.close()
        console.print("[bold]Overall stats by target:[/bold]\n")
        for t in targets:
            st = memory.get_stats(t)
            console.print(f"[bold]{t}:[/bold] {st['subdomains']} subs · {st['endpoints']} endpoints · "
                          f"{st['open_findings']} open findings")


def _print_stats(st):
    for k, v in st.items():
        if isinstance(v, dict):
            console.print(f"  [cyan]{k}:[/cyan] " + ", ".join(f"{sk}={sv}" for sk, sv in v.items()))
        else:
            console.print(f"  [cyan]{k}:[/cyan] {v}")


def cmd_findings(target=None, all_status=False, severity=None, json_out=False):
    findings = memory.get_all_findings(target)
    if not all_status:
        findings = [f for f in findings if f["status"] == "new"]
    if severity:
        min_ord = SEVERITY_ORDER.get(severity.lower(), 0)
        findings = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 0) >= min_ord]

    if json_out:
        import json
        print(json.dumps(findings, indent=2))
        return

    table = Table(title=f"Findings ({len(findings)})", box=box.SIMPLE_HEAVY)
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Template")
    table.add_column("URL")
    for f in findings:
        color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "cyan", "info": "white"}.get(f["severity"], "white")
        table.add_row(
            str(f["id"]),
            f["target"],
            f"[{color}]{f['severity']}[/{color}]",
            f["status"],
            f["template_id"],
            f["url"],
        )
    console.print(table)


def cmd_status(finding_id, status, note=None):
    if status not in ("reviewed", "reported", "false_positive", "reopen"):
        console.print(f"[red]Invalid status: {status}. Use reviewed|reported|false_positive|reopen[/red]")
        sys.exit(1)
    if status == "reopen":
        memory.set_finding_status(finding_id, "new", note)
    else:
        memory.set_finding_status(finding_id, status, note)
    console.print(f"[green]Finding {finding_id} → {status}[/green]")


def cmd_js(target=None):
    conn = memory._connect()
    try:
        if target:
            rows = conn.execute("SELECT * FROM js_files WHERE target = ?", (target,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM js_files").fetchall()
    finally:
        conn.close()
    table = Table(title=f"JS files ({len(rows)})", box=box.SIMPLE_HEAVY)
    table.add_column("URL")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Last fetched")
    for r in rows:
        table.add_row(r["url"], r["target"], r["status"], (r["last_fetched"] or "")[:16])
    console.print(table)


def cmd_ports(target=None):
    conn = memory._connect()
    try:
        if target:
            rows = conn.execute("SELECT * FROM ports WHERE target = ?", (target,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ports").fetchall()
    finally:
        conn.close()
    table = Table(title=f"Open ports ({len(rows)})", box=box.SIMPLE_HEAVY)
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("Service")
    table.add_column("Target")
    for r in rows:
        table.add_row(r["host"], str(r["port"]), r["service"] or "", r["target"])
    console.print(table)


def cmd_subdomains(target=None):
    conn = memory._connect()
    try:
        if target:
            rows = conn.execute("SELECT * FROM subdomains WHERE target = ?", (target,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM subdomains").fetchall()
    finally:
        conn.close()
    table = Table(title=f"Subdomains ({len(rows)})", box=box.SIMPLE_HEAVY)
    table.add_column("Domain")
    table.add_column("Status")
    table.add_column("IP")
    table.add_column("Tech")
    for r in rows:
        table.add_row(r["domain"], r["status"] or "", r["ip"] or "", r["tech_stack"] or "")
    console.print(table)


def cmd_history(target=None):
    rows = memory.get_scan_history(target)
    table = Table(title=f"Scan history ({len(rows)})", box=box.SIMPLE_HEAVY)
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Started")
    table.add_column("New subs")
    table.add_column("New eps")
    table.add_column("New finds")
    for r in rows:
        table.add_row(str(r["id"]), r["target"], (r["started_at"] or "")[:16],
                      str(r["new_subdomains"]), str(r["new_endpoints"]), str(r["new_findings"]))
    console.print(table)


def cmd_out_of_scope(target=None, limit=50):
    rows = memory.get_out_of_scope_hits(target, limit)
    table = Table(title=f"Out-of-scope blocked {len(rows)}", box=box.SIMPLE_HEAVY)
    table.add_column("Target")
    table.add_column("Host")
    table.add_column("Reason")
    table.add_column("Seen")
    for r in rows:
        table.add_row(r["target"], r["host"], r["reason"] or "", (r["seen_at"] or "")[:16])
    console.print(table)


def cmd_candidates(target=None, vuln_class=None, min_confidence=1, status="new", limit=100):
    rows = memory.get_candidates(target=target, vuln_class=vuln_class,
                                 min_confidence=min_confidence, status=status, limit=limit)
    table = Table(title=f"Vuln candidates ({len(rows)})", box=box.SIMPLE_HEAVY)
    table.add_column("ID")
    table.add_column("Conf")
    table.add_column("Class")
    table.add_column("Method")
    table.add_column("URL")
    table.add_column("Param")
    table.add_column("Evidence")
    for c in rows:
        color = {3: "red", 2: "yellow", 1: "cyan"}.get(c["confidence"], "white")
        param = c["param"] or ""
        evid = (c["evidence"] or "")[:90]
        table.add_row(str(c["id"]), f"[{color}]{c['confidence']}/3[/{color}]",
                      c["vuln_class"], c["method"], c["url"], param, evid)
    console.print(table)


def cmd_candidate_status(candidate_id, status, note=None):
    if status not in ("verified", "false_positive", "new"):
        console.print(f"[red]Status must be verified|false_positive|new[/red]")
        sys.exit(1)
    memory.set_candidate_status(candidate_id, status, note)
    console.print(f"[green]Candidate {candidate_id} → {status}[/green]")


def cmd_briefing(target, limit=20):
    import guide
    print(guide.build_briefing(target, limit=limit, with_llm=False))


def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon DB CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("targets")
    p = sub.add_parser("stats")
    p.add_argument("target", nargs="?")

    p = sub.add_parser("findings")
    p.add_argument("target", nargs="?")
    p.add_argument("--all", action="store_true")
    p.add_argument("--severity")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("status")
    p.add_argument("finding_id", type=int)
    p.add_argument("status")
    p.add_argument("--note")

    p = sub.add_parser("js")
    p.add_argument("target", nargs="?")

    p = sub.add_parser("ports")
    p.add_argument("target", nargs="?")

    p = sub.add_parser("subdomains")
    p.add_argument("target", nargs="?")

    p = sub.add_parser("history")
    p.add_argument("target", nargs="?")

    p = sub.add_parser("out-of-scope")
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("candidates")
    p.add_argument("target", nargs="?")
    p.add_argument("--class", dest="vuln_class")
    p.add_argument("--confidence", type=int, default=1)
    p.add_argument("--status", default="new", help="new|verified|false_positive|all")
    p.add_argument("--limit", type=int, default=100)

    p = sub.add_parser("cand-status")
    p.add_argument("candidate_id", type=int)
    p.add_argument("status")
    p.add_argument("--note")

    p = sub.add_parser("briefing")
    p.add_argument("target")
    p.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()

    if args.cmd == "targets":
        list_targets()
    elif args.cmd == "stats":
        cmd_stats(getattr(args, "target", None))
    elif args.cmd == "findings":
        cmd_findings(args.target, args.all, args.severity, args.json)
    elif args.cmd == "status":
        cmd_status(args.finding_id, args.status, args.note)
    elif args.cmd == "js":
        cmd_js(args.target)
    elif args.cmd == "ports":
        cmd_ports(args.target)
    elif args.cmd == "subdomains":
        cmd_subdomains(args.target)
    elif args.cmd == "history":
        cmd_history(args.target)
    elif args.cmd == "out-of-scope":
        cmd_out_of_scope(args.target, args.limit)
    elif args.cmd == "candidates":
        cmd_candidates(args.target, args.vuln_class, args.confidence, args.status, args.limit)
    elif args.cmd == "cand-status":
        cmd_candidate_status(args.candidate_id, args.status, args.note)
    elif args.cmd == "briefing":
        cmd_briefing(args.target, args.limit)


if __name__ == "__main__":
    main()
