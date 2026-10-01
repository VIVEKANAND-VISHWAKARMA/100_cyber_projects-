#!/usr/bin/env python3
"""
netmon-view.py - View and export the netmon activity log.

Usage:
    python3 netmon-view.py                      # today's activity
    python3 netmon-view.py --date 2026-07-23    # a specific day
    python3 netmon-view.py --app firefox        # filter by process name
    python3 netmon-view.py --domain google      # filter by hostname/domain
    python3 netmon-view.py --export csv out.csv
    python3 netmon-view.py --summary            # top apps / top domains only
"""

import argparse
import csv
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / ".local" / "share" / "netmon" / "netmon.db"


def fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


def fetch(args):
    if not DB_PATH.exists():
        sys.exit(f"No log found at {DB_PATH}. Has netmon.py been run yet?")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM connections WHERE 1=1"
    params = []
    if args.date:
        query += " AND date(start_time) = ?"
        params.append(args.date)
    else:
        query += " AND date(start_time) = date('now', 'localtime')"
    if args.app:
        query += " AND process_name LIKE ?"
        params.append(f"%{args.app}%")
    if args.domain:
        query += " AND (hostname LIKE ? OR remote_ip LIKE ?)"
        params.append(f"%{args.domain}%")
        params.append(f"%{args.domain}%")
    query += " ORDER BY start_time DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def print_table(rows):
    if not rows:
        print("No matching activity.")
        return
    print(f"{len(rows)} connections\n")
    print(f"{'time':<9} {'app':<20} {'host':<35} {'duration':>10}")
    print("-" * 78)
    for r in rows:
        t = datetime.fromisoformat(r["start_time"]).strftime("%H:%M:%S")
        host = r["hostname"] or r["remote_ip"]
        print(f"{t:<9} {r['process_name'][:19]:<20} {host[:34]:<35} {fmt_duration(r['duration_seconds']):>10}")


def print_summary(rows):
    if not rows:
        print("No activity for this period.")
        return
    by_app = {}
    by_domain = {}
    for r in rows:
        by_app[r["process_name"]] = by_app.get(r["process_name"], 0) + r["duration_seconds"]
        host = r["hostname"] or r["remote_ip"]
        by_domain[host] = by_domain.get(host, 0) + r["duration_seconds"]

    print("Top apps by time online:")
    for name, secs in sorted(by_app.items(), key=lambda x: -x[1])[:10]:
        print(f"  {name:<20} {fmt_duration(secs)}")

    print("\nTop domains/hosts contacted:")
    for host, secs in sorted(by_domain.items(), key=lambda x: -x[1])[:10]:
        print(f"  {host:<35} {fmt_duration(secs)}")


def export(rows, fmt, path):
    if fmt == "json":
        Path(path).write_text(json.dumps(rows, indent=2))
    elif fmt == "csv":
        if not rows:
            Path(path).write_text("")
        else:
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
    print(f"Exported {len(rows)} rows to {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--date", help="YYYY-MM-DD (default: today)")
    parser.add_argument("--app", help="Filter by process name substring")
    parser.add_argument("--domain", help="Filter by hostname/IP substring")
    parser.add_argument("--summary", action="store_true", help="Show top apps/domains only")
    parser.add_argument("--export", nargs=2, metavar=("FORMAT", "PATH"), help="Export: csv|json PATH")
    args = parser.parse_args()

    rows = fetch(args)

    if args.export:
        fmt, path = args.export
        export(rows, fmt, path)
        return

    if args.summary:
        print_summary(rows)
    else:
        print_table(rows)
        print()
        print_summary(rows)


if __name__ == "__main__":
    main()
