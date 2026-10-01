#!/usr/bin/env python3
"""
netmon.py - Personal network activity logger for Linux.

Logs, for every process on this machine, when it opens a network connection,
to which remote address/hostname, and how long the connection stayed open.
Everything is written to a local SQLite database. Nothing leaves the machine.

This captures connection METADATA only (process, remote host, port, timing) -
it does NOT capture page content, keystrokes, or screen contents.

Usage:
    python3 netmon.py                 # run in foreground, poll every 2s
    python3 netmon.py --interval 5    # poll every 5s instead

Note: seeing connections for processes owned by other users (or full detail
on some processes) requires running with sudo. On a single-user laptop,
running as your own user is usually enough to see your own apps.
"""

import argparse
import signal
import socket
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    sys.exit("Missing dependency. Install with: pip install psutil --break-system-packages")

DB_DIR = Path.home() / ".local" / "share" / "netmon"
DB_PATH = DB_DIR / "netmon.db"

_hostname_cache = {}
_running = True


def resolve_hostname(ip, timeout=0.3):
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = ""
    finally:
        socket.setdefaulttimeout(old_timeout)
    _hostname_cache[ip] = host
    return host


def init_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            process_name TEXT,
            exe_path TEXT,
            remote_ip TEXT,
            remote_port INTEGER,
            hostname TEXT,
            local_port INTEGER,
            start_time TEXT,
            end_time TEXT,
            duration_seconds REAL
        )
        """
    )
    conn.commit()
    return conn


def process_info(pid):
    try:
        p = psutil.Process(pid)
        return p.name(), (p.exe() if p.exe() else "")
    except Exception:
        return "unknown", ""


def snapshot():
    """Return dict keyed by (pid, laddr, raddr) -> connection info for all
    current established connections with a remote address."""
    result = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        sys.exit(
            "Permission denied reading connections. Try running with sudo:\n"
            "  sudo python3 netmon.py"
        )
    for c in conns:
        if not c.raddr or not c.pid:
            continue
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        key = (c.pid, c.laddr.port if c.laddr else None, c.raddr.ip, c.raddr.port)
        result[key] = {
            "pid": c.pid,
            "local_port": c.laddr.port if c.laddr else None,
            "remote_ip": c.raddr.ip,
            "remote_port": c.raddr.port,
        }
    return result


def main():
    global _running
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds")
    args = parser.parse_args()

    conn = init_db()
    active = {}  # key -> {start_time, pid, process_name, exe_path, remote_ip, remote_port, local_port, hostname}

    def flush_all(*_):
        global _running
        _running = False
        now = datetime.now()
        for info in active.values():
            write_record(conn, info, now)
        conn.commit()
        conn.close()
        print("\nnetmon stopped, log flushed.")
        sys.exit(0)

    signal.signal(signal.SIGINT, flush_all)
    signal.signal(signal.SIGTERM, flush_all)

    print(f"netmon logging to {DB_PATH} (Ctrl+C to stop)")

    while _running:
        current = snapshot()
        now = datetime.now()

        # New connections
        for key, c in current.items():
            if key not in active:
                name, exe = process_info(c["pid"])
                hostname = resolve_hostname(c["remote_ip"])
                active[key] = {
                    "start_time": now,
                    "pid": c["pid"],
                    "process_name": name,
                    "exe_path": exe,
                    "remote_ip": c["remote_ip"],
                    "remote_port": c["remote_port"],
                    "local_port": c["local_port"],
                    "hostname": hostname,
                }

        # Closed connections
        for key in list(active.keys()):
            if key not in current:
                write_record(conn, active[key], now)
                del active[key]

        conn.commit()
        time.sleep(args.interval)


def write_record(conn, info, end_time):
    duration = (end_time - info["start_time"]).total_seconds()
    if duration < 1:
        return  # skip noise blips
    conn.execute(
        """INSERT INTO connections
           (pid, process_name, exe_path, remote_ip, remote_port, hostname, local_port,
            start_time, end_time, duration_seconds)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            info["pid"],
            info["process_name"],
            info["exe_path"],
            info["remote_ip"],
            info["remote_port"],
            info["hostname"],
            info["local_port"],
            info["start_time"].isoformat(),
            end_time.isoformat(),
            duration,
        ),
    )


if __name__ == "__main__":
    main()
