#!/usr/bin/env python3
"""
Memory layer: owns all reads/writes to db/recon.sqlite3.

This is what gives the agent "state" across runs — every upsert_* function
sets first_seen only on initial insert, and always bumps last_seen. That's
the mechanism the diff engine relies on to know what's actually new.
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent.parent / "db" / "recon.sqlite3"

SCHEMA = """
CREATE TABLE IF NOT EXISTS subdomains (
    domain      TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    first_seen  DATETIME NOT NULL,
    last_seen   DATETIME NOT NULL,
    status      TEXT,
    ip          TEXT,
    tech_stack  TEXT
);

CREATE TABLE IF NOT EXISTS endpoints (
    url         TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    source      TEXT,
    first_seen  DATETIME NOT NULL,
    last_seen   DATETIME NOT NULL,
    params      TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    template_id  TEXT NOT NULL,
    severity     TEXT,
    url          TEXT NOT NULL,
    first_seen   DATETIME NOT NULL,
    last_seen    DATETIME NOT NULL,
    status       TEXT DEFAULT 'new',
    notes        TEXT,
    UNIQUE(target, template_id, url)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT NOT NULL,
    started_at     DATETIME NOT NULL,
    finished_at    DATETIME,
    new_subdomains INTEGER DEFAULT 0,
    new_endpoints  INTEGER DEFAULT 0,
    new_findings   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS js_files (
    url          TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    hash         TEXT,
    first_seen   DATETIME,
    last_fetched DATETIME,
    status       TEXT DEFAULT 'new' -- new | changed | unchanged
);

CREATE TABLE IF NOT EXISTS ports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    service    TEXT,
    first_seen DATETIME,
    last_seen  DATETIME,
    status     TEXT DEFAULT 'open',
    UNIQUE(host, port)
);

CREATE TABLE IF NOT EXISTS out_of_scope_hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    host       TEXT NOT NULL,
    reason     TEXT,
    seen_at    DATETIME
);

CREATE TABLE IF NOT EXISTS tech_changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    domain     TEXT NOT NULL,
    old_tech   TEXT,
    new_tech   TEXT,
    changed_at DATETIME
);

CREATE TABLE IF NOT EXISTS candidates (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT NOT NULL,
    url            TEXT NOT NULL,
    param          TEXT,                -- parameter name being tested (if any)
    method         TEXT,                -- GET | POST
    vuln_class     TEXT NOT NULL,       -- sqli|xss|ssti|lfi|cmdi|ssrf|open_redirect|cors|...
    confidence     INTEGER DEFAULT 1,   -- 1 needs-manual | 2 strong-signal | 3 confirmed-by-signature
    payload        TEXT,                -- the payload that triggered it
    evidence       TEXT,                -- excerpt from the response / reason
    status         TEXT DEFAULT 'new',  -- new | verified | false_positive
    notes          TEXT,
    first_seen     DATETIME NOT NULL,
    last_seen      DATETIME NOT NULL
);
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Ensure schema exists. Safe to call on every run."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------

def upsert_subdomain(target, domain, ip=None, status="alive", tech_stack=None):
    """Insert a subdomain if new, otherwise just update last_seen/status/ip/tech.
    Returns True if this was a brand-new row (i.e. genuinely new subdomain)."""
    conn = _connect()
    try:
        cur = conn.execute("SELECT * FROM subdomains WHERE domain = ?", (domain,))
        existing = cur.fetchone()
        now = _now()
        if existing:
            # Track tech stack changes
            if existing["tech_stack"] != tech_stack and tech_stack:
                _log_tech_change(conn, target, domain, existing["tech_stack"], tech_stack, now)
            conn.execute(
                """UPDATE subdomains
                   SET last_seen = ?, status = ?, ip = ?, tech_stack = ?
                   WHERE domain = ?""",
                (now, status, ip, tech_stack, domain),
            )
            conn.commit()
            return False
        else:
            conn.execute(
                """INSERT INTO subdomains
                   (domain, target, first_seen, last_seen, status, ip, tech_stack)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (domain, target, now, now, status, ip, tech_stack),
            )
            conn.commit()
            return True
    finally:
        conn.close()


def get_all_subdomains(target):
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM subdomains WHERE target = ?", (target,)
        ).fetchall()
        return {r["domain"]: dict(r) for r in rows}
    finally:
        conn.close()


def mark_subdomain_dead(target, domain):
    """A previously-alive subdomain didn't respond this run."""
    conn = _connect()
    try:
        conn.execute(
            "UPDATE subdomains SET status = 'dead', last_seen = ? WHERE domain = ?",
            (_now(), domain),
        )
        conn.commit()
    finally:
        conn.close()


def _log_tech_change(conn, target, domain, old, new, now):
    try:
        conn.execute(
            """INSERT INTO tech_changes (target, domain, old_tech, new_tech, changed_at)
               VALUES (?, ?, ?, ?, ?)""",
            (target, domain, old, new, now),
        )
        conn.commit()
    except sqlite3.Error:
        pass


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def upsert_endpoint(target, url, source=None, params=None):
    conn = _connect()
    try:
        cur = conn.execute("SELECT url FROM endpoints WHERE url = ?", (url,))
        existing = cur.fetchone()
        now = _now()
        if existing:
            conn.execute(
                "UPDATE endpoints SET last_seen = ?, source = ?, params = ? WHERE url = ?",
                (now, source, params, url),
            )
            conn.commit()
            return False
        else:
            conn.execute(
                """INSERT INTO endpoints
                   (url, target, source, first_seen, last_seen, params)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (url, target, source, now, now, params),
            )
            conn.commit()
            return True
    finally:
        conn.close()


def get_all_endpoints(target):
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM endpoints WHERE target = ?", (target,)
        ).fetchall()
        return {r["url"]: dict(r) for r in rows}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Findings (nuclei matches)
# ---------------------------------------------------------------------------

def upsert_finding(target, template_id, url, severity="info"):
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT id FROM findings WHERE target = ? AND template_id = ? AND url = ?",
            (target, template_id, url),
        )
        existing = cur.fetchone()
        now = _now()
        if existing:
            conn.execute(
                "UPDATE findings SET last_seen = ? WHERE id = ?",
                (now, existing["id"]),
            )
            conn.commit()
            return False
        else:
            conn.execute(
                """INSERT INTO findings
                   (target, template_id, severity, url, first_seen, last_seen, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'new')""",
                (target, template_id, severity, url, now, now),
            )
            conn.commit()
            return True
    finally:
        conn.close()


def get_open_findings(target=None, severity=None, limit=None):
    """Findings that haven't been marked reviewed/reported/false_positive yet."""
    conn = _connect()
    try:
        q = "SELECT * FROM findings WHERE status = 'new'"
        args = []
        if target:
            q += " AND target = ?"
            args.append(target)
        if severity:
            sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            min_order = sev_order.get(severity.lower(), 0)
            q += f" AND severity IN ({','.join(['?'] * len([s for s in sev_order if sev_order[s] >= min_order]))})"
            args += [s for s in sev_order if sev_order[s] >= min_order]
        q += " ORDER BY CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, first_seen DESC"
        if limit:
            q += " LIMIT ?"
            args.append(limit)
        rows = conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_findings(target=None):
    conn = _connect()
    try:
        if target:
            rows = conn.execute(
                "SELECT * FROM findings WHERE target = ? ORDER BY first_seen DESC", (target,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM findings ORDER BY first_seen DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def set_finding_status(finding_id, status, notes=None):
    """status: 'reviewed' | 'reported' | 'false_positive'"""
    conn = _connect()
    try:
        conn.execute(
            "UPDATE findings SET status = ?, notes = ? WHERE id = ?",
            (status, notes, finding_id),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# JS files
# ---------------------------------------------------------------------------

def get_all_js_files(target):
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM js_files WHERE target = ?", (target,)
        ).fetchall()
        return {r["url"]: dict(r) for r in rows}
    finally:
        conn.close()


def upsert_js_file(target, url, hash_value, status="new"):
    conn = _connect()
    try:
        now = _now()
        cur = conn.execute("SELECT url FROM js_files WHERE url = ?", (url,))
        existing = cur.fetchone()
        if existing:
            conn.execute(
                "UPDATE js_files SET hash = ?, last_fetched = ?, status = ? WHERE url = ?",
                (hash_value, now, status, url),
            )
            conn.commit()
        else:
            conn.execute(
                """INSERT INTO js_files (url, target, hash, first_seen, last_fetched, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (url, target, hash_value, now, now, status),
            )
            conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

def upsert_port(target, host, port, service=None):
    conn = _connect()
    try:
        now = _now()
        cur = conn.execute("SELECT id FROM ports WHERE host = ? AND port = ?", (host, port))
        existing = cur.fetchone()
        if existing:
            conn.execute(
                "UPDATE ports SET last_seen = ?, service = ?, status = 'open' WHERE id = ?",
                (now, service, existing["id"]),
            )
            conn.commit()
            return False
        else:
            conn.execute(
                """INSERT INTO ports (target, host, port, service, first_seen, last_seen, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'open')""",
                (target, host, port, service, now, now),
            )
            conn.commit()
            return True
    finally:
        conn.close()


def get_ports(target):
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM ports WHERE target = ?", (target,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Out-of-scope audit
# ---------------------------------------------------------------------------

def record_out_of_scope(target, host, reason=""):
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO out_of_scope_hits (target, host, reason, seen_at) VALUES (?, ?, ?, ?)",
            (target, host, reason, _now()),
        )
        conn.commit()
    finally:
        conn.close()


def get_out_of_scope_hits(target=None, limit=100):
    conn = _connect()
    try:
        if target:
            rows = conn.execute(
                "SELECT * FROM out_of_scope_hits WHERE target = ? ORDER BY seen_at DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM out_of_scope_hits ORDER BY seen_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Vulnerability candidates (vuln_scanner output)
# ---------------------------------------------------------------------------

def add_candidate(target, url, vuln_class, param=None, method="GET", confidence=1,
                  payload=None, evidence=None):
    """Store a potential vulnerability for human review. Deduplicates on
    (url, param, vuln_class, payload). Returns True if newly added."""
    conn = _connect()
    try:
        now = _now()
        cur = conn.execute(
            """SELECT id FROM candidates
               WHERE url = ? AND IFNULL(param,'') = IFNULL(?,'') AND vuln_class = ? AND IFNULL(payload,'') = IFNULL(?,'')""",
            (url, param, vuln_class, payload),
        )
        existing = cur.fetchone()
        if existing:
            conn.execute("UPDATE candidates SET last_seen = ? WHERE id = ?", (now, existing["id"]))
            conn.commit()
            return False
        conn.execute(
            """INSERT INTO candidates
               (target, url, param, method, vuln_class, confidence, payload, evidence,
                status, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)""",
            (target, url, param, method, vuln_class, confidence, payload, evidence, now, now),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def get_candidates(target=None, vuln_class=None, min_confidence=1, status="new", limit=200):
    conn = _connect()
    try:
        q = "SELECT * FROM candidates WHERE 1=1"
        args = []
        if status and status != "all":
            q += " AND status = ?"
            args.append(status)
        if target:
            q += " AND target = ?"
            args.append(target)
        if vuln_class:
            q += " AND vuln_class = ?"
            args.append(vuln_class)
        q += " AND confidence >= ?"
        args.append(min_confidence)
        q += " ORDER BY confidence DESC, first_seen DESC LIMIT ?"
        args.append(limit)
        rows = conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_candidates(target=None):
    return get_candidates(target=target, status="all", limit=10000)


def set_candidate_status(candidate_id, status, notes=None):
    """status: 'verified' | 'false_positive' | 'new'"""
    conn = _connect()
    try:
        conn.execute(
            "UPDATE candidates SET status = ?, notes = ?, last_seen = ? WHERE id = ?",
            (status, notes, _now(), candidate_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_candidate_stats(target=None):
    conn = _connect()
    try:
        where = "WHERE target = ?" if target else ""
        args = (target,) if target else ()
        rows = conn.execute(
            f"SELECT vuln_class, COUNT(*) c, MAX(confidence) mx FROM candidates {where} GROUP BY vuln_class",
            args,
        ).fetchall()
        by_status = {}
        for r in conn.execute(
            f"SELECT status, COUNT(*) c FROM candidates {where} GROUP BY status", args
        ).fetchall():
            by_status[r["status"]] = r["c"]
        return {
            "by_class": {r["vuln_class"]: {"count": r["c"], "max_confidence": r["mx"]} for r in rows},
            "by_status": by_status,
            "total": sum(r["c"] for r in rows),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scan run audit log
# ---------------------------------------------------------------------------

def start_scan_run(target):
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO scan_runs (target, started_at) VALUES (?, ?)",
            (target, _now()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def finish_scan_run(run_id, new_subdomains=0, new_endpoints=0, new_findings=0):
    conn = _connect()
    try:
        conn.execute(
            """UPDATE scan_runs
               SET finished_at = ?, new_subdomains = ?, new_endpoints = ?, new_findings = ?
               WHERE id = ?""",
            (_now(), new_subdomains, new_endpoints, new_findings, run_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan_history(target=None, limit=30):
    conn = _connect()
    try:
        if target:
            rows = conn.execute(
                "SELECT * FROM scan_runs WHERE target = ? ORDER BY started_at DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_stats(target=None):
    """Aggregate stats for the dashboard / analytics."""
    conn = _connect()
    try:
        where = "WHERE target = ?" if target else ""
        args = (target,) if target else ()

        sub = conn.execute(
            f"SELECT COUNT(*) c, SUM(CASE WHEN status='alive' THEN 1 ELSE 0 END) alive FROM subdomains {where}",
            args,
        ).fetchone()
        ep = conn.execute(f"SELECT COUNT(*) c FROM endpoints {where}", args).fetchone()
        find = conn.execute(
            f"""SELECT COUNT(*) c,
                       SUM(CASE WHEN status='new' THEN 1 ELSE 0 END) open
                FROM findings {where}""",
            args,
        ).fetchone()
        js = conn.execute(f"SELECT COUNT(*) c FROM js_files {where}", args).fetchone()
        ports = conn.execute(f"SELECT COUNT(DISTINCT host) c FROM ports {where}", args).fetchone()
        runs = conn.execute(f"SELECT COUNT(*) c FROM scan_runs {where}", args).fetchone()

        sev = {}
        for row in conn.execute(
            f"SELECT severity, COUNT(*) c FROM findings {where} GROUP BY severity", args
        ).fetchall():
            sev[row["severity"]] = row["c"]

        return {
            "subdomains": sub["c"] or 0,
            "alive_hosts": sub["alive"] or 0,
            "endpoints": ep["c"] or 0,
            "findings": find["c"] or 0,
            "open_findings": find["open"] or 0,
            "js_files": js["c"] or 0,
            "hosts_with_ports": ports["c"] or 0,
            "scan_runs": runs["c"] or 0,
            "severity": sev,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Discovery-source tracking helper
# ---------------------------------------------------------------------------

def update_scan_source_stamp(target):
    """No-op kept for API compatibility / potential future use."""
    return None


# Ensure schema exists on import
init_db()
