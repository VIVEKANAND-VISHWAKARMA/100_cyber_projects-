#!/usr/bin/env python3
"""
Read-only FastAPI web dashboard over the recon.sqlite3 database.

Usage:
    python3 scripts/dashboard.py           # serves on 127.0.0.1:8000
    python3 scripts/dashboard.py --host 0.0.0.0

Endpoints:
    GET /                 high-level overview (HTML)
    GET /target/<name>    per-target detail (HTML)
    GET /api/stats        JSON stats
    GET /api/findings     JSON findings
    GET /api/subdomains   JSON subdomains
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import memory

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn


app = FastAPI(title="Bug Bounty Recon Dashboard")


def _html_page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115;color:#e6e6e6;margin:0 }}
 header {{ background:#1a1d24;padding:14px 24px;border-bottom:1px solid #2a2e38 }}
 header a {{ color:#40a9ff;text-decoration:none;margin-right:16px }}
 h1 {{ margin:0;font-size:18px }}
 .wrap {{ padding:20px 24px }}
 a {{ color:#40a9ff }}
 table {{ border-collapse:collapse;width:100%;font-size:13px;margin-bottom:20px }}
 th {{ text-align:left;color:#888;padding:6px 10px;border-bottom:1px solid #2a2e38 }}
 td {{ padding:6px 10px;border-bottom:1px solid #20242c;word-break:break-all }}
 .sev-critical{{color:#ff4d4f}} .sev-high{{color:#ff7a45}} .sev-medium{{color:#faad14}} .sev-low{{color:#40a9ff}}
 .cards {{ display:flex;gap:14px;flex-wrap:wrap;margin:10px 0 24px }}
 .card {{ background:#1a1d24;border:1px solid #2a2e38;border-radius:8px;padding:12px 18px;min-width:100px }}
 .card b {{ font-size:20px;display:block }} .card span {{ color:#888;font-size:11px;text-transform:uppercase }}
</style></head>
<body><header><a href="/">Home</a><a href="/api/stats">Stats JSON</a><a href="/api/findings">Findings JSON</a></header>
<div class="wrap">{body}</div></body></html>"""


def _target_links():
    conn = memory._connect()
    try:
        targets = [r["target"] for r in conn.execute(
            "SELECT DISTINCT target FROM subdomains ORDER BY target").fetchall()]
    finally:
        conn.close()
    return "".join(f'<a href="/target/{t}">{t}</a> ' for t in targets)


@app.get("/", response_class=HTMLResponse)
def home():
    stats = memory.get_stats()
    cards = "".join(
        f'<div class="card"><b>{v}</b><span>{k.replace("_", " ")}</span></div>'
        for k, v in stats.items() if not isinstance(v, dict)
    )
    body = f'<p><b>Targets:</b></p><p>{_target_links()}</p><div class="cards">{cards}</div>'
    return _html_page("Recon Dashboard", body)


@app.get("/target/{target}", response_class=HTMLResponse)
def target_page(target: str):
    stats = memory.get_stats(target)
    findings = memory.get_all_findings(target)
    open_f = [f for f in findings if f["status"] == "new"]

    cards = "".join(
        f'<div class="card"><b>{v}</b><span>{k.replace("_", " ")}</span></div>'
        for k, v in stats.items() if not isinstance(v, dict)
    )

    f_rows = "".join(
        f'<tr><td>{f["id"]}</td><td class="sev-{f["severity"]}">{f["severity"]}</td>'
        f'<td>{f["status"]}</td><td>{f["template_id"]}</td><td>{f["url"]}</td></tr>'
        for f in open_f
    )
    f_table = (f'<h3>Open findings ({len(open_f)})</h3><table>'
               f'<tr><th>ID</th><th>Sev</th><th>Status</th><th>Template</th><th>URL</th></tr>{f_rows}</table>'
               if open_f else "")

    subs = [dict(r) for r in memory._connect().execute(
        "SELECT * FROM subdomains WHERE target = ? ORDER BY domain", (target,)).fetchall()]
    conn = memory._connect()
    try:
        ports = [dict(r) for r in conn.execute(
            "SELECT * FROM ports WHERE target = ? ORDER BY host, port", (target,)).fetchall()]
    finally:
        conn.close()
    s_rows = "".join(
        f'<tr><td>{s["domain"]}</td><td>{s["status"]}</td><td>{s["ip"]}</td>'
        f'<td>{s["tech_stack"]}</td></tr>' for s in subs
    )
    s_table = f'<h3>Subdomains ({len(subs)})</h3><table><tr><th>Domain</th><th>Status</th><th>IP</th><th>Tech</th></tr>{s_rows}</table>'

    p_rows = "".join(
        f'<tr><td>{p["host"]}</td><td>{p["port"]}</td><td>{p["service"]}</td></tr>' for p in ports
    )
    p_table = f'<h3>Open ports ({len(ports)})</h3><table><tr><th>Host</th><th>Port</th><th>Service</th></tr>{p_rows}</table>' if ports else ""

    body = f'<p><a href="/">← back</a></p><h1>{target}</h1><div class="cards">{cards}</div>{f_table}{s_table}{p_table}'
    return _html_page(target, body)


@app.get("/api/stats")
def api_stats(target: str = None):
    if target:
        return JSONResponse(memory.get_stats(target))
    conn = memory._connect()
    try:
        targets = [r["target"] for r in conn.execute(
            "SELECT DISTINCT target FROM subdomains ORDER BY target").fetchall()]
    finally:
        conn.close()
    return JSONResponse({t: memory.get_stats(t) for t in targets})


@app.get("/api/findings")
def api_findings(target: str = None, severity: str = None):
    findings = memory.get_all_findings(target)
    if severity:
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        min_o = order.get(severity.lower(), 1)
        findings = [f for f in findings if order.get(f["severity"], 1) >= min_o]
    return JSONResponse(findings)


@app.get("/api/subdomains")
def api_subdomains(target: str = None):
    conn = memory._connect()
    try:
        if target:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM subdomains WHERE target = ? ORDER BY domain", (target,)).fetchall()]
        else:
            rows = [dict(r) for r in conn.execute("SELECT * FROM subdomains ORDER BY domain").fetchall()]
    finally:
        conn.close()
    return JSONResponse(rows)


@app.get("/api/ports")
def api_ports(target: str = None):
    conn = memory._connect()
    try:
        if target:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM ports WHERE target = ?", (target,)).fetchall()]
        else:
            rows = [dict(r) for r in conn.execute("SELECT * FROM ports").fetchall()]
    finally:
        conn.close()
    return JSONResponse(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(f"[+] Dashboard: http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
