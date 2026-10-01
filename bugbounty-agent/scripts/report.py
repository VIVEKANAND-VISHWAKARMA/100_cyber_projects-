#!/usr/bin/env python3
"""
Generates a static HTML report summarizing everything tracked for a target
(or all targets). Reads straight from memory (SQLite) — no external deps
beyond jinja2 which is in requirements.txt.

Usage:
    python3 report.py [--target target.com] [--out reports/]
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import memory


def _collect(target=None):
    """Return a plain data structure ready for the template."""
    conn = memory._connect()
    try:
        if target:
            subs = [dict(r) for r in conn.execute(
                "SELECT * FROM subdomains WHERE target = ?", (target,)).fetchall()]
            eps = [dict(r) for r in conn.execute(
                "SELECT * FROM endpoints WHERE target = ?", (target,)).fetchall()]
            finds = [dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE target = ?", (target,)).fetchall()]
            js = [dict(r) for r in conn.execute(
                "SELECT * FROM js_files WHERE target = ?", (target,)).fetchall()]
            ports = [dict(r) for r in conn.execute(
                "SELECT * FROM ports WHERE target = ?", (target,)).fetchall()]
            runs = memory.get_scan_history(target)
            stats = memory.get_stats(target)
        else:
            subs = [dict(r) for r in conn.execute("SELECT * FROM subdomains").fetchall()]
            eps = [dict(r) for r in conn.execute("SELECT * FROM endpoints").fetchall()]
            finds = [dict(r) for r in conn.execute("SELECT * FROM findings").fetchall()]
            js = [dict(r) for r in conn.execute("SELECT * FROM js_files").fetchall()]
            ports = [dict(r) for r in conn.execute("SELECT * FROM ports").fetchall()]
            runs = memory.get_scan_history()
            stats = memory.get_stats()
    finally:
        conn.close()

    targets = sorted(set([s["target"] for s in subs] +
                         [f["target"] for f in finds] +
                         [e["target"] for e in eps]))

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "target": target or "All targets",
        "targets": targets,
        "stats": stats,
        "subdomains": sorted(subs, key=lambda s: s["domain"]),
        "endpoints": sorted(eps, key=lambda e: e["url"]),
        "findings": sorted(finds, key=lambda f: (-(4 if f["severity"] == "high" else 3 if f["severity"] == "medium" else 2 if f["severity"] == "low" else 1), f["first_seen"] or "")),
        "js": js,
        "ports": sorted(ports, key=lambda p: p["host"]),
        "runs": runs,
        "out_of_scope": memory.get_out_of_scope_hits(target, 100),
    }


TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — {{ data.target }}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         background: #0f1115; color: #e6e6e6; }
  header { background: #1a1d24; padding: 18px 28px; border-bottom: 1px solid #2a2e38; }
  h1 { margin: 0; font-size: 20px; }
  header small { color: #888; }
  .stats { display: flex; flex-wrap: wrap; gap: 14px; padding: 18px 28px; }
  .stat { background: #1a1d24; border: 1px solid #2a2e38; border-radius: 8px;
          padding: 10px 18px; min-width: 110px; }
  .stat b { display: block; font-size: 22px; }
  .stat span { color: #888; font-size: 12px; text-transform: uppercase; }
  h2 { margin: 26px 28px 8px; font-size: 16px; border-bottom: 1px solid #2a2e38;
       padding-bottom: 6px; color: #9aa4b2; }
  table { border-collapse: collapse; width: calc(100% - 56px); margin: 8px 28px 26px;
          font-size: 13px; }
  th { text-align: left; color: #888; font-weight: 600; padding: 6px 10px;
       border-bottom: 1px solid #2a2e38; }
  td { padding: 6px 10px; border-bottom: 1px solid #20242c; word-break: break-all; }
  tr:hover td { background: #171a21; }
  .sev-critical { color: #ff4d4f; font-weight: 700; }
  .sev-high { color: #ff7a45; font-weight: 700; }
  .sev-medium { color: #faad14; }
  .sev-low { color: #40a9ff; }
  .sev-info { color: #888; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; }
  .b-new { background: #633a00; color: #faad14; }
  .b-reported { background: #003a18; color: #52c41a; }
  .b-fp { background: #4d1212; color: #ff4d4f; }
  .b-reviewed { background: #1a3d6e; color: #40a9ff; }
</style>
</head>
<body>
<header>
  <h1>Bug Bounty Recon Report</h1>
  <small>Target: {{ data.target }} · Generated {{ data.generated }}</small>
</header>

<div class="stats">
  {% for k, v in data.stats.items() %}{% if not v is mapping %}
  <div class="stat"><b>{{ v }}</b><span>{{ k.replace('_',' ') }}</span></div>
  {% endif %}{% endfor %}
</div>

<h2>Findings ({{ data.findings|length }})</h2>
<table>
  <tr><th>ID</th><th>Target</th><th>Severity</th><th>Status</th><th>Template</th><th>URL</th></tr>
  {% for f in data.findings %}
  <tr>
    <td>{{ f.id }}</td>
    <td>{{ f.target }}</td>
    <td class="sev-{{ f.severity }}">{{ f.severity }}</td>
    <td><span class="badge b-{{ f.status.replace('_','') if f.status != 'false_positive' else 'fp' }}">{{ f.status }}</span></td>
    <td>{{ f.template_id }}</td>
    <td>{{ f.url }}</td>
  </tr>
  {% endfor %}
</table>

<h2>Subdomains ({{ data.subdomains|length }})</h2>
<table>
  <tr><th>Domain</th><th>Status</th><th>IP</th><th>Tech</th><th>First seen</th><th>Last seen</th></tr>
  {% for s in data.subdomains %}
  <tr><td>{{ s.domain }}</td><td>{{ s.status }}</td><td>{{ s.ip }}</td><td>{{ s.tech_stack }}</td>
      <td>{{ (s.first_seen or '')[:16] }}</td><td>{{ (s.last_seen or '')[:16] }}</td></tr>
  {% endfor %}
</table>

<h2>Endpoints ({{ data.endpoints|length }})</h2>
<table>
  <tr><th>URL</th><th>Source</th><th>First seen</th></tr>
  {% for e in data.endpoints %}
  <tr><td>{{ e.url }}</td><td>{{ e.source }}</td><td>{{ (e.first_seen or '')[:16] }}</td></tr>
  {% endfor %}
</table>

<h2>Open Ports ({{ data.ports|length }})</h2>
<table>
  <tr><th>Host</th><th>Port</th><th>Service</th></tr>
  {% for p in data.ports %}
  <tr><td>{{ p.host }}</td><td>{{ p.port }}</td><td>{{ p.service }}</td></tr>
  {% endfor %}
</table>

<h2>Tracked JS files ({{ data.js|length }})</h2>
<table>
  <tr><th>URL</th><th>Status</th><th>Last fetched</th></tr>
  {% for j in data.js %}
  <tr><td>{{ j.url }}</td><td>{{ j.status }}</td><td>{{ (j.last_fetched or '')[:16] }}</td></tr>
  {% endfor %}
</table>

</body>
</html>
"""


def generate(target=None, out_dir="reports"):
    from jinja2 import Template
    data = _collect(target)
    tpl = Template(TEMPLATE)
    html = tpl.render(data=data)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    fname = Path(out_dir) / f"report-{target.replace('.', '_') if target else 'all'}.html"
    fname.write_text(html)
    print(f"[+] Report written to {fname}")
    return str(fname)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target")
    parser.add_argument("--out", default="reports")
    args = parser.parse_args()
    generate(args.target, args.out)
