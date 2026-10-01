#!/usr/bin/env python3
"""
Sends a formatted notification about the scan diff to Discord, Telegram,
and/or Email, depending on which endpoint env vars are set.

Email via standard SMTP (smtplib) using SMTP_HOST/PORT/USER/PASSWORD in .env.
"""

import os
import smtplib
from email.mime.text import MIMEText

import requests

from config import load_config

cfg = load_config()
MAX_ITEMS = cfg.get("notifications", {}).get("max_items_per_section", 25)


def _truncate(items, cap=MAX_ITEMS):
    items = list(items)
    if len(items) <= cap:
        return items
    return items[:cap] + [f"... and {len(items) - cap} more"]


def _format_diff_text(diff: dict, triage_summary: str | None) -> str:
    if triage_summary:
        return f"**Target: {diff['target']}**\n\n{triage_summary}"

    lines = [f"**Target: {diff['target']}**"]

    if diff["new_findings"]:
        sev = diff.get("new_finding_severities") or {}
        sev_str = ", ".join(f"{k}={v}" for k, v in sorted(sev.items())) if sev else ""
        lines.append(f"\n**New scanner findings ({len(diff['new_findings'])})** {sev_str}")
        lines += [
            f"- [{f['severity'].upper()}] {f['template_id']} — {f['url']}"
            for f in _truncate(diff["new_findings"])
        ]

    if diff["new_subdomains"]:
        lines.append(f"\n**New subdomains ({len(diff['new_subdomains'])}):**")
        lines += [f"- {d}" for d in _truncate(diff["new_subdomains"])]

    if diff["revived_hosts"]:
        lines.append(f"\n**Revived hosts ({len(diff['revived_hosts'])}):**")
        lines += [f"- {d}" for d in _truncate(diff["revived_hosts"])]

    if diff["dead_hosts"]:
        lines.append(f"\n**Hosts went offline ({len(diff['dead_hosts'])}):**")
        lines += [f"- {d}" for d in _truncate(diff["dead_hosts"])]

    if diff["new_endpoints"]:
        lines.append(f"\n**New endpoints ({len(diff['new_endpoints'])}):**")
        lines += [f"- {u}" for u in _truncate(diff["new_endpoints"])]

    if diff["js_changes"]:
        lines.append(f"\n**JS bundle changes ({len(diff['js_changes'])}):**")
        lines += [
            f"- [{c['status'].upper()}] {c['url']}"
            for c in _truncate(diff["js_changes"])
        ]

    if diff["new_ports"]:
        lines.append(f"\n**New open ports ({len(diff['new_ports'])}):**")
        lines += [
            f"- {p['host']}:{p['port']} ({p['service'] or 'unknown'})"
            for p in _truncate(diff["new_ports"])
        ]

    return "\n".join(lines)


def _send_discord(message: str):
    url = os.environ.get("DISCORD_WEBHOOK_URL")
    if not url:
        return False
    try:
        requests.post(url, json={"content": message[:1900]}, timeout=15)
        return True
    except requests.RequestException:
        return False


def _send_telegram(message: str):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        return False
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat, "text": message[:4000], "parse_mode": "Markdown"},
            timeout=15,
        )
        return True
    except requests.RequestException:
        return False


def _send_email(subject: str, body: str):
    host = os.environ.get("SMTP_HOST")
    to = os.environ.get("EMAIL_TO")
    if not host or not to:
        return False
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    from_addr = os.environ.get("EMAIL_FROM", user)

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to

    try:
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.starttls()
            if user:
                server.login(user, password)
            server.sendmail(from_addr, [to], msg.as_string())
        return True
    except Exception:
        return False


def notify(diff: dict, triage_summary: str | None = None):
    if not diff.get("has_changes"):
        return  # nothing new — stay quiet, don't spam

    message = _format_diff_text(diff, triage_summary)

    sent_any = False
    if _send_discord(message):
        sent_any = True
    if _send_telegram(message):
        sent_any = True
    if _send_email(f"[Recon] {diff['target']} — {len(diff['new_findings'])} new findings", message):
        sent_any = True

    if not sent_any:
        print("[!] No notification channels configured — printing to console instead:\n")
        print(message)
