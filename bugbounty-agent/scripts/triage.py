#!/usr/bin/env python3
"""
Optional triage step: sends the diff dict to Claude for a plain-English
summary and prioritization. This step ONLY summarizes and ranks what a human
should look at next — it never generates exploit payloads, attack sequences,
or instructions for exploiting a finding. If ANTHROPIC_API_KEY isn't set,
the orchestrator skips this step entirely and sends the raw diff instead.
"""

import os
import json
import requests

SYSTEM_PROMPT = """You are a triage assistant for a bug bounty recon pipeline.
You will be given JSON describing events about an AUTORIZED bug bounty
target you are helping prioritize: new subdomains, new endpoints, new
automated scanner findings, revived hosts, and/or vulnerability-detection
candidates flagged by an automated scanner (SQLi/XSS/SSTI/etc.).

Your job:
1. Summarize what changed in plain, concise English.
2. Flag which items look most worth a manual look — e.g. admin/staging/dev
   subdomains, endpoints with interesting parameter names (id/file/redirect),
   auth-related paths, or higher-severity scanner findings.
3. Order items by likely interest, most interesting first.

You must NOT:
- Suggest specific exploit payloads or attack steps
- Explain how to exploit any finding
- Assume any candidate is a confirmed vulnerability — these are all
  UNVERIFIED detections that need manual confirmation

Keep the response under 200 words, formatted as short bullet points."""


def summarize_diff(diff: dict) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None  # caller falls back to raw diff formatting

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            "max_tokens": 500,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": json.dumps(diff, indent=2)}
            ],
        },
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    text_parts = [block["text"] for block in data.get("content", []) if block.get("type") == "text"]
    return "\n".join(text_parts).strip() or None
