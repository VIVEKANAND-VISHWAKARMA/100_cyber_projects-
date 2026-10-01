#!/usr/bin/env python3
"""
Guide / briefing companion.

After a scan (or on demand), this produces a prioritized manual-testing
checklist so the agent "guides" your next move instead of just dumping data:

  - top vulnerability candidates by confidence (from vuln_scanner)
  - highest-value endpoints to poke (params hinting at IDOR/SSRF/LFI/SSTI)
  - new findings worth manual verification
  - optionally a Claude-powered plain-English briefing if ANTHROPIC_API_KEY set

Usage:
    python3 guide.py --target example.com [--limit 20] [--print]
    python3 guide.py --target example.com --json
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import memory
import vuln_scanner
import triage


def interesting_endpoints_section(target, limit=10):
    ranked = vuln_scanner.rank_param_urls(target, limit=limit)
    if not ranked:
        return []
    lines = [f"Top {len(ranked)} endpoints with interesting params (IDOR/SSRF/LFI/SSTI candidates):"]
    for score, url, params in ranked:
        lines.append(f"  [{score}x] {url}   params: {', '.join(params)}")
    return lines


def findings_section(target, limit=10):
    open_f = memory.get_open_findings(target)
    if not open_f:
        return []
    sev = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    open_f.sort(key=lambda f: -sev.get(f["severity"], 1))
    lines = [f"Open scanner findings worth manual verification ({len(open_f)}):"]
    for f in open_f[:limit]:
        lines.append(f"  [{f['severity'].upper()}] {f['template_id']} — {f['url']}  (id {f['id']})")
    return lines


def candidates_section(target, limit=20):
    lines = vuln_scanner.guide_from_candidates(target, limit=limit)
    return lines


def mission_summary(target):
    stats = memory.get_stats(target)
    return (f"Attack surface for [{target}]: {stats['subdomains']} subdomains "
            f"({stats['alive_hosts']} alive), {stats['endpoints']} endpoints, "
            f"{stats['open_findings']} open scanner findings, "
            f"{memory.get_candidate_stats(target)['total']} vuln candidates.")


def build_briefing(target, limit=20, with_llm=True):
    sections = []
    sections.append(mission_summary(target))

    parts = {
        "candidates": candidates_section(target, limit),
        "endpoints": interesting_endpoints_section(target, limit=min(limit, 12)),
        "findings": findings_section(target, limit=min(limit, 12)),
    }

    if with_llm:
        try:
            summary = triage.summarize_diff({"target": target, **{k: v for k, v in parts.items()}})
            if summary:
                sections.insert(0, f"## AI briefing\n{summary}")
        except Exception as e:
            print(f"[!] LLM briefing skipped: {e}")

    for key, lines in parts.items():
        if lines:
            sections.append(f"## {key.replace('_', ' ').capitalize()}")
            sections.extend(lines)

    if len(sections) == 1:
        sections.append("Nothing to guide on yet — run the orchestrator to build attack surface.")
    return "\n\n".join(sections)


def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon guide/briefing")
    parser.add_argument("--target", required=True)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--no-llm", action="store_true", help="skip Claude briefing")
    parser.add_argument("--json", action="store_true", help="emit raw JSON instead of text")
    args = parser.parse_args()

    if args.json:
        out = {
            "target": args.target,
            "mission": mission_summary(args.target),
            "candidates": memory.get_candidates(target=args.target, status="new")[:args.limit],
            "interesting_endpoints": vuln_scanner.rank_param_urls(args.target, limit=args.limit),
            "open_findings": memory.get_open_findings(args.target)[:args.limit],
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print(build_briefing(args.target, args.limit, with_llm=not args.no_llm))


if __name__ == "__main__":
    main()