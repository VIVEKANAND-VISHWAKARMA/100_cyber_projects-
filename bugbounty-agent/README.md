# Bug Bounty Recon Agent (Advanced)

A stateful, memory-backed reconnaissance and monitoring pipeline for bug
bounty hunting. It continuously enumerates an **authorized** target's attack
surface (subdomains, live hosts, endpoints, ports, JS bundles, known vuln
signatures), remembers what it has already seen, and alerts you only about
what's **new or changed** since the last run — with an optional **LLM
triage** layer for plain-English prioritization.

This is a **recon and monitoring system**, not an autonomous attacker. It
does not generate exploits or perform intrusive attacks — it wraps
well-known, community-standard OSINT/recon tools and community-vetted nuclei
detection templates, then layers memory + diffing + optional AI triage on
top.

> **Responsible use:** only run this against programs where the domain is
> explicitly **in scope** and you are authorized. Re-read the program policy
> regularly — scope changes. Manual verification and reporting are on you.

---

## What's new in this build (vs. the base project)

| Capability | What it does |
|---|---|
| **Vulnerability candidate detection (DAST)** | Actively tests discovered pages/params/forms for **SQLi (error + time-blind + boolean-blind), XSS, SSTI (Jinja/Twig/Freemarker/etc.), LFI/path traversal, command injection, open redirect, CRLF/header injection**. Results are stored as **candidates** with a confidence score (1–3), never auto-confirmed. |
| **Passive security checks** | Security headers audit, cookie flags (HttpOnly/Secure/SameSite), server-banner disclosure, JS secret scanning (AWS/GCP/GitHub/Slack keys), exposed admin/swagger/debug paths, backup/source files, directory listing, GraphQL introspection, CORS misconfig (origin echo + credentials), subdomain-takeover response signatures. |
| **Guide / briefing** | `scripts/guide.py` and `cli.py briefing` produce a prioritized manual-testing checklist — top candidates by confidence, high-value endpoints (params hinting at IDOR/SSRF/LFI/SSTI), and what to do with each. Optional Claude-powered plain-English briefing. |
| **Scope guard** | Hard allowlist check — any discovered host not under your target's root domain is **blocked and audited** (db: `out_of_scope_hits`). Prevents accidental out-of-scope scanning. |
| **Wildcard-DNS detection** | Detects wildcard DNS on the target so we don't sputter against phantom subdomains. |
| **Parallel subdomain enum** | `subfinder` + **crt.sh CT logs** run concurrently and are merged. |
| **Passive discovery on steroids** | Wayback CDX historical URLs + **Shodan** (optional) for banners, services, and open ports — no direct target traffic. |
| **Port scanning** | Optional `masscan` integration (root required); Shodan-derived ports stored when no active scan is desired. |
| **JS bundle diffing** | Downloads + SHA-256 hashes JS files; alerts only when bundles **change** (fresh deploy = fresh bugs). Refetch interval & ignore patterns configurable. |
| **Dead-host tracking** | Hosts that went offline since the last run are reported, not just new ones. |
| **Rate limiting + retries** | Per-tool concurrency caps and retry/backoff; gentle by default for program rate limits. |
| **Per-target config** | `targets/<name>.yaml` overrides global `config.yaml` per program. |
| **HTML reports** | Static, shareable report per target (`scripts/report.py`). |
| **Web dashboard** | Read-only FastAPI dashboard over the DB (`scripts/dashboard.py`). |
| **CLI** | Manage findings, stats, subdomains, ports, JS, scan history (`scripts/cli.py`). |
| **Email notifications** | SMTP channel in addition to Discord/Telegram. |
| **Audit log** | Out-of-scope attempts + tech-stack change history tracked. |

---

## Architecture

```
scheduler (cron) ──► orchestrator.py
                      ├─ Wildcard detect + scope guard (allowlist)
                      ├─ subfinder ────┐  (parallel)
                      ├─ crt.sh ───────┴─► merged subdomain set
                      ├─ Shodan (passive, optional) ──► port/service intel
                      ├─ httpx ──► live hosts + tech detect + IPs
                      ├─ katana ──► endpoints
                      ├─ Wayback ──► historical endpoints (passive)
                      ├─ jsdiff ──► JS bundle hashing / change detect
                      ├─ masscan (optional, root) ──► open ports
                      ├─ nuclei ──► default detection templates only
                      │
                      └─┬─ memory (SQLite: subdomains / endpoints /
                        │      findings / js_files / ports / run log /
                        │      scan_runs / tech_changes)
                        ├─ diff engine (what changed? new / revived / dead /
                        │      js changes / new ports)
                        ├─ triage (optional Claude summary + prioritization)
                        └─ notifier (Discord / Telegram / Email)
```

---

## Requirements

Install external recon tools (each separately):

| Tool | Purpose | Install |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [katana](https://github.com/projectdiscovery/katana) | Endpoint crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [masscan](https://github.com/robertdavidgraham/masscan) *(optional)* | Port scanning | `sudo apt install masscan` (needs root) |

Python deps:

```bash
pip install -r requirements.txt
```

---

## Setup

1. Clone/copy this folder.
2. Add your **in-scope** root domains to `targets/scope.txt` (one per line).
3. Copy `.env.example` → `.env` and fill in your notification channels.
4. Init the DB (schema is also auto-created on first import):

   ```bash
   python3 scripts/init_db.py
   ```

5. Run one scan manually to seed memory:

   ```bash
   python3 scripts/orchestrator.py --target-file targets/scope.txt
   ```

   or a single ad-hoc target:

   ```bash
   python3 scripts/orchestrator.py --target example.com
   ```

6. *(Optional)* Repeat automatically. Scheduling is opt-in: by default every
   run is a one-shot scan. Either use the built-in scheduler or cron:

   Built-in scheduler (Ctrl-C to stop):
   ```bash
   python3 scripts/orchestrator.py --target-file targets/scope.txt --schedule 6h
   ```

   Or via external cron (any interval):
   ```
   0 */6 * * * cd /path/to/bugbounty-agent && /usr/bin/python3 scripts/orchestrator.py --target-file targets/scope.txt >> logs/cron.log 2>&1
   ```

---

## Per-target configuration

Create `targets/<root-domain>.yaml` to override the global `config.yaml` for
one program, e.g. gentler rate limits or stricter severity filter. See
`targets/_example.yaml` for a commented template.

---

## Daily workflow

```bash
# See what changed / what's new
python3 scripts/orchestrator.py --target-file targets/scope.txt

# Inspect findings
python3 scripts/cli.py findings
python3 scripts/cli.py findings --severity high
python3 scripts/cli.py findings example.com

# Triage a finding: review / report / false-positive
python3 scripts/cli.py status 42 reported --note "Reported as #12345"
python3 scripts/cli.py status 42 false_positive --note "WAF noise"

# The vulnerability candidate workflow:
#   1) list what the scanner flagged (sorted by confidence)
python3 scripts/cli.py candidates
python3 scripts/cli.py candidates --class sqli
python3 scripts/cli.py candidates --confidence 2        # only strong signals
#   2) get a guided, prioritized manual-testing checklist
python3 scripts/cli.py briefing example.com
#   3) after manual verification, mark each candidate
python3 scripts/cli.py cand-status 15 verified          # you confirmed it
python3 scripts/cli.py cand-status 15 false_positive --note "reflection, not injectable"

# History & stats
python3 scripts/cli.py stats example.com
python3 scripts/cli.py history example.com
python3 scripts/cli.py js example.com
python3 scripts/cli.py ports
python3 scripts/cli.py out-of-scope

# Reports & dashboard
python3 scripts/report.py --target example.com
python3 scripts/dashboard.py                      # http://127.0.0.1:8000
```

---

## Scripts reference

| File | Purpose |
|---|---|
| `scripts/orchestrator.py` | Main pipeline entrypoint (tools chain + memory + diff + notify) |
| `scripts/vuln_scanner.py` | **DAST engine** — active + passive vulnerability candidate detection |
| `scripts/guide.py` | **Prioritized manual-testing briefing** (guides your next move) |
| `scripts/memory.py` | All DB read/write — the "state" of the agent (auto-creates schema) |
| `scripts/diff_engine.py` | What changed since last run (new/revived/dead, js, ports) |
| `scripts/scope_guard.py` | Scope allowlist + wildcard/DNS + private-IP guard |
| `scripts/passive.py` | crt.sh, Wayback CDX, Shodan passive discovery |
| `scripts/jsdiff.py` | JS bundle hashing + change detection |
| `scripts/tools.py` | External tool executor with timeouts/retries/rate limits |
| `scripts/triage.py` | Optional Claude API summary + prioritization (never exploits) |
| `scripts/notifier.py` | Discord / Telegram / Email notifications |
| `scripts/cli.py` | Finding, candidate & database management CLI |
| `scripts/dashboard.py` | Read-only FastAPI web dashboard |
| `scripts/report.py` | Static HTML report generator |
| `scripts/config.py` | YAML config loader (global + per-target merge) |
| `scripts/init_db.py` | Explicitly (re)create the schema |

## How to use this to actually find bugs

1. **Run it daily as your radar.** New subdomains, endpoints, ports, and JS
   bundle changes = freshly deployed code = where bugs live.
2. **Let the DAST engine test what it found.** `vuln_scanner.py` runs
   automatically after discovery and flags candidates across SQLi, XSS,
   SSTI, LFI, CMDi, redirects, CRLF, CORS, exposed panels, and more.
3. **Read the briefing, then verify by hand.** `cli.py briefing example.com`
   gives you a prioritized checklist. A candidate is *not* a bug — confirm
   impact manually before reporting (this is the only way to filter the
   false positives every scanner produces).
4. **Mark your work.** `cand-status <id> verified|false_positive` keeps the
   DB honest so you never re-review the same noise twice.
5. **The hard parts are yours by design.** Business logic, auth issues, IDORs,
   DOM XSS and chained attacks need a human understanding the app — the
   scanner builds the map and does the grunt work; you do the thinking.

---

## Database schema

Tables: **subdomains**, **endpoints**, **findings**, **scan_runs**,
**js_files**, **ports**, **out_of_scope_hits**, **tech_changes**. Full DDL is
in `scripts/memory.py` (kept authoritative) and documented in
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

---