# Architecture

## 1. High-level flow

```
                         ┌────────────────────────┐
                         │   SCHEDULER (opt-in)   │
                         │ --schedule 6h or cron  │
                         └───────────┬────────────┘
                                     │
                                     ▼
                    ┌───────────────────────────────┐
                    │        ORCHESTRATOR            │
                    │     (orchestrator.py)          │
                    │  reads targets/scope.txt       │
                    │  + per-target YAML overrides   │
                    └───────────────────┬───────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                 ▼                                 ▼
┌─────────────┐   ┌──────────────┐   ┌───────────────────────────────┐
│ scope_guard │   │  PASSIVE     │   │  ACTIVE (via tools.py)         │
│ allowlist   │   │  (passive.py) │   │  subfinder ──┐                 │
│ + wildcard  │   │  crt.sh       │◀─▶│  crt.sh    ──┼── subdomains    │
│ + IP guard  │   │  Wayback CDX  │   │  Shodan      └─► httpx (live)  │
└─────────────┘   │  Shodan API   │   │                katana (crawl) │
                  └──────────────┘   │                masscan (ports) │
                                     │                nuclei (scan)    │
                                     └───────────────┬───────────────┘
                                                     │
                     ┌───────────────────────────────▼────────────────┐
                     │               MEMORY LAYER (memory.py)          │
                     │             db/recon.sqlite3                    │
                     │  subdomains | endpoints | findings | scan_runs  │
                     │  js_files  | ports | out_of_scope_hits |        │
                     │  tech_changes                                   │
                     └───────────────────────────────┬────────────────┘
                                                     │
                                                     ▼
                     ┌───────────────────────────────┬────────────────┐
                     │           DIFF ENGINE          │                │
                     │      (diff_engine.py)          │                │
                     │  new_subdomains · new_endpoints│                │
                     │  new_findings · revived_hosts  │                │
                     │  dead_hosts · js_changes       │                │
                     │  new_ports                     │                │
                     └──────────────────┬────────────┴────────┬───────┘
                                        ▼                       ▼
                        ┌────────────────────────┐   ┌────────────────────┐
                        │   TRIAGE (optional)     │   │   NOTIFIER          │
                        │   (triage.py) Claude    │──▶│   (notifier.py)     │
                        │   summarizes + ranks    │   │   Discord/Telegram/ │
                        │   — no exploit gen      │   │   Email webhook     │
                        └────────────────────────┘   └────────────────────┘

                        Plus side channels:
                        ┌──────────────┐ ┌──────────────┐ ┌─────────────┐
                        │ cli.py       │ │ dashboard.py │ │ report.py   │
                        │ (manage some)│ │ (FastAPI     │ │ (HTML       │
                        │              │ │  read view)  │ │  generator) │
                        └──────────────┘ └──────────────┘ └─────────────┘
```

## 2. Component responsibilities

### Orchestrator (`orchestrator.py`)
- Single entrypoint, run manually, via the built-in opt-in `--schedule`
  loop, or by external cron. Accepts `--target-file`,
  `--target`, `--workers` (parallel per-target processes).
- For each target: detect wildcard DNS, enumerate subdomains in parallel
  (subfinder + crt.sh), run the scope guard, probe live hosts with httpx,
  crawl endpoints with katana, pull Wayback history, hash JS bundles,
  optionally port-scan with masscan, run nuclei (default templates only).
- Feeds results to `memory.py`, builds a diff, optionally Claude-triaged,
  then notifies.
- All external tool subprocesses go through `tools.py` which adds timeouts,
  retries/backoff, and rate-limit flags.

### Scope guard (`scope_guard.py`)
- `filter_in_scope_domains` / `filter_in_scope_urls`: hard allowlist check
  against the target root domain.
- `validate_ip_in_private_range`: rejects RFC1918/reserved IPs.
- `detect_wildcard`: one-shot random-subdomain DNS probe.
- Every rejected host is recorded in `out_of_scope_hits` for audit.

### Passive discovery (`passive.py`)
- `crtsh_subdomains`: Certificate Transparency log dump.
- `wayback_urls` / `wayback_js_files`: Wayback CDX historical URL discovery.
- `shodan_host_info` / `shodan_ports`: passive service/port/banner intel
  (needs `SHODAN_API_KEY`). Runs against already-known IPs only.

### Tool executor (`tools.py`)
- `run_tool`: subprocess wrapper with retry + backoff + timeout.
- Wrappers: `subfinder`, `probe_httpx`, `crawl_katana`, `scan_nuclei`,
  `scan_masscan`. Rate limits come from httpx/nuclei `-c`/`-rl` flags.
- `scan_nuclei` **always** uses default community detection templates and
  defaults to passive-safe severity filtering — never custom fuzz/exploit
  template paths unless you explicitly supply one in config/.env.

### JS diffing (`jsdiff.py`)
- Extracts `<script src>` URLs from each live page, downloads and SHA-256
  hashes the bundles (rescans only after `refetch_interval_days`), compares
  against `js_files` memory, and reports `new`/`changed`.
- `ignore_patterns` and `min_size_kb` reduce third-party/CDN noise.

### Memory (`memory.py`)
Schema is authoritative here; `init_db()` runs on import.
`upsert_*` functions set `first_seen` on insert and bump `last_seen` on
update — this is what makes the diff meaningful.

### Diff engine (`diff_engine.py`)
Pure comparison. Returns a plain dict:
```python
{
  "target", "phases",
  "new_subdomains", "new_endpoints",
  "new_findings",              # list of {template_id, url, severity}
  "new_finding_severities",    # {severity: count}
  "revived_hosts", "dead_hosts",
  "js_changes",                # list of {url, status}
  "new_ports",                 # list of {host, port, service}
  "has_changes",
}
```

### Triage (`triage.py`) — optional
Sends the diff JSON to the Anthropic Messages API with a system prompt that
ONLY asks for a plain-English summary and a manual-review priority ranking.
It explicitly forbids exploit payloads / attack steps.

### Notifier (`notifier.py`)
Formats the diff (or the triage summary) and sends to Discord webhook,
Telegram bot, and/or SMTP email. No channels configured → prints to console.

### CLI / Dashboard / Report
- `cli.py`: list/inspect findings and **vuln candidates** (with class +
  confidence filters), update status (`reviewed`/`reported`/`false_positive`/
  `reopen`, and `verified`/`false_positive` for candidates), view stats/
  history/JS/ports/subdomains/out-of-scope audit, and print a briefing.
- `guide.py`: builds a prioritized manual-testing checklist from stored
  candidates, interesting endpoints, and open findings; optional Claude
  plain-English briefing (`--no-llm` to skip).
- `dashboard.py`: FastAPI, read-only HTML + JSON endpoints
  (`/api/stats`, `/api/findings`, `/api/subdomains`, `/api/ports`).
- `report.py`: jinja2-rendered static HTML report per target.

### Vulnerability scanner (`vuln_scanner.py`)
Active detection (per-parameter, GET + POST forms):
- SQL injection — error signatures per backend, time-based (safe_mode caps
  at 3s), boolean-blind length diff (skipped when page reflects input)
- Reflected XSS — distinctive `bqt…` markers, reflection detection
- SSTI — engine-agnostic eval markers (`{{999999999*999999999}}` → distinctive
  `999999998000000001`); engine attribution on match
- LFI/path traversal — `../../etc/passwd` style content markers
- Command injection — time-based (`sleep 3`-family) + `;id`/`whoami`
  output-marker only (deliberately avoids reflection false positives)
- Open redirect (Location echo), CRLF/header injection (injected header echo)

Passive checks: security headers, cookie flags, server/X-Powered-By
disclosure, JS secret regexes, exposed admin/swagger/debug paths, backup &
`.git`/source files, directory listing, GraphQL introspection,
CORS origin-echo+credentials, subdomain-takeover HTTP signatures (heuristic —
DNS verification still required).

Every positive is stored in the `candidates` table with a confidence score
(1 needs-manual / 2 strong-signal / 3 signature-match) and evidence excerpt.
Nothing is ever auto-confirmed — a candidate is an instruction to look.

### Guide (`guide.py`)
Turns stored candidates + interesting endpoints (`id=`/`file=`/`redirect=`/…)
+ open findings into an ordered checklist with per-class manual-verification
tips (e.g. "Confirm which template engine, test eval only, do not chain to
RCE"). This is the "agent guides you" layer.

## 3. Database schema

```sql
CREATE TABLE IF NOT EXISTS subdomains (
    domain      TEXT PRIMARY KEY,
    target      TEXT NOT NULL,                 -- root domain / program
    first_seen  DATETIME NOT NULL,
    last_seen   DATETIME NOT NULL,
    status      TEXT,                          -- 'alive' | 'dead'
    ip          TEXT,
    tech_stack  TEXT                           -- comma-separated
);

CREATE TABLE IF NOT EXISTS endpoints (
    url         TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    source      TEXT,                          -- 'katana' | 'wayback'
    first_seen  DATETIME NOT NULL,
    last_seen   DATETIME NOT NULL,
    params      TEXT                           -- comma-separated query params
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    template_id  TEXT NOT NULL,
    severity     TEXT,                          -- info|low|medium|high|critical
    url          TEXT NOT NULL,
    first_seen   DATETIME NOT NULL,
    last_seen    DATETIME NOT NULL,
    status       TEXT DEFAULT 'new',            -- new|reviewed|reported|false_positive
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
    status       TEXT DEFAULT 'new'             -- new | changed | unchanged
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

CREATE TABLE IF NOT EXISTS out_of_scope_hits (   -- scope-guard audit trail
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    host       TEXT NOT NULL,
    reason     TEXT,
    seen_at    DATETIME
);

CREATE TABLE IF NOT EXISTS tech_changes (        -- tech stack change history
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    domain     TEXT NOT NULL,
    old_tech   TEXT,
    new_tech   TEXT,
    changed_at DATETIME
);

CREATE TABLE IF NOT EXISTS candidates (          -- vuln_scanner detection log
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT NOT NULL,
    url            TEXT NOT NULL,
    param          TEXT,
    method         TEXT,                          -- GET | POST
    vuln_class     TEXT NOT NULL,                 -- sqli|xss|ssti|lfi|cmdi|...
    confidence     INTEGER DEFAULT 1,            -- 1 needs-manual | 2 strong-signal | 3 signature-match
    payload        TEXT,
    evidence       TEXT,
    status         TEXT DEFAULT 'new',            -- new | verified | false_positive
    notes          TEXT,
    first_seen     DATETIME NOT NULL,
    last_seen      DATETIME NOT NULL
);
```

## 4. Config

- `config.yaml` — global defaults (tool on/off, timeouts, rate limits,
  diffing filters, jsdiff, notification caps, dashboard host/port).
- `.env` — secrets (webhooks, API keys, SMTP).
- `targets/<root-domain>.yaml` — per-target override; merged shallow+deep.

## 5. Safety boundaries

This system performs **discovery, monitoring, and detection-only testing**:
- Passive OSINT (crt.sh, Wayback, Shodan) hits third parties minimally.
- Active tooling is limited to: DNS/HTTP probing, crawling, **default** nuclei
  detection templates, and the in-app DAST engine sending **detection**
  payloads (time-based tests capped, no data exfiltration, no destructive
  payloads, no persistent access).
- A hard **scope guard** drops anything not under the target root domain and
  records it.
- Findings and candidates always land in `new` status for the human to verify
  before reporting.

It does not generate exploit chains, brute-force credentials, exfiltrate
data, or decide for you what to report. Manual verification and reporting
stays with you.