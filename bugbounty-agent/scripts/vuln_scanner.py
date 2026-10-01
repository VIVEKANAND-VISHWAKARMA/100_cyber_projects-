#!/usr/bin/env python3
"""
Vulnerability detection engine (DAST layer) for authorized in-scope targets.

For every live URL / endpoint the pipeline discovered, this module:
  - probes the page (status, headers, body excerpt, timing)
  - discovers HTML forms and their input fields
  - sends conservative *detection* payloads across many vuln classes and
    scores the response (reflection, error signatures, timing, boolean diffs)
  - performs passive checks (security headers, cookie flags, exposed paths,
    JS secret scanning, subdomain-takeover signatures)
  - stores everything as "candidates" of varying confidence for the HUMAN to
    verify — never a confirmed bug on its own

SAFETY BOUNDARY (safe_mode, default ON):
  - time-based payloads capped at 3s (SLEEP(3)/pg_sleep(3)/WAITFOR 3s)
  - no data exfiltration, no persistent access, no destructive payloads
  - no heavy fuzzing / brute-forcing
  - every request goes through the scope guard and is rate-limited
  - confidence 3 (strongest) still requires manual verification —
    a "confidence" here means the *detection signature* matched, not that
    impact was proven.
"""

import base64
import hashlib
import random
import re
import string
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

import memory
import scope_guard
from config import env


USER_AGENT = "Mozilla/5.0 (compatible; BugBountyReconAgent/1.0; +in-scope authorized testing)"
MAX_BODY = 300_000


# ---------------------------------------------------------------------------
# Detection payload database
# ---------------------------------------------------------------------------

def _token(rng: random.Random) -> str:
    return "bqt" + "".join(rng.choices(string.hexdigits, k=6))


# time-based SQL delay markers (low-impact, safe_mode-friendly)
SQL_TIME_PAYLOADS = [
    ("mysql", "' OR SLEEP(3)-- -"),
    ("mysql2", "' AND (SELECT 1 FROM (SELECT SLEEP(3))a)-- -"),
    ("postgres", "'; SELECT pg_sleep(3)-- -"),
    ("mssql", "'; WAITFOR DELAY '0:0:3'--"),
    ("sqlite", "' AND 1=2 AND sleep(3)--"),   # sqlite lacks native sleep; low chance
]

# error-based SQL signatures -> backend detection
SQL_ERROR_SIGNATURES = [
    ("mysql", re.compile(r"(You have an error in your SQL syntax|Warning: mysql_|SQLSTATE\[HY[0-9]+\])", re.I)),
    ("postgres", re.compile(r"(PostgreSQL.*ERROR|syntax error at or near|PGRES)", re.I)),
    ("mssql", re.compile(r"(Unclosed quotation mark|Microsoft OLE DB Provider for SQL|Line \d+ near)", re.I)),
    ("oracle", re.compile(r"(ORA-[0-9]{5}|Oracle error)", re.I)),
    ("sqlite", re.compile(r"(sqlite3\.OperationalError|SQLite/JDBCDriver)", re.I)),
    ("generic", re.compile(r"(SQL syntax|DB Error|Database error|Unknown column|near \".*\": syntax)", re.I)),
]

# boolean-blind probe pair (non-destructive)
SQL_BOOL_TRUE = "1' AND '1'='1"
SQL_BOOL_FALSE = "1' AND '1'='2"

SSTI_PAYLOADS = [
    ("jinja/nunjucks", "{{999999999*999999999}}", "999999998000000001"),
    ("twig/django", "{{7*7}}", "49"),
    ("velocity/java", "$\\{999999999\\*999999999\\}", "999999998000000001"),
    ("freemarker", "${999999999*999999999}", "999999998000000001"),
    ("erb/ruby", "<%= 999999999*999999999 %>", "999999998000000001"),
    ("smarty", "{999999999*999999999}", "999999998000000001"),
]

# reflection markers for XSS / generic reflection
XSS_MARKERS = ["<bqt>", "'\"><bqt>", '" autofocus onfocus="bqt"', "\\';bqt;//"]

LFI_PAYLOADS = [
    ("unix", "../../../../etc/passwd", "root:x:0:0:"),
    ("linux_var", "....//....//....//etc/passwd", "root:x:0:0:"),
    ("win_var", "..\\..\\..\\windows\\win.ini", "for 16-bit"),
    ("null_var", "..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0:"),
]

# Command injection: time-based (low-impact sleep, safe_mode-capped) and
# output-marker detection (;id → "uid=" appears only if executed).
CMDI_TIME_PAYLOADS = [
    ("unix", ";sleep 3"),
    ("unix_subshell", "$(sleep 3)"),
    ("unix_backticks", "`sleep 3`"),
    ("windows_cmd", "& ping -n 3 127.0.0.1"),
]
CMDI_OUTPUT_PAYLOADS = [
    ("unix_id", ";id", re.compile(r"uid=[0-9]+\(")),
    ("unix_id_sub", "$(id)", re.compile(r"uid=[0-9]+\(")),
    ("win_whoami", "& whoami", re.compile(r"nt authority|eicar|desktop-[a-z0-9]", re.I)),
]

CRLF_PAYLOADS = ["%0d%0aX-BBQ-{t}: 1", "\r\nX-BBQ-{t}: 1", "%0d%0aSet-Cookie: bbq=1"]

# Open redirect URL values (sent to redirect-friendly params)
REDIRECT_PAYLOADS = ["//evil.example.com/", "https://evil.example.com/", "///evil.example.com"]

# SSRF-friendly: flag params that commonly hit backend fetchers, plus optional OAST time check
SSRF_PARAM_HINTS = [
    "url", "uri", "next", "target", "u", "dest", "redirect", "redir", "path", "file",
    "dir", "image", "img", "load", "fetch", "proxy", "download", "link", "goto", "open",
]

GRAPHQL_ENDPOINTS = ["/graphql", "/api/graphql", "/graph", "/gql", "/v1/graphql"]

# common exposed paths (non-intrusive; presence = interesting, not a vuln alone)
EXPOSED_PATHS = [
    "/admin", "/admin/", "/administrator", "/manage", "/wp-admin/", "/wp-login.php",
    "/login", "/login.php", "/dashboard", "/swagger", "/swagger-ui/", "/swagger/index.html",
    "/api-docs", "/api/docs", "/v2/api-docs", "/v3/api-docs", "/docs/", "/redoc",
    "/graphql", "/api/graphql", "/server-status", "/server-info", "/status",
    "/debug", "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
    "/console", "/.git/HEAD", "/.env", "/.ssh/id_rsa", "/config.php", "/configuration.php",
    "/phpinfo.php", "/phpinfo", "/test.php", "/info.php", "/elmah.axd",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/.DS_Store",
    "/WEB-INF/web.xml", "/application.properties", "/.env.local",
]

BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".save", ".swp", "~", ".zip", ".tar.gz",
                   ".sql", ".txt", ".log", ".inc", ".db", ".json", ".yaml", ".yml"]

BUILD_PATH_HINTS = ["/build", "/dist", "/public/build", "/static", "/assets", "/js", "/app"]

# file endings to treat as static asset (skipped for param testing)
STATIC_EXT = {".js", ".css", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
              ".woff2", ".ttf", ".eot", ".pdf", ".mp4", ".mp3", ".map", ".webp", ".zip",
              ".gz", ".min.js", ".min.css", ".txt"}

# subdomain-takeover-ish HTTP response signatures (heuristic only — verify DNS!)
TAKEOVER_SIGNATURES = [
    ("AWS S3", ["NoSuchBucket", "does not exist"]),
    ("Azure", ["ResourceNotFound", "The specified bucket does not exist"]),
    ("GitHub Pages", ["There isn't a GitHub Pages site here"]),
    ("Heroku", ["There's nothing here, yet", "herokudns.com"]),
    ("Shopify", ["Sorry, this shop is currently unavailable"]),
    ("Fastly", ["Fastly error: unknown domain"]),
    ("Pantheon", ["404 error unknown site!"]),
    ("Bitbucket", ["Repository not found"]),
    ("Wordpress.com", ["Do you want to register"]),
]

# JS secret patterns (passive)
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_secret", re.compile(r"aws_secret(_access_key)?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("google_api", re.compile(r"(AIza[0-9A-Za-z_-]{35})")),
    ("github_token", re.compile(r"(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("firebase_url", re.compile(r"https?://[a-z0-9-]+\.firebaseio\.com")),
    ("generic_api", re.compile(r"(api[_-]?key|apikey|secret|token|password)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.I)),
]

# cookie flags worth checking
CHECK_COOKIE_FLAG = ["Session", "XSRF", "csrf", "sid", "auth", "token"]


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class Probe:
    def __init__(self, cfg, session=None):
        self.cfg = cfg
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.threshold = cfg.get("time_threshold", 3)
        self.delay = cfg.get("request_delay", 0.3)

    def _pause(self):
        time.sleep(self.delay)

    def get(self, url, params=None, headers=None, timeout=None):
        self._pause()
        return self.session.get(url, params=params, headers=headers,
                                timeout=timeout or self.threshold + 4, stream=True)

    def post(self, url, data=None, headers=None, timeout=None):
        self._pause()
        return self.session.post(url, data=data, headers=headers,
                                 timeout=timeout or self.threshold + 4, stream=True)

    def read_body(self, resp):
        try:
            chunks = []
            for chunk in resp.iter_content(65536):
                chunks.append(chunk)
                if sum(len(c) for c in chunks) > MAX_BODY:
                    break
            return b"".join(chunks).decode("utf-8", "replace")
        except Exception:
            return ""


def reflect_marker_in_body(token, body):
    return token in body or token in urldecode(body)


def urldecode(s):
    from urllib.parse import unquote
    return unquote(s)


# ---------------------------------------------------------------------------
# Core per-parameter detection
# ---------------------------------------------------------------------------

def test_param(probe, target, url, method, param, config, results, as_post=False, side_data=None):
    """Run all active detection classes against a single parameter."""
    classes = config.get("classes", ALL_CLASSES)
    base_body, base_status, base_len, base_time = baseline(probe, url, method, param, as_post)
    rng = random.Random(hashlib.md5(f"{url}|{param}".encode()).hexdigest())
    token = _token(rng)

    findings = []

    def _emit(cls, confidence, payload, evidence):
        results["added"] += memory.add_candidate(
            target, url, cls, param=param, method=method,
            confidence=confidence, payload=payload, evidence=evidence,
        )
        results["scanned"] += 1

    # ---- SQL injection (error-based) ----
    if "sqli" in classes:
        probe_payload = "'"
        status, body, t = send(probe, url, method, param, probe_payload, as_post)
        if body:
            for backend, sig in SQL_ERROR_SIGNATURES:
                if sig.search(body):
                    _emit("sqli", 3, probe_payload, f"DB error signature ({backend}): {snippet(sig, body)}")
                    break

    # ---- SQL injection (time-based) ----
    if "sqli" in classes:
        for backend, pl in SQL_TIME_PAYLOADS:
            t0 = time.time()
            status, body, t = send(probe, url, method, param, pl, as_post)
            elapsed = time.time() - t0
            if elapsed >= config.get("time_threshold", 3) - 0.5 and elapsed > base_time + 2.5:
                _emit("sqli", 2 if backend != "sqlite" else 1,
                      pl, f"time-based delay observed ({backend}, {elapsed:.1f}s, baseline {base_time:.1f}s)")
                break  # one time-based hit is enough

    # ---- SQL injection (boolean blind) ----
    # Skip on pages that reflect input (the response diff is just reflection)
    if "sqli" in classes:
        _, tracker_body, _ = send(probe, url, method, param, "bqt" + token, as_post)
        page_reflects = bool(tracker_body) and "bqt" + token in tracker_body
        if not page_reflects:
            _, body_true, t_true = send(probe, url, method, param, SQL_BOOL_TRUE, as_post)
            _, body_false, t_false = send(probe, url, method, param, SQL_BOOL_FALSE, as_post)
            if body_true is not None and body_false is not None:
                lt = abs(len(body_true) - len(body_false))
                if len(body_true) > 200 and lt > len(base_body) * 0.05 and lt > 100:
                    _emit("sqli", 1, SQL_BOOL_FALSE,
                          f"boolean response length diff ({lt} bytes) between true/false")

    # ---- XSS / reflection ----
    if "xss" in classes:
        for marker_tpl in XSS_MARKERS:
            payload = marker_tpl.replace("bqt", token)
            status, body, t = send(probe, url, method, param, payload, as_post)
            if body and reflect_marker_in_body(token, body):
                _emit("xss", 1, payload, f"payload reflected in response")
                break

    # ---- SSTI ----
    if "ssti" in classes:
        for engine, pl, marker in SSTI_PAYLOADS:
            status, body, t = send(probe, url, method, param, pl, as_post)
            if body:
                # look for the evaluated result near the payload OR anywhere
                if marker in body:
                    _emit("ssti", 3, pl, f"template evaluated ({engine}): rendered {marker}")
                    break

    # ---- LFI / path traversal ----
    if "lfi" in classes:
        for name, pl, marker in LFI_PAYLOADS:
            status, body, t = send(probe, url, method, param, pl, as_post)
            if body and marker in body:
                _emit("lfi", 3, pl, f"file content marker found ({name})")
                break

    # ---- Command injection (time + output-marker only; avoids reflection FPs) ----
    if "cmdi" in classes:
        for name, pl in CMDI_TIME_PAYLOADS:
            t0 = time.time()
            status, body, t = send(probe, url, method, param, pl, as_post)
            elapsed = time.time() - t0
            if elapsed >= config.get("time_threshold", 3) - 0.5 and elapsed > base_time + 2.5:
                _emit("cmdi", 2, pl, f"time-based delay observed ({name}, {elapsed:.1f}s)")
                break
        for name, pl, out_re in CMDI_OUTPUT_PAYLOADS:
            status, body, t = send(probe, url, method, param, pl, as_post)
            if body and out_re.search(body):
                _emit("cmdi", 2, pl, f"command output marker observed ({name})")
                break

    # ---- Open redirect ----
    if "open_redirect" in classes:
        for pl in REDIRECT_PAYLOADS:
            r = probe.get(url, params={param: pl})
            loc = (r.headers.get("Location") or "").lower()
            if "evil.example.com" in loc:
                _emit("open_redirect", 2, pl, f"Location header: {loc}")
                r.close()
                break

    # ---- CRLF / header injection ----
    if "crlf" in classes:
        for raw in CRLF_PAYLOADS:
            payload_raw = raw.replace("{t}", token)
            r = probe.get(url, params={param: payload_raw})
            r.close()
            hdr_check = "x-bbq-{0}".format(token) in {k.lower() for k in r.headers}
            if hdr_check:
                # verify via the actual header value
                matched = any(v.lower() == token.lower() for v in r.headers.values())
                _emit("crlf", 2, payload_raw, "injected header observed in response")
                break

    return findings


def baseline(probe, url, method, param, as_post):
    status, body, t = send(probe, url, method, param, "aaq1", as_post)
    return (body or ""), status, (len(body) if body else 0), t


def send(probe, url, method, param, value, as_post):
    """Send one detection request; returns (status, body, elapsed)."""
    try:
        if as_post:
            r = probe.post(url, data={param: value})
        else:
            r = probe.get(url, params={param: value})
        elapsed = r.elapsed.total_seconds()
        status = r.status_code
        body = probe.read_body(r)
        r.close()
        return status, body, elapsed
    except requests.RequestException:
        return None, None, 0.0


def snippet(regex_or_str, body, span=140):
    if isinstance(regex_or_str, re.Pattern):
        m = regex_or_str.search(body)
        idx = m.start() if m else 0
    elif regex_or_str in body:
        idx = body.index(regex_or_str)
    else:
        idx = 0
    start = max(0, idx - 40)
    return body[start:start + span].replace("\n", " ")[:span]


ALL_CLASSES = ["sqli", "xss", "ssti", "lfi", "cmdi", "open_redirect", "crlf"]


# ---------------------------------------------------------------------------
# Passive checks
# ---------------------------------------------------------------------------

def passive_headers(probe, url, method, param, base_response_headers, results, target, config):
    """Security header + cookie flag audit on a single page (non-payload)."""
    headers = base_response_headers or {}
    if not headers:
        return

    # only report on HTML-ish or root pages to avoid asset noise
    ctype = (headers.get("Content-Type") or "").lower()
    if "text/" not in ctype and "json" not in ctype and "xml" not in ctype and ctype:
        return

    required = {
        "Strict-Transport-Security": "HSTS missing on HTTPS page",
        "Content-Security-Policy": "no content security policy",
        "X-Frame-Options": "no clickjacking protection (XFO)",
        "X-Content-Type-Options": "no MIME sniffing protection",
        "Referrer-Policy": "no referrer policy",
    }
    if url.lower().startswith("https:"):
        for hdr, msg in required.items():
            if hdr.lower() not in {k.lower() for k in headers}:
                memory.add_candidate(target, url, "security_headers", param=None,
                                     method=method, confidence=1, evidence=msg)

    # cookie flags
    sc = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    if sc:
        for raw in sc:
            name = raw.split(";")[0].split("=")[0].strip()
            if any(flag in name.lower() for flag in CHECK_COOKIE_FLAG) or name.lower() == "session":
                flagged = []
                if "httponly" not in raw.lower():
                    flagged.append("HttpOnly")
                if url.lower().startswith("https") and "secure" not in raw.lower():
                    flagged.append("Secure")
                if "samesite" not in raw.lower():
                    flagged.append("SameSite")
                if flagged:
                    memory.add_candidate(target, url, "cookie_flags", param=name,
                                         method=method, confidence=1,
                                         evidence=f"{name}: missing {', '.join(flagged)}")

    # info disclosure
    server = headers.get("Server", "")
    if server and re.search(r"nginx/[0-9]|apache/[0-9]|IIS/[0-9]|openresty/[0-9]", server):
        memory.add_candidate(target, url, "info_disclosure", param=None,
                             method=method, confidence=1, evidence=f"Server banner: {server}")
    if headers.get("X-Powered-By"):
        memory.add_candidate(target, url, "info_disclosure", confidence=1,
                             evidence=f"X-Powered-By: {headers.get('X-Powered-By')}")


def check_exposed_paths(probe, target, base_url, results, config):
    """Non-intrusive presence checks for common admin/debug/source paths."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    paths = config.get("exposed_paths") or EXPOSED_PATHS
    for path in paths:
        r = probe.get(origin + path)
        status = r.status_code
        body = probe.read_body(r)
        r.close()
        if status in (200, 301, 302, 307, 401, 403):
            hint = "interesting" if status != 200 else "accessible"
            memory.add_candidate(target, origin + path, "exposed_path", confidence=1,
                                 method="GET", evidence=f"HTTP {status} ({hint}), {len(body)} bytes")
            break  # one hit per origin is enough noise-trim

    # backup/source files (only check common config basenames, NOT every endpoint)
    for name, suffix in [("config", ".bak"), ("wp-config", ".php.bak"), (".env", ".swp"),
                         ("config", ".php~"), (".git", "/HEAD"), ("backup", ".zip")]:
        r = probe.get(origin + f"/{name}{suffix}" if suffix != "/HEAD" else origin + "/.git/HEAD")
        body = probe.read_body(r)
        r.close()
        if r.status_code == 200 and body and r.headers.get("Content-Type", "").startswith(("text", "application/octet")):
            if suffix == "/HEAD" and "ref:" in body:
                memory.add_candidate(target, origin + "/.git/HEAD", "source_exposed",
                                     confidence=3, evidence=".git/HEAD reachable (ref: ...)")
            elif len(body) > 50 or "<?php" in body.lower() or "=" in body[:200]:
                memory.add_candidate(target, origin + f"/{name}{suffix}", "backup_file",
                                     confidence=2, evidence=f"{len(body)} bytes fetched")


def check_directory_listing(probe, target, origin, results):
    r = probe.get(origin + "/")
    body = probe.read_body(r)
    r.close()
    if re.search(r"<title>Index of [^<]+</title>|Directory listing for|Parent Directory", body, re.I):
        memory.add_candidate(target, origin + "/", "directory_listing", confidence=2,
                             evidence="index-style listing")


def check_graphql(probe, target, base_url, results):
    parsed = urlparse(base_url)
    for ep in GRAPHQL_ENDPOINTS:
        url = f"{parsed.scheme}://{parsed.netloc}{ep}"
        try:
            r = probe.post(url, data={"query": "{__typename}"}, headers={"Content-Type": "application/json"})
            body = probe.read_body(r)
            r.close()
            if r.status_code == 200 and "__typename" in body:
                # introspection probe
                r = probe.post(url, json={"query": query_introspection()})
                ib = probe.read_body(r)
                r.close()
                if "types" in ib or "__schema" in ib:
                    memory.add_candidate(target, url, "graphql_introspection", confidence=2,
                                         method="POST", evidence="introspection query returned schema")
                    break
        except requests.RequestException:
            continue


def query_introspection():
    return "{__schema{types{name fields{name}}}}"


def check_cors(probe, target, url, headers_by_url, results):
    """Send a cross-origin request; if the response echoes the Origin with
    Allow-Origin AND Allow-Credentials, that's a candidate."""
    parsed = urlparse(url)
    if not parsed.path or parsed.path in ("/", "/favicon.ico"):
        return
    try:
        h = {"Origin": "https://evil.example.com"}
        r = probe.get(url, headers=h)
        aoa = (r.headers.get("Access-Control-Allow-Origin") or "").strip()
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").strip()
        r.close()
        if aoa == "https://evil.example.com" and acac.lower() == "true":
            memory.add_candidate(target, url, "cors_misconfig", confidence=2,
                                 method="GET", evidence="ACAO echoes attacker origin + ACAC=true")
    except requests.RequestException:
        return


def scan_js_secrets(probe, target, base_url, body, results):
    if not body:
        return
    for name, pat in SECRET_PATTERNS:
        m = pat.search(body)
        if m:
            secret = m.group(1) if m.lastindex else m.group(0)
            memory.add_candidate(target, base_url, "secret_exposure", confidence=2,
                                 evidence=f"{name}: {mask(secret)}")
            break


def mask(s, keep=6):
    return s[:keep] + "..." + s[-4:] if len(s) > keep + 4 else "..."

def check_takeover_signature(probe, target, url, body, results):
    if not body:
        return
    for service, patterns in TAKEOVER_SIGNATURES:
        for p in patterns:
            if p.lower() in body.lower():
                memory.add_candidate(target, url, "subdomain_takeover", confidence=1,
                                     evidence=f"response signature for {service}: {p}")
                return


# ---------------------------------------------------------------------------
# Form discovery
# ---------------------------------------------------------------------------

def find_forms(html):
    """Naive but functional form discovery. Returns [(action, method, [input names])]"""
    forms = []
    if not html:
        return forms
    for m in re.finditer(r"<form[^>]*>", html, re.I):
        tag = m.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', tag, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', tag, re.I)
        action_url = action.group(1) if action else None
        meth = (method.group(1) if method else "get").lower()
        # collect inputs until </form>
        end = html.find("</form>", m.end())
        chunk = html[m.end():end if end != -1 else m.end() + 2000]
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', chunk, re.I)
        selects = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', chunk, re.I)
        forms.append((action_url, meth, sorted(set(inputs + selects))))
    return forms


def interesting_param(name):
    n = name.lower()
    hints = ["id", "file", "url", "redirect", "u", "user", "userid", "uid", "email",
             "download", "path", "doc", "dir", "q", "search", "page", "callback",
             "next", "return", "ref", "target", "img", "image", "load", "src",
             "template", "view", "action", "cmd", "exec", "code", "lang", "admin",
             "referer", "host", "domain", "subdomain", "token", "key", "apikey",
             "repo", "commit", "rev", "version", "theme", "route", "controller"]
    return any(h == n or (n.startswith(h) and h in n) for h in hints)


def rank_param_urls(target, limit=25):
    """From memory endpoints, extract URLs with interesting params for manual testing."""
    eps = memory.get_all_endpoints(target)
    ranked = []
    for url, rec in eps.items():
        params = rec.get("params")
        names = [p for p in (params or "").split(",") if p]
        score = 0
        interesting = []
        for p in names:
            if interesting_param(p):
                score += 1
                interesting.append(p)
        if score:
            ranked.append((score, url, interesting))
    ranked.sort(key=lambda x: -x[0])
    return ranked[:limit]


# ---------------------------------------------------------------------------
# Orchestrated scanning
# ---------------------------------------------------------------------------

def scan_target(target, config):
    """Top-level: scan this target's known live URLs/endpoints for candidates."""
    vs = config.get("vuln_scanner", {})
    if not vs.get("enabled", True):
        print("[=] vuln_scanner disabled in config")
        return []

    probe = Probe(vs)
    results = {"scanned": 0, "added": 0}
    max_urls = vs.get("max_urls", 50)
    max_params = vs.get("max_params_per_url", 5)
    active_classes = vs.get("classes", ALL_CLASSES)
    passive = vs.get("passive_checks", True)

    # Build candidate list of URLs: live hosts first, then endpoints w/ params
    live_urls = []  # orchestrator passes these; fallback: from endpoints memory
    eps = memory.get_all_endpoints(target)
    param_endpoints = sorted(
        [u for u, r in eps.items() if r.get("params")],
        key=lambda u: -len((eps[u].get("params") or "").split(",")),
    )
    base_urls = []
    conn = memory._connect()
    try:
        rows = conn.execute("SELECT url FROM endpoints WHERE target = ?", (target,)).fetchall()
        base_urls = [r["url"] for r in rows]
    finally:
        conn.close()

    # dedupe: prefer highest-value URLs
    seen_origins = set()
    scan_list = []
    for u in param_endpoints + base_urls:
        parsed = urlparse(u)
        if not parsed.scheme or not parsed.netloc:
            continue
        if not scope_guard.validate_url_in_scope(target, u):
            continue
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.strip("/") or "/"
        if any(ex in parsed.path.lower() for ex in STATIC_EXT):
            continue
        scan_list.append(u)
        if len(scan_list) >= max_urls:
            break

    if not scan_list:
        print("[=] no endpoints to test yet — run discovery first")

    for url in scan_list:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            r = probe.get(origin + (parsed.path or "/"))
            base_body = probe.read_body(r)
            headers = dict(r.headers)
            status = r.status_code
            r.close()
        except requests.RequestException:
            continue

        if passive:
            passive_headers(probe, target, url, "GET", headers, results, target, vs)
            check_takeover_signature(probe, target, url, base_body, results)
            scan_js_secrets(probe, target, url, base_body, results)
            check_graphql(probe, target, url, results)

        # parse params from the URL itself and test the top-N
        in_url_params = list(parse_qs(parsed.query).keys())
        params_to_test = (in_url_params + [n for n in (eps.get(url, {}).get("params") or "").split(",") if n])
        params_to_test = list(dict.fromkeys(p for p in params_to_test if p))
        for param in params_to_test[:max_params]:
            if not scope_guard.validate_url_in_scope(target, url):
                break
            test_param(probe, target, url, "GET", param, vs, results)

        # POST forms
        for action, meth, inputs in find_forms(base_body):
            form_url = action or origin
            if not form_url.startswith("http"):
                form_url = origin + ("" if form_url.startswith("/") else "/") + form_url
            if not scope_guard.validate_url_in_scope(target, form_url):
                continue
            for param in inputs[:max_params]:
                test_param(probe, target, form_url, "POST", param, vs, results, as_post=True)

        # CORS check on non-root paths
        if passive and parsed.path and parsed.path not in ("/", ""):
            check_cors(probe, target, url, None, results)

        # exposed paths / listing only on first origin hit
        if origin not in seen_origins:
            seen_origins.add(origin)
            if passive:
                check_exposed_paths(probe, target, url, results, vs)
                check_directory_listing(probe, target, origin, results)

    print(f"[+] vuln_scanner: {results['scanned']} detections → {results['added']} new candidates "
          f"across {len(scan_list)} URLs")
    return results


def guide_from_candidates(target, limit=20):
    """Produce a prioritized manual-testing checklist from stored candidates."""
    cands = memory.get_candidates(target=target, status="new")
    cands.sort(key=lambda c: (-c["confidence"], c["first_seen"]))
    tips = {
        "sqli": "Confirm by hand: note the true/false or time response; identify DB type. "
                "Do NOT exfiltrate data.",
        "xss": "Confirm where the payload lands (attribute/script/event). Test with a harmless "
               "marker to avoid alert() noise.",
        "ssti": "Identify the engine (Jinja/Twig/Freemarker...), confirm eval with arithmetic. "
                "Do not chain into RCE without authorization.",
        "lfi": "Map readable files via error/content diffs. Confirm path traversal reachability.",
        "cmdi": "Confirm echo marker executes in a controlled, non-destructive way.",
        "open_redirect": "Check redirect follows external URL and flows can be security-relevant "
                         "(OAuth/nonce/token leak).",
        "crlf": "Check if injected header can set cookies / poison cache.",
        "cors_misconfig": "Verify credentialed requests from an attacker origin would be allowed.",
        "secret_exposure": "Check whether the exposed secret is live (rotation is the fix).",
        "graphql_introspection": "Test for excessive introspective info, then test auth on mutations.",
        "subdomain_takeover": "Verify via DNS (CNAME to a dangling service), claim the service, "
                              "confirm you can host content there.",
        "exposed_path": "Check auth on the panel; try default creds only with authorization.",
        "backup_file": "Download once (you already have a copy), check for hardcoded creds.",
        "source_exposed": ".git or source exposure — reverify refs/commits exist.",
        "directory_listing": "Confirm listing reveals sensitive files.",
        "cookie_flags": "Suggest adding httponly/secure/samesite — low impact, easy report.",
        "security_headers": "Missing headers are low severity — good for report completeness.",
        "info_disclosure": "Banner/stack disclosure — low severity, part of a fuller report.",
    }
    lines = []
    if not cands:
        lines.append("No open candidates. Run discovery to build attack surface, then the "
                     "vuln_scanner will have something to test.")
        return lines
    lines.append(f"Top {len(cands[:limit])} candidates to manually verify (sorted by confidence):")
    for c in cands[:limit]:
        tip = tips.get(c["vuln_class"], "Verify manually.")
        lines.append(
            f"  [{c['confidence']}/3] {c['vuln_class']:<18} {c['url']}"
            + (f" ?{c['param']}={c['payload'] or ''}" if c['param'] else "")
        )
        lines.append(f"       evidence: {c['evidence'][:140]}")
        lines.append(f"       manual: {tip}")
    return lines


if __name__ == "__main__":
    import sys
    t = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    from config import load_target_config
    cfg = load_target_config(t)
    res = scan_target(t, cfg)
    print("\n".join(guide_from_candidates(t)))