# BugHunter CLI

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Status: Active Development](https://img.shields.io/badge/status-active%20development-yellow)](./README.md#known-limitations--current-issues)
[![Concurrency](https://img.shields.io/badge/concurrency-async%20%E2%86%91-brightgreen)](./README.md#key-technical-features)
[![Reports](https://img.shields.io/badge/reports-structure%20JSON-blueviolet)](./README.md#structured-json-reporting)
[![Tests](https://img.shields.io/badge/tests-52%20passing-green)](./README.md#automated-testing)

> **A lightweight, asynchronous Dynamic Application Security Testing (DAST) scanner & fuzzer, built from scratch in Python.**

BugHunter CLI systematically maps a website's attack surface (crawling), injects security payloads into every discovered parameter and form input (fuzzing), and analyzes the responses for vulnerability indicators (SQL Injection, Reflected XSS, Command Injection, Path Traversal, File Inclusion, and more). It is designed primarily for **local educational environments** such as DVWA, OWASP Juice Shop, or any authorized localhost target.

---

## Table of Contents

- [Key Technical Features](#key-technical-features)
- [Architecture & Project Structure](#architecture--project-structure)
- [Installation & Setup Guide](#installation--setup-guide)
- [Usage Guide & CLI Options](#usage-guide--cli-options)
- [Automated Testing](#automated-testing)
- [Known Limitations & Current Issues](#known-limitations--current-issues)
- [Disclaimer](#disclaimer)
- [Developer Credit](#developer-credit)

---

## Key Technical Features

### Fully Asynchronous Architecture (`httpx.AsyncClient` + `asyncio`)

All network I/O runs on a single event loop with non-blocking concurrency:

- **`core/crawler.py`** — Uses `httpx.AsyncClient` with an `asyncio.Semaphore` to bound concurrent page fetches while discovering URLs, query parameters, and form inputs.
- **`core/fuzzer.py`** — Injects payloads asynchronously, collecting status code, latency, response size, and the raw HTML body for each attempt.
- **`main.py`** — Orchestrates the whole pipeline through `asyncio.run()` and an explicit `max_concurrent` (threads) limiter.

This keeps CPU overhead minimal, memory footprints low, and throughput high — ideal for scanning multi-page applications quickly.

### Domain Scope Enforcement

Crawl and fuzz activity is strictly confined to the `--target` scope. All extracted links are resolved with `urllib.parse.urljoin` and validated against:

1. Scheme whitelist (`http` / `https` only)
2. Exact host (or subdomain, when enabled) matching
3. **Base-path lock** — links must stay inside the target's root path (e.g. a scan starting at `http://localhost/dvwa/` never crawls `/xampp`, `/perpustakaan`, or any other out-of-tree path)
4. **Session-safety blacklist** — links containing destructive session keywords (`logout`, `logoff`, `signout`, `deconnexion`, `action=logout`, `?logout=1`, ...) are discarded so a crawl can never kill the authenticated `PHPSESSID`
5. Normalized deduplication with infinite-loop prevention

External or malformed URLs are silently discarded before any request is made.

Before fuzzing, every discovered endpoint is probed with a single clean request; links that answer **4xx** are treated as dead or mis-resolved (e.g. a login action resolved to a non-existent path) and are skipped entirely so they never generate false findings.

### Smart False-Positive Filter

XSS detection requires **more than a payload-length heuristic** — a finding is only reported when:

1. The injected payload is **longer than 3 characters** (single/double quotes are treated as benign probes, not findings).
2. The payload contains **XSS markers** such as `<`, `>`, `script`, or event-handler attributes (`onerror=`, `onload=`, etc.).
3. The payload is **actually reflected** in the response body.

This eliminates the classic micro–false-positive trap where a lone `'` or `"` in HTML is mistakenly flagged as a reflected XSS vector.

### Pattern-Based Vulnerability Detection

- **SQL Injection** — Database engine–specific error signatures (MySQL, PostgreSQL, SQLite, SQL Server) plus SQL keyword heuristics.
- **Reflected XSS** — Payload reflection detection with the smart filter described above.
- **Command Injection** — Shell error output and usage-message patterns.
- **Path Traversal & File Inclusion** — OS path signatures (`/etc/passwd`, Windows `config\sam`, `php://` stream wrappers, `data://` URIs).
- **Error Exposure** — Server-side failures (HTTP 5xx) and connection/timeout errors. Client errors (4xx) are treated as link-quality signals, never as vulnerabilities.
- **Latency (Time-Based) Injection** — Response-timing anomaly detection.

### Authenticated Scanning via Session Cookies (`--cookie`)

Protected, login-gated endpoints can be scanned without any support code by
supplying the authenticated browser session directly:

```bash
python main.py --target http://localhost/my-app --cookie "PHPSESSID=a1b2c3; laravel_session=eyJ..."
```

- **Parsing** — the cookie header string is split into an httpx-ready
  `dict` (`name1=val1; name2=val2`). Whitespace is trimmed and malformed
  segments (no `=`) are skipped, so a bad cookie never aborts a scan.
- **Propagation** — the parsed cookies are attached to the single shared
  `httpx.AsyncClient` used by both the crawl and fuzz phases, so every
  crawler and fuzzer request automatically carries the session to the
  target domain.
- **Universal** — works across PHP sessions, Laravel/Django/Flask CSRF
  cookies, JWTs in cookies, and any other cookie-based auth scheme, with no
  framework-specific special-casing.

### CSRF-Aware Stateful Fuzzing

```
Crawl phase            Fuzz phase (same session)
   │                        │
   ├─ Extract hidden tokens ┼─ Reuse the shared httpx.AsyncClient
   │   · input _token       │   (cookies + tokens persist)
  │   · DVWA user_token    │
   │   · <meta csrf-token>  │
   └─ Record per-form       └─ Forward _token + all original form
        _csrf_token            fields alongside the injected payload
```

The scanner operates over a **single `httpx.AsyncClient` across the whole pipeline**, so session cookies and CSRF tokens discovered while crawling are honored when the same endpoints are fuzzed. Every post-request replays the full original form body (hidden fields included) with only the targeted parameter swapped for the payload — giving protected, token-guarded forms like Laravel Breeze a valid request instead of an immediate 419 rejection.

### Adaptive Backoff & Rate-Limit Resilience

- **HTTP 429 retries** — rate-limited responses are retried with exponential backoff (`1s → 2s → 4s → max 10s`, up to 3 retries), respecting the scanner's own throttling duty cycle.
- **Latency pause** — a 0.5s pause after any response exceeding the `latency_warning_ms` threshold keeps requests gentle on slow endpoints.
- **Graceful signal handling** — a request that stays rate-limited after all retries is recorded as `Rate limited (429 after 3 retries)`, and 429 responses are **never** misreported as server-error exposure by the analyzer.

### GET Form Fuzzing & Query Fidelity

Two correctness fixes keep requests faithful to what a real browser would send:

- **Query parameters survive crawling** — discovered links (`?name=test`) keep
  their query strings end-to-end; deduplication is keyed on the *path* only, so
  `xss_r/?name=1` and `xss_r/?name=2` are both fuzzed instead of collapsing the
  second fingerprint onto the first.
- **GET forms are fuzzed as GET forms** — the payload plus every original field
  is forwarded as an encoded query string (no more silently dropped payloads
  because a form happened to use `method="get"`). An empty/`"#"` action resolves
  to the current page URL, and relative actions resolve with `urljoin`, so
  DVWA-style `action="#"` forms land on the real endpoint.

### Detection Evidence (`matched_snippet`)

Every generated finding now carries a ~120-character excerpt of the raw response
centred on the reflected payload or matched error signature:

```json
"details": { "matched_snippet": "...Hello <script>alert(1)</script>..." }
```

This serves as tangible, copy-pasteable proof of detection in the JSON report —
no need to re-request the target to inspect what the scanner matched.

### Session Cookie Sanity Probe

When `--cookie` is supplied, the scanner first issues one clean request and
checks whether it bounced onto a login page (URL path containing `login`, or a
rendered `<form>` with a `type="password"` input). If the session is not
effective, a warning is printed at scan start so a `0`-findings result is never
silently mistaken for a clean target.

### Structured JSON Reporting

Every scan produces a machine-readable report:

```json
{
  "scan_id": "9ac46c83",
  "target_url": "http://localhost/dvwa/login.php",
  "start_time": "2026-09-17T01:39:18.123456",
  "end_time": "2026-09-17T01:39:22.203401",
  "duration_seconds": 4.08,
  "total_urls_scanned": 81,
  "total_findings": 6,
  "is_vulnerable": true,
  "detections": [
    {
      "scan_id": "9ac46c83",
      "target_url": "http://localhost/...",
      "method": "GET",
      "parameter": "id",
      "payload": "<img src=x onerror=alert(1)>",
      "vulnerability_type": "xss_reflected",
      "confidence": 0.95,
      "evidence": "Payload reflected: <img src=x onerror=alert(1)>",
      "details": {
        "status_code": "200",
        "matched_snippet": "...Hello <img src=x onerror=alert(1)>..."
      },
      "timestamp": "2026-09-17T01:39:20.431221"
    }
  ]
}
```

Reports are saved to `reports/bughunter_<scan_id>_<timestamp>.json` and mirrored as rich, colorized terminal tables.

---

## Architecture & Project Structure

```
bugHunter_cli/
├── main.py                 # CLI entry point — pipeline orchestration (argparse, asyncio.run)
├── requirements.txt        # Runtime + test dependencies (pinned)
├── README.md               # This documentation
├── AGENTS.md               # Project conventions & developer guidelines
├── core/
│   ├── __init__.py
│   ├── crawler.py          # URL discovery, param/form + CSRF extraction, dedup, scope enforcement
│   ├── fuzzer.py           # Payload injection engine (async, concurrency-bounded, 429 backoff)
│   └── analyzer.py         # Response analysis & vulnerability detection
├── utils/
│   ├── __init__.py
│   └── reporter.py         # JSON export + rich terminal rendering
├── reports/                # Generated scan reports (JSON)
└── tests/                  # pytest unit/integration suite (52 tests)
    ├── __init__.py
    ├── test_main.py        # URL validation, --cookie parser & client injection
    ├── test_crawler.py     # Deduplication, depth limiting, CSRF extraction
    ├── test_fuzzer.py      # Timeout/connection resilience, CSRF form data, 429 backoff
    └── test_analyzer.py    # SQLi/XSS/latency detection, 429 handling, false-positive tests
```

### Module Responsibilities

| Module | Responsibility |
|--------|----------------|
| `core/crawler.py` | Traverse the target, extract links/query params/forms, enforce domain boundaries, deduplicate. |
| `core/fuzzer.py` | Replay discovered endpoints with the curated payload set (GET/POST), capture raw responses. |
| `core/analyzer.py` | Inspect responses for vulnerability indicators and produce `Detection` records. |
| `utils/reporter.py` | Serialize findings to JSON and render summary/detail tables to the terminal. |
| `main.py` | Parse CLI args, validate input, run the 4-stage pipeline, report results. |

### Scan Pipeline

```
Crawl → Fuzz → Analyze → Report
  1.  Discover URLs, parameters & forms        (core/crawler.py)
  2.  Inject payloads with bounded concurrency (core/fuzzer.py)
  3.  Detect vulnerability indicators          (core/analyzer.py)
  4.  Export JSON + render summary             (utils/reporter.py)
```

---

## Installation & Setup Guide

### Prerequisites

- **Python 3.11+** (developed and tested on 3.13)
- `pip` / `venv` available on your system

### 1. Clone the repository

```bash
git clone https://github.com/your-username/bugHunter_cli.git
cd bugHunter_cli
```

### 2. Create a virtual environment

**Windows (PowerShell / cmd):**

```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs the runtime stack (`httpx`, `beautifulsoup4`, `rich`) plus the test stack (`pytest`, `pytest-asyncio`, `pytest-httpx`) — all pinned to a known-compatible set.

### 4. Verify the installation

```bash
python main.py --target http://localhost --depth 0
```

You should see the BugHunter banner and a completed scan summary.

---

## Usage Guide & CLI Options

### Command

```bash
python main.py --target <URL> [options]
```

### CLI Options

| Argument | Short | Type | Default | Description |
|----------|-------|------|---------|-------------|
| `--target` | `-t` | `str` | *(required)* | Target URL to scan (`http://` or `https://`). |
| `--depth` | `-d` | `int` | `3` | Maximum crawl depth. |
| `--threads` | `-T` | `int` | `10` | Number of concurrent HTTP requests. |
| `--output` | `-o` | `str` | `reports` | Output directory for JSON reports. |
| `--verbose` | `-v` | flag | `False` | Print per-URL discoveries and full detection details. |
| `--cookie` | | `str` | `""` | Authenticated session cookies sent with every request (`"name1=val1; name2=val2"`). |

### Examples

```bash
# Basic scan of a local DVWA instance
python main.py --target http://localhost/dvwa

# Deeper crawl with higher concurrency
python main.py --target http://localhost/juicy-shop --depth 5 --threads 20

# Export to a custom output directory
python main.py --target https://example.com --output ./results

# Verbose mode — list all discovered URLs and full detection evidence
python main.py --target http://localhost/dvwa/login.php --verbose

# Authenticated scan — reuse cookies from a logged-in browser session
python main.py --target http://localhost/my-app --cookie "PHPSESSID=abc123; logged_in=1"
```

### Reading the Output

- **Terminal summary** — scan metadata table plus a vulnerability type/count breakdown.
- **JSON report** — full structured findings, including `is_vulnerable` for quick triage.
- **Exit codes** — `0` when no vulnerabilities are found, `1` on findings or fatal errors (useful for CI gating, although the tool is currently in active development).

---

## Execution Capabilities (Current Snapshot)

> Status of the tool *today* — what a real run leverages end-to-end.

### Full Scanning Lifecycle

```
Crawl → Fuzz → Analyze → Report
```

Crawling discovers the attack surface, fuzzing replays every parameter and form
input with curated payloads, the analyzer classifies responses, and a `rich`
terminal summary plus a structured JSON report close the loop. No external
orchestrator is required — `main.py` drives all four stages with a single
async event loop.

### Authenticated Scanning (`--cookie`)

Endpoints behind a login gate are reachable without any support code by
forwarding the authenticated browser session:

```bash
python main.py --target http://localhost/dvwa/vulnerabilities/exec/ \
  --cookie "PHPSESSID=abc123def456" --depth 0 --threads 8 -o reports
```

The session cookie is parsed into an `httpx`-ready dict, attached to the single
shared async client used by **both** the crawler and fuzzer, and carried into
every request — so DVWA `PHPSESSID` sessions, Laravel `laravel_session`, and
CSRF cookies all work transparently)Skip.

### Crawler Safeguards

Two guards keep a scan honest while it races through a site:

- **Session-safety blacklist** — destructive endpoints (`logout`, `logoff`,
  `signout`, `?action=logout`, …) are never fuzzed, so an authenticated
  session is never killed mid-scan.
- **Base-path scope lock** — crawling stays strictly inside the target's root
  path; a scan started at `/dvwa/` never wanders into `/xampp`, `/phpmyadmin`
  or any other out-of-tree directory, even if the HTML links there.

### Detection Engine (Zero-false-positive bias)

The analyzer never reports a vulnerability from a template file's wording; it
requires **actual evidence in the live response**:

- **Reflected XSS** — payload must contain XSS markers (`<`, `>`, `script`,
  `onerror=`, …) *and* be reflected back verbatim in the body (with a
  `matched_snippet` proving it).
- **SQL Injection (error-based)** — native DB error signatures across MySQL,
  PostgreSQL, SQLite, MSSQL (e.g. `SQLSTATE[HY000]`, `SQL syntax … near … at
  line`).
- **Path Traversal / LFI** — OS file-path signatures (`/etc/passwd`,
  `php://` / `data://` wrappers, Windows path leaks).
- **Command Injection (context-aware)** — only shell/executor *permission
  denied* signatures (`sh: 1: ./id: Permission denied`, Java `Cannot run
  program … error=13`) count as command injection. A PHP include warning like
  `Warning: include(…bad…): Failed to open stream: Permission denied` is
  **rejected** — it is a file-inclusion artifact, not a shell error, and is
  never mis-reported as command injection.

### Structured JSON Reporting

Every scan emits a machine-readable report (`reports/bughunter_<hash>.json`)
with `detections`, `total_urls_scanned`, `total_findings`, `is_vulnerable`, and
per-finding evidence — ready for CI ingestion or triage dashboards.

---

## Quick Start — Real Commands

```bash
# 1) Unauthenticated surface probe (fast, depth 0)
python main.py --target http://localhost/dvwa/ --depth 0 -o reports

# 2) Authenticated deep scan (login-gated area, bounded concurrency)
python main.py --target http://localhost/dvwa/vulnerabilities/exec/ \
  --cookie "PHPSESSID=<your-session>" --depth 1 --threads 8

# 3) Custom concurrency & output
python main.py --target http://localhost:8000 --threads 12 --depth 2 \
  --output ./my_scan
```

---

## Verified Benchmark — DVWA (Security: Low)

Validated against a local **DVWA** instance (`dvwa.local`) with an
authenticated session, `--depth 1`, 8 threads:

| Metric | Result |
|--------|--------|
| URLs discovered (crawl) | **31** |
| Requests sent / fuzzed | **729** |
| Total true positives | **70** |
| └ Reflected XSS | **45** |
| └ SQL Injection (error-based) | **15** |
| └ Path Traversal / LFI | **10** |
| False positives | **0** |

> Methodology: payloads were injected into every discovered parameter and form
> input, and each response was re-requested live to confirm the signature was
> genuinely reflected from the request rather than baked into a static page.
> The context-aware command-injection filter kept the DVWA PHP File-Inclusion
> `Permission denied` notice out of the command-injection bucket — every one of
> the 70 findings passed manual re-verification.

---

## Automated Testing

The suite uses `pytest` together with `pytest-asyncio` (STRICT mode) — no live network access is required, network-dependent paths are exercised through mocks and isolated asyncio test cases.

```bash
# From the project root, with the virtual environment active
python -m pytest tests/ -v
```

Expected result: **52 passing tests** across 4 test modules:

| Test Module | Coverage |
|-------------|----------|
| `tests/test_main.py` | URL scheme/host validation, `--cookie` parser (single/multiple/whitespace/malformed), cookie injection into the shared client, login-gate session probe |
| `tests/test_crawler.py` | URL deduplication (query-insensitive), query preservation on normalize, max-depth limiting, session-blacklist (logout/action=logout), base-path scope lock, CSRF extraction (meta, hidden input, DVWA `user_token`) |
| `tests/test_fuzzer.py` | Timeout & connection-error resilience, dead-link (4xx) skipping, GET-form fuzzing (payload via query, empty/`"#"`/relative action resolution), absolute-action URL normalization (GET+POST), CSRF-aware form data, 429 backoff & rate-limit reporting |
| `tests/test_analyzer.py` | SQLi detection, XSS reflection (with `matched_snippet` evidence), latency injection, 429/4xx no-error-exposure, 5xx reporting, false-positive rejection |

---

## Known Limitations & Current Issues

> **Status: Active Development — this project is NOT final.** The items below are tracked, transparent limitations that require further work.

1. **Session state is basic.** CSRF tokens and cookies are carried across the crawl → fuzz phases via a shared `httpx.AsyncClient`, but the scanner does not automate multi-step login flows, mid-scan token rotation, or expiry refresh. Tokens are captured once per discovered form; if the application rotates them between scans or inside the crawl, later requests may still be rejected.

2. **Rate-limit handling is heuristic.** HTTP 429 responses are retried with exponential backoff (up to 3 retries), and a short pause is applied after high-latency responses. WAF/captcha block pages are not parsed, and a `429 → 200` recovery is treated as a clean success without deeper inspection.

3. **Detection depth.** Detection is primarily regex/pattern-based with simple latency-threshold heuristics. It is not yet a Bayesian/ML classifier, and high-jitter networks may produce latency false positives.

4. **Scope of validation.** BugHunter is validated against local educational targets (DVWA, OWASP Juice Shop). The GET-form and query-fidelity fixes are verified through mocked transport tests; a live DVWA re-validation pass is the recommended next sanity check. Multi-step login automation, HTTP/2-specific edge cases, and headless-browser DOM XSS remain out of scope.

5. **Documented but untested integrations.** CI-gating by exit code and large-scale production scanning have not been exercised and should be considered experimental.

---

## Disclaimer

**BugHunter CLI is an educational and research tool.** It performs active security testing that may trigger defensive measures, data modification, or legal consequences if misused.

- Only scan **systems you own** or **explicitly authorized** to test (e.g., local Virtual Machines running DVWA or OWASP Juice Shop).
- Never point this tool at production systems, third-party domains, or any infrastructure without written permission.
- Use of this tool for unauthorized access or malicious activity is prohibited.

The developer provides this software **as-is**, without warranty of any kind, and accepts **no liability** for any damage or legal consequences arising from its misuse.

---

## Developer Credit

| | |
|---|---|
| **Developer** | **V** |
| **Focus** | DAST automation, async architecture, false-positive reduction |
| **Tech Stack** | Python 3.11+ · `httpx` · `asyncio` · BeautifulSoup4 · `rich` · `pytest` |

---

<p align="center"><strong>BugHunter CLI</strong> — built for learning, hardened for practice.<br/> Reporting issues & contributions are welcome.</p>