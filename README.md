# BugHunter CLI

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Status: Active Development](https://img.shields.io/badge/status-active%20development-yellow)](./README.md#known-limitations--current-issues)
[![Concurrency](https://img.shields.io/badge/concurrency-async%20%E2%86%91-brightgreen)](./README.md#key-technical-features)
[![Reports](https://img.shields.io/badge/reports-structure%20JSON-blueviolet)](./README.md#structured-json-reporting)
[![Tests](https://img.shields.io/badge/tests-15%20passing-green)](./README.md#automated-testing)

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

Crawl and fuzz activity is strictly confined to the `--target` domain. All extracted links are resolved with `urllib.parse.urljoin` and validated against:

1. Scheme whitelist (`http` / `https` only)
2. Exact host (or subdomain, when enabled) matching
3. Normalized deduplication with infinite-loop prevention

External or malformed URLs are silently discarded before any request is made.

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
- **Error Exposure** — Status-code anomalies / server errors.
- **Latency (Time-Based) Injection** — Response-timing anomaly detection.

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
      "details": { "status_code": "200" },
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
│   ├── crawler.py          # URL discovery, param/form extraction, dedup, scope enforcement
│   ├── fuzzer.py           # Payload injection engine (async, concurrency-bounded)
│   └── analyzer.py         # Response analysis & vulnerability detection
├── utils/
│   ├── __init__.py
│   └── reporter.py         # JSON export + rich terminal rendering
├── reports/                # Generated scan reports (JSON)
└── tests/                  # pytest unit/integration suite (15 tests)
    ├── __init__.py
    ├── test_main.py        # URL validation & CLI entry behavior
    ├── test_crawler.py     # Deduplication, depth limiting
    ├── test_fuzzer.py      # Timeout/connection resilience, graceful degradation
    └── test_analyzer.py    # SQLi/XSS/latency detection, false-positive tests
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
```

### Reading the Output

- **Terminal summary** — scan metadata table plus a vulnerability type/count breakdown.
- **JSON report** — full structured findings, including `is_vulnerable` for quick triage.
- **Exit codes** — `0` when no vulnerabilities are found, `1` on findings or fatal errors (useful for CI gating, although the tool is currently in active development).

---

## Automated Testing

The suite uses `pytest` together with `pytest-asyncio` (STRICT mode) — no live network access is required, network-dependent paths are exercised through mocks and isolated asyncio test cases.

```bash
# From the project root, with the virtual environment active
python -m pytest tests/ -v
```

Expected result: **15 passing tests** across 4 test modules:

| Test Module | Coverage |
|-------------|----------|
| `tests/test_main.py` | URL scheme/host validation for CLI input |
| `tests/test_crawler.py` | URL deduplication, max-depth limiting |
| `tests/test_fuzzer.py` | Timeout & connection-error resilience, graceful degradation |
| `tests/test_analyzer.py` | SQLi detection, XSS reflection, latency injection, false-positive rejection |

---

## Known Limitations & Current Issues

> **Status: Active Development — this project is NOT final.** The items below are tracked, transparent limitations that require further work.

1. **URL construction anomalies in JSON reports.** On specific modern-framework targets (e.g., authentication routes such as those generated by Laravel Breeze), certain discovered `href` values are already absolute URLs. When merged with the base URL, the recorded `target_url` field can occasionally present as a doubled/concatenated string (e.g., `http://host/path/http://host/path`). Normalization and deduplication of these edge cases is still being hardened in `core/crawler.py`.

2. **No CSRF-token / session-aware fuzzing.** Stateless payload injection bypasses hidden CSRF tokens (common in Laravel Breeze and other modern stacks), which can cause the server to reject otherwise-valid requests — producing noise rather than meaningful response analysis. Stateful handling (token extraction, cookie persistence, session reuse) is not yet implemented.

3. **Rate-limiting & WAF handling.** There is no adaptive backoff or throttling awareness. Aggressive `--threads` values against protected endpoints may trigger rate-limit responses or WAF blocks, which the analyzer may currently interpret as error exposure.

4. **Detection depth.** Detection is primarily regex/pattern-based with simple latency-threshold heuristics. It is not yet a Bayesian/ML classifier, and high-jitter networks may produce latency false positives.

5. **Scope of validation.** BugHunter is validated against local, unauthenticated educational targets (DVWA, OWASP Juice Shop). Authenticated scanning, HTTP/2-specific edge cases, and headless-browser DOM XSS are out of scope for the current milestone.

6. **Documented but untested integrations.** CI-gating by exit code and large-scale production scanning have not been exercised and should be considered experimental.

---

## Disclaimer

**BugHunter CLI is an educational and research tool.** It performs active security testing that may trigger defensive measures, data modification, or legal consequences if misused.

- Only scan **systems you own** or **explicitly authorized** to test (e.g., local Virtual Machines running DVWA or OWASP Juice Shop).
- Never point this tool at production systems, third-party domains, or any infrastructure without written permission.
- Use of this tool for unauthorized access or malicious activity is prohibited.

The developer provides this software **as-is**, without warranty of any kind, and accepts **no liability** for any damage or legal consequences arising from its misuse.

---

## Credit

Made with ☕ by **[V]**

---

<p align="center"><strong>BugHunter CLI</strong> — built for learning, hardened for practice.<br/> Reporting issues & contributions are welcome.</p>
