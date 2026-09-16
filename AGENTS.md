# BugHunter CLI - AGENTS.md

## ROLE & EXPERTISE
Senior Application Security Engineer and Python Core Developer. Production-ready, modular, clean code. Strict PEP 8 compliance, consistent type hinting, comprehensive error handling.

## PROJECT SUMMARY: BugHunter CLI
Lightweight modular CLI for automatic Dynamic Application Security Testing (DAST). Targets local educational environments (localhost, DVWA, OWASP Juice Shop). Systematically maps website attack surface (crawling) and tests basic vulnerabilities (e.g., SQL Injection) on form inputs and URL parameters.

## TECH STACK
- Python 3.11+
- `httpx` (asynchronous HTTP requests)
- `beautifulsoup4` (HTML parsing)
- `argparse` (CLI argument parsing)
- `rich` (terminal tables, progress bars, colored logs)

## REQUIRED ARCHITECTURE
1. `core/crawler.py`: URL extraction, query parameter parsing, form input collection. URL deduplication logic, infinite loop prevention.
2. `core/fuzzer.py`: Payload injection to crawler-discovered parameters. HTTP requests, collect status code, latency, raw HTML response.
3. `core/analyzer.py`: Analyze fuzzer responses. Detect native DB error patterns, reflected malicious text, response anomalies.
4. `utils/reporter.py`: Export findings to structured JSON, render scan summary table to terminal.
5. `main.py`: CLI entry point. Orchestrates full pipeline. Accepts `--target`, `--threads`, `--output` arguments.

## STRICT CODING RULES
- **Type Hinting:** Mandatory Python built-in type hints on all functions, methods, complex variables.
- **Network Resilience:** Explicit `timeout` on every HTTP request. Graceful network exception handling (`ConnectionError`, `TimeoutException`).
- **Logic Separation:** Core folder logic禁止 direct `print()` calls. All terminal visual output managed by `main.py` or `rich` logger.
- **Scope Security:** Crawler/fuzzer MUST validate domain boundaries. Never crawl/fuzz outside `--target` domain.
- **Generation Process:** ONE MODULE AT A TIME (step by step). No full codebase in single response.
- **No Placeholders:** Never use placeholder comments (`# TODO: implement here`). Core functions must be fully functional and executable.
