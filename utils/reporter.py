"""Reporter module for bugHunter CLI.

Exports findings to structured JSON and renders terminal summary tables.
Uses rich for colored output.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from collections.abc import Sequence

    from core.analyzer import AnalysisResult, Detection, VulnerabilityType

console = Console()


def escape_json_string(value: str) -> str:
    """Safely escape string for JSON."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


class Reporter:
    """Generate scan reports in JSON format and terminal tables."""

    def __init__(self, output_dir: str = "reports") -> None:
        """Initialize reporter.

        Args:
            output_dir: Directory to save JSON reports.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_json_report(
        self,
        scan_id: str,
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        analysis_results: list[AnalysisResult],
    ) -> dict:
        """Build structured JSON report."""
        all_detections: list[dict] = []

        for result in analysis_results:
            for detection in result.detections:
                detection_dict = {
                    "scan_id": scan_id,
                    "target_url": detection.url,
                    "method": detection.method,
                    "parameter": detection.param_name,
                    "payload": detection.payload,
                    "vulnerability_type": detection.vuln_type.value,
                    "confidence": detection.confidence,
                    "evidence": detection.evidence,
                    "details": detection.details,
                    "timestamp": datetime.now().isoformat(),
                }
                all_detections.append(detection_dict)

        report = {
            "scan_id": scan_id,
            "target_url": target_url,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "total_urls_scanned": len(analysis_results),
            "total_findings": len(all_detections),
            "is_vulnerable": len(all_detections) > 0,
            "detections": all_detections,
        }

        return report

    def export_json(
        self,
        scan_id: str,
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        analysis_results: list[AnalysisResult],
    ) -> str:
        """Export analysis results to JSON file.

        Args:
            scan_id: Unique identifier for this scan.
            target_url: Target URL that was scanned.
            start_time: Scan start timestamp.
            end_time: Scan end timestamp.
            analysis_results: List of analysis results.

        Returns:
            Path to saved JSON file.
        """
        report = self._build_json_report(
            scan_id, target_url, start_time, end_time, analysis_results
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bughunter_{scan_id}_{timestamp}.json"
        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return str(filepath)

    def render_summary(
        self,
        scan_id: str,
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        analysis_results: list[AnalysisResult],
        total_urls: int,
    ) -> None:
        """Render scan summary table to terminal.

        Args:
            scan_id: Unique identifier for this scan.
            target_url: Target URL that was scanned.
            start_time: Scan start timestamp.
            end_time: Scan end timestamp.
            analysis_results: List of analysis results.
            total_urls: Total URLs discovered during crawling.
        """
        duration = (end_time - start_time).total_seconds()

        # Count detections by type
        vuln_counts: dict[VulnerabilityType, int] = {}
        total_findings = 0

        for result in analysis_results:
            for detection in result.detections:
                vuln_counts[detection.vuln_type] = vuln_counts.get(
                    detection.vuln_type, 0
                ) + 1
                total_findings += 1

        # Build summary table
        table = Table(title=f"BugHunter Scan Summary [scan_id={scan_id}]", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="magenta")
        table.add_column("Value", style="green")

        table.add_row("Target URL", target_url)
        table.add_row("Scan ID", scan_id)
        table.add_row("Duration", f"{duration:.2f}s")
        table.add_row("URLs Discovered", str(total_urls))
        table.add_row("URLs Tested", str(len(analysis_results)))
        table.add_row("Total Findings", str(total_findings))

        console.print(table)

        # Build findings table
        if vuln_counts:
            findings_table = Table(title="Vulnerability Findings", show_header=True, header_style="bold red")
            findings_table.add_column("Type", style="white")
            findings_table.add_column("Count", style="yellow", justify="right")

            for vuln_type, count in sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True):
                findings_table.add_row(vuln_type.value, str(count))

            console.print(findings_table)
        else:
            console.print("\n[bold green]No vulnerabilities detected.[/bold green]")

    def render_detection_details(self, detection: Detection) -> None:
        """Render detailed information about a single detection.

        Args:
            detection: Detection to display.
        """
        console.print(f"\n{'=' * 60}")
        console.print(f"[bold]{detection.vuln_type.value.upper()}[/bold]")
        console.print(f"  [cyan]URL:[/cyan] {detection.url}")
        console.print(f"  [cyan]Method:[/cyan] {detection.method}")
        console.print(f"  [cyan]Parameter:[/cyan] {detection.param_name}")
        console.print(f"  [cyan]Payload:[/cyan] {detection.payload}")
        console.print(f"  [cyan]Confidence:[/cyan] {detection.confidence:.0%}")
        console.print(f"  [cyan]Evidence:[/cyan] {detection.evidence}")

        if detection.details:
            console.print("  [cyan]Details:[/cyan]")
            for key, value in detection.details.items():
                console.print(f"    {key}: {value}")

    def render_all_detections(
        self,
        analysis_results: list[AnalysisResult],
    ) -> None:
        """Render all detections with full details.

        Args:
            analysis_results: List of analysis results.
        """
        all_detections: list[Detection] = []

        for result in analysis_results:
            all_detections.extend(result.detections)

        if not all_detections:
            return

        for detection in all_detections:
            self.render_detection_details(detection)