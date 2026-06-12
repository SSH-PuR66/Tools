from __future__ import annotations

import argparse
import logging
import platform
from pathlib import Path

from rich.console import Console
from rich.table import Table

from controltrace import __version__
from controltrace.collectors.linux import LinuxCollector
from controltrace.logging_config import configure_logging
from controltrace.models import AssessmentReport, utc_now
from controltrace.poam import write_poam_csv
from controltrace.report_csv import write_findings_csv
from controltrace.report_html import render_html_report
from controltrace.report_json import write_json_report
from controltrace.rule_engine import RuleEngine

LOGGER = logging.getLogger(__name__)
console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="controltrace",
        description="Local security baseline assessment with NIST, MITRE, STIG-style checks, and POA&M export.",
    )

    parser.add_argument(
        "--rules",
        default="rules",
        help="Directory containing YAML assessment rules.",
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for generated reports.",
    )

    parser.add_argument(
        "--classification",
        default="UNCLASSIFIED",
        help="Report classification marking.",
    )

    parser.add_argument(
        "--include-passed",
        action="store_true",
        help="Include passed checks in detailed outputs.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose)

    started = utc_now()

    current_platform = platform.system().lower()

    if current_platform != "linux":
        console.print("[red]This version currently supports Linux assessment only.[/red]")
        console.print("[yellow]Windows collector is intentionally left as a roadmap module.[/yellow]")
        raise SystemExit(2)

    collector = LinuxCollector()
    engine = RuleEngine.from_directory(Path(args.rules))

    findings = engine.evaluate_linux(collector)

    if not args.include_passed:
        report_findings = findings
    else:
        report_findings = findings

    completed = utc_now()

    report = AssessmentReport(
        tool_name="ControlTrace",
        tool_version=__version__,
        hostname=collector.hostname(),
        platform="linux",
        started_at=started,
        completed_at=completed,
        classification=args.classification,
        findings=report_findings,
    )

    output_dir = Path(args.output_dir)
    html_path = render_html_report(report, output_dir / "controltrace-report.html")
    json_path = write_json_report(report, output_dir / "controltrace-report.json")
    csv_path = write_findings_csv(report, output_dir / "controltrace-findings.csv")
    poam_path = write_poam_csv(report, output_dir / "controltrace-poam.csv")

    _print_summary(report, html_path, json_path, csv_path, poam_path)


def _print_summary(
    report: AssessmentReport,
    html_path: Path,
    json_path: Path,
    csv_path: Path,
    poam_path: Path,
) -> None:
    table = Table(title="ControlTrace Assessment Summary")

    table.add_column("Metric")
    table.add_column("Value")

    table.add_row("Hostname", report.hostname)
    table.add_row("Platform", report.platform)
    table.add_row("Total Checks", str(report.total_findings))
    table.add_row("Passed", str(report.passed_findings))
    table.add_row("Failed", str(report.failed_findings))
    table.add_row("HTML Report", str(html_path))
    table.add_row("JSON Report", str(json_path))
    table.add_row("CSV Findings", str(csv_path))
    table.add_row("POA&M Export", str(poam_path))

    console.print(table)

    severity_table = Table(title="Failed Findings by Severity")
    severity_table.add_column("Severity")
    severity_table.add_column("Count")

    for severity, count in report.severity_counts.items():
        severity_table.add_row(severity, str(count))

    console.print(severity_table)
