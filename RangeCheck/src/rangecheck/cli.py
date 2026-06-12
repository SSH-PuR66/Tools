from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

from rangecheck.logging_config import configure_logging
from rangecheck.report_csv import write_findings_csv
from rangecheck.report_html import render_html_report
from rangecheck.report_json import write_json_report
from rangecheck.scanner import ScanConfigurationError, parse_ports, scan_target
from rangecheck.scope import ScopeValidationError, load_scope

LOGGER = logging.getLogger(__name__)
console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rangecheck",
        description=(
            "Authorized network exposure assessment with service fingerprinting, "
            "NIST SP 800-53 mapping, MITRE ATT&CK mapping, CVSS metadata, and reporting."
        ),
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target IP address or CIDR range. Required unless --scope is provided.",
    )

    parser.add_argument(
        "--scope",
        default=None,
        help="YAML scope file containing authorized targets and limits.",
    )

    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm that you are authorized to assess the provided target.",
    )

    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated ports or ranges, for example 22,80,443,8000-8010.",
    )

    parser.add_argument(
        "--rules",
        default="rules",
        help="Directory containing YAML rule files.",
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Maximum concurrent connection attempts.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Connection timeout in seconds.",
    )

    parser.add_argument(
        "--max-hosts",
        type=int,
        default=None,
        help="Maximum hosts allowed in a CIDR scan.",
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for generated reports.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose console logging.",
    )

    return parser


async def async_main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose)

    try:
        ports = parse_ports(args.ports)
        rules_dir = Path(args.rules)

        if args.scope:
            scope = load_scope(Path(args.scope))

            if len(ports) > scope.max_ports_per_host:
                raise ScanConfigurationError(
                    f"Requested {len(ports)} ports, which exceeds scope limit "
                    f"of {scope.max_ports_per_host}."
                )

            targets = scope.include_targets
            exclusions = scope.exclude_targets
            concurrency = args.concurrency or scope.default_concurrency
            timeout = args.timeout or scope.default_timeout_seconds
            max_hosts = args.max_hosts or scope.max_hosts
            classification = scope.classification
            distribution = scope.distribution

        else:
            if not args.target:
                raise ScanConfigurationError("A target is required unless --scope is provided.")

            if not args.confirm_authorized:
                raise ScanConfigurationError(
                    "You must pass --confirm-authorized when scanning without a scope file."
                )

            targets = [args.target]
            exclusions = []
            concurrency = args.concurrency or 100
            timeout = args.timeout or 1.5
            max_hosts = args.max_hosts or 256
            classification = "UNCLASSIFIED"
            distribution = "Authorized assessment only"

        if concurrency < 1:
            raise ScanConfigurationError("Concurrency must be at least 1.")

        if timeout <= 0:
            raise ScanConfigurationError("Timeout must be greater than 0.")

        output_dir = Path(args.output_dir)
        reports = []

        for target in targets:
            report = await scan_target(
                target=target,
                ports=ports,
                concurrency=concurrency,
                timeout=timeout,
                max_hosts=max_hosts,
                rules_dir=rules_dir,
                exclusions=exclusions,
                classification=classification,
                distribution=distribution,
            )

            safe_target = target.replace("/", "_").replace(":", "_")
            html_path = render_html_report(report, output_dir / f"rangecheck-{safe_target}.html")
            json_path = write_json_report(report, output_dir / f"rangecheck-{safe_target}.json")
            csv_path = write_findings_csv(report, output_dir / f"rangecheck-{safe_target}.csv")

            reports.append((report, html_path, json_path, csv_path))

        for report, html_path, json_path, csv_path in reports:
            _print_summary(report, html_path, json_path, csv_path)

        return 0

    except (ScanConfigurationError, ScopeValidationError) as exc:
        LOGGER.error("Configuration error: %s", exc)
        console.print(f"[red]Configuration error:[/red] {exc}")
        return 2

    except KeyboardInterrupt:
        console.print("[yellow]Scan interrupted by user.[/yellow]")
        return 130

    except Exception as exc:
        LOGGER.exception("Unhandled error during assessment")
        console.print(f"[red]Unhandled error:[/red] {exc}")
        return 1


def _print_summary(report, html_path: Path, json_path: Path, csv_path: Path) -> None:
    table = Table(title=f"RangeCheck Summary: {report.target}")

    table.add_column("Metric")
    table.add_column("Value")

    table.add_row("Target", report.target)
    table.add_row("Hosts with findings", str(report.total_hosts))
    table.add_row("Open services", str(report.total_services))
    table.add_row("Findings", str(report.total_vulnerabilities))
    table.add_row("HTML report", str(html_path))
    table.add_row("JSON report", str(json_path))
    table.add_row("CSV findings", str(csv_path))

    console.print(table)

    severity_table = Table(title="Findings by Severity")
    severity_table.add_column("Severity")
    severity_table.add_column("Count")

    for severity, count in report.severity_counts.items():
        severity_table.add_row(severity, str(count))

    console.print(severity_table)


def main() -> None:
    raise SystemExit(asyncio.run(async_main()))
