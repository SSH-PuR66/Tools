from __future__ import annotations

import csv
from pathlib import Path

from rangecheck.models import AssessmentReport


def write_findings_csv(report: AssessmentReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "host",
                "port",
                "rule_id",
                "title",
                "severity",
                "cvss_score",
                "cvss_vector",
                "nist_sp_800_53",
                "mitre_attack",
                "recommendation",
            ]
        )

        for host in report.hosts:
            for finding in host.vulnerabilities:
                writer.writerow(
                    [
                        finding.host,
                        finding.port,
                        finding.rule_id,
                        finding.title,
                        finding.severity,
                        finding.cvss.score,
                        finding.cvss.vector,
                        ";".join(finding.mappings.nist_sp_800_53),
                        ";".join(
                            technique["technique_id"]
                            for technique in finding.mappings.mitre_attack
                        ),
                        finding.recommendation,
                    ]
                )

    return output_path
