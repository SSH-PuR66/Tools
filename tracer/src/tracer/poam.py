from __future__ import annotations

import csv
from pathlib import Path

from controltrace.models import AssessmentReport


def write_poam_csv(report: AssessmentReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "Weakness ID",
                "Weakness Name",
                "Source",
                "Asset Identifier",
                "Original Risk Rating",
                "Adjusted Risk Rating",
                "NIST Controls",
                "MITRE ATT&CK",
                "Description",
                "Recommendation",
                "Evidence",
                "Status",
            ]
        )

        for finding in report.findings:
            if finding.status != "fail":
                continue

            writer.writerow(
                [
                    finding.rule_id,
                    finding.title,
                    "ControlTrace",
                    report.hostname,
                    finding.severity,
                    finding.severity,
                    ";".join(finding.mappings.nist_sp_800_53),
                    ";".join(
                        technique["technique_id"]
                        for technique in finding.mappings.mitre_attack
                    ),
                    finding.description,
                    finding.recommendation,
                    finding.evidence.value,
                    "Open",
                ]
            )

    return output_path
