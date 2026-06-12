from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from rangecheck.models import AssessmentReport


def write_json_report(report: AssessmentReport, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(report)
    data["started_at"] = report.started_at.isoformat()
    data["completed_at"] = report.completed_at.isoformat()
    data["total_hosts"] = report.total_hosts
    data["total_services"] = report.total_services
    data["total_vulnerabilities"] = report.total_vulnerabilities
    data["severity_counts"] = report.severity_counts

    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return output_path
