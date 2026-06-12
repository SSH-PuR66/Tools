from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class CvssMetadata:
    version: str
    vector: str
    score: float


@dataclass(frozen=True)
class FrameworkMapping:
    nist_sp_800_53: list[str]
    disa_stig: list[str]
    mitre_attack: list[dict[str, str]]
    cwe: list[str]


@dataclass(frozen=True)
class Evidence:
    source: str
    collected: bool
    value: str
    error: str | None = None


@dataclass(frozen=True)
class ControlFinding:
    rule_id: str
    title: str
    platform: str
    category: str
    status: str
    severity: str
    cvss: CvssMetadata
    mappings: FrameworkMapping
    description: str
    recommendation: str
    evidence: Evidence
    references: list[str]


@dataclass
class AssessmentReport:
    tool_name: str
    tool_version: str
    hostname: str
    platform: str
    started_at: datetime
    completed_at: datetime
    classification: str
    findings: list[ControlFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def failed_findings(self) -> int:
        return sum(1 for finding in self.findings if finding.status == "fail")

    @property
    def passed_findings(self) -> int:
        return sum(1 for finding in self.findings if finding.status == "pass")

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

        for finding in self.findings:
            if finding.status == "fail":
                counts[finding.severity] = counts.get(finding.severity, 0) + 1

        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "hostname": self.hostname,
            "platform": self.platform,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "classification": self.classification,
            "total_findings": self.total_findings,
            "failed_findings": self.failed_findings,
            "passed_findings": self.passed_findings,
            "severity_counts": self.severity_counts,
            "findings": self.findings,
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
