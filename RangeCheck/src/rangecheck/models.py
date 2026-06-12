from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ScopeConfig:
    engagement_name: str
    owner: str
    purpose: str
    authorized: bool
    authorization_statement: str
    include_targets: list[str]
    exclude_targets: list[str]
    max_hosts: int
    max_ports_per_host: int
    default_timeout_seconds: float
    default_concurrency: int
    classification: str
    distribution: str


@dataclass(frozen=True)
class ServiceFinding:
    host: str
    port: int
    protocol: str
    state: str
    service_name: str
    banner: str | None = None


@dataclass(frozen=True)
class FrameworkMapping:
    nist_sp_800_53: list[str]
    mitre_attack: list[dict[str, str]]
    cwe: list[str]


@dataclass(frozen=True)
class CvssMetadata:
    version: str
    vector: str
    score: float


@dataclass(frozen=True)
class VulnerabilityFinding:
    rule_id: str
    host: str
    port: int
    title: str
    category: str
    description: str
    severity: str
    cvss: CvssMetadata
    mappings: FrameworkMapping
    recommendation: str
    evidence: str
    references: list[str]


@dataclass
class HostAssessment:
    host: str
    services: list[ServiceFinding] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)


@dataclass
class AssessmentReport:
    tool_name: str
    tool_version: str
    target: str
    started_at: datetime
    completed_at: datetime
    classification: str
    distribution: str
    methodology: str
    hosts: list[HostAssessment]

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def total_services(self) -> int:
        return sum(len(host.services) for host in self.hosts)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(host.vulnerabilities) for host in self.hosts)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }

        for host in self.hosts:
            for finding in host.vulnerabilities:
                counts[finding.severity] = counts.get(finding.severity, 0) + 1

        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "classification": self.classification,
            "distribution": self.distribution,
            "methodology": self.methodology,
            "total_hosts": self.total_hosts,
            "total_services": self.total_services,
            "total_vulnerabilities": self.total_vulnerabilities,
            "severity_counts": self.severity_counts,
            "hosts": self.hosts,
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
