from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from rangecheck.cvss import validate_cvss_v3_vector
from rangecheck.models import (
    CvssMetadata,
    FrameworkMapping,
    ServiceFinding,
    VulnerabilityFinding,
)


class RuleLoadError(ValueError):
    pass


class RuleEngine:
    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self.rules = rules

    @classmethod
    def from_directory(cls, rules_dir: Path) -> "RuleEngine":
        if not rules_dir.exists():
            raise RuleLoadError(f"Rules directory does not exist: {rules_dir}")

        rules: list[dict[str, Any]] = []

        for path in sorted(rules_dir.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))

            if not isinstance(raw, dict):
                raise RuleLoadError(f"Invalid rule file: {path}")

            file_rules = raw.get("rules", [])

            if not isinstance(file_rules, list):
                raise RuleLoadError(f"Rule file must contain a rules list: {path}")

            for rule in file_rules:
                _validate_rule(rule, path)
                rules.append(rule)

        if not rules:
            raise RuleLoadError(f"No rules were loaded from: {rules_dir}")

        return cls(rules)

    def evaluate_service(self, service: ServiceFinding) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []

        for rule in self.rules:
            if _rule_matches_service(rule, service):
                findings.append(_build_finding(rule, service))

        return findings


def _validate_rule(rule: Any, path: Path) -> None:
    required = [
        "id",
        "title",
        "category",
        "match",
        "severity",
        "cvss",
        "mappings",
        "description",
        "recommendation",
        "references",
    ]

    if not isinstance(rule, dict):
        raise RuleLoadError(f"Rule in {path} must be a YAML object.")

    for key in required:
        if key not in rule:
            raise RuleLoadError(f"Rule {rule.get('id', '<unknown>')} missing {key} in {path}")

    match = rule["match"]

    if not isinstance(match, dict):
        raise RuleLoadError(f"Rule {rule['id']} match must be an object.")

    if not any(key in match for key in ["ports", "services", "banner_regex"]):
        raise RuleLoadError(
            f"Rule {rule['id']} must match on at least one of ports, services, or banner_regex."
        )

    cvss = rule["cvss"]

    if not isinstance(cvss, dict):
        raise RuleLoadError(f"Rule {rule['id']} cvss must be an object.")

    if "vector" not in cvss or "score" not in cvss or "version" not in cvss:
        raise RuleLoadError(f"Rule {rule['id']} cvss must include version, vector, and score.")

    if not validate_cvss_v3_vector(str(cvss["vector"])):
        raise RuleLoadError(f"Rule {rule['id']} contains an invalid CVSS v3 vector.")


def _rule_matches_service(rule: dict[str, Any], service: ServiceFinding) -> bool:
    match = rule.get("match", {})

    ports = match.get("ports")
    services = match.get("services")
    banner_regex = match.get("banner_regex")

    port_match = isinstance(ports, list) and service.port in ports
    service_match = isinstance(services, list) and service.service_name in services

    banner_match = False
    if isinstance(banner_regex, list) and service.banner:
        banner_match = any(
            re.search(str(pattern), service.banner)
            for pattern in banner_regex
        )

    return port_match or service_match or banner_match


def _build_finding(rule: dict[str, Any], service: ServiceFinding) -> VulnerabilityFinding:
    cvss = rule["cvss"]
    mappings = rule["mappings"]

    return VulnerabilityFinding(
        rule_id=str(rule["id"]),
        host=service.host,
        port=service.port,
        title=str(rule["title"]),
        category=str(rule["category"]),
        description=str(rule["description"]).strip(),
        severity=str(rule["severity"]),
        cvss=CvssMetadata(
            version=str(cvss["version"]),
            vector=str(cvss["vector"]),
            score=float(cvss["score"]),
        ),
        mappings=FrameworkMapping(
            nist_sp_800_53=list(mappings.get("nist_sp_800_53", [])),
            mitre_attack=list(mappings.get("mitre_attack", [])),
            cwe=list(mappings.get("cwe", [])),
        ),
        recommendation=str(rule["recommendation"]).strip(),
        evidence=service.banner or f"{service.protocol.upper()} port {service.port} open",
        references=list(rule.get("references", [])),
    )
