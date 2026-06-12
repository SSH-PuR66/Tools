from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from controltrace.collectors.linux import LinuxCollector
from controltrace.models import (
    ControlFinding,
    CvssMetadata,
    Evidence,
    FrameworkMapping,
)


class RuleLoadError(ValueError):
    pass


class RuleEngine:
    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self.rules = rules

    @classmethod
    def from_directory(cls, rules_dir: Path) -> "RuleEngine":
        rules: list[dict[str, Any]] = []

        if not rules_dir.exists():
            raise RuleLoadError(f"Rules directory does not exist: {rules_dir}")

        for file_path in sorted(rules_dir.glob("*.yaml")):
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))

            if not isinstance(raw, dict):
                raise RuleLoadError(f"Invalid rule file: {file_path}")

            loaded_rules = raw.get("rules")

            if not isinstance(loaded_rules, list):
                raise RuleLoadError(f"Rule file must contain a rules list: {file_path}")

            for rule in loaded_rules:
                _validate_rule(rule, file_path)
                rules.append(rule)

        if not rules:
            raise RuleLoadError(f"No rules were loaded from: {rules_dir}")

        return cls(rules)

    def evaluate_linux(self, collector: LinuxCollector) -> list[ControlFinding]:
        findings: list[ControlFinding] = []

        for rule in self.rules:
            if rule.get("platform") != "linux":
                continue

            findings.append(self._evaluate_linux_rule(rule, collector))

        return findings

    def _evaluate_linux_rule(
        self,
        rule: dict[str, Any],
        collector: LinuxCollector,
    ) -> ControlFinding:
        check = rule["check"]
        check_type = check["type"]

        if check_type == "file_contains_setting":
            evidence = collector.read_file_setting(
                path=check["path"],
                key=check["key"],
            )

            expected_values = [str(value).lower() for value in check["expected_values"]]
            actual = evidence.value.split("=", 1)[-1].strip().lower() if evidence.value else ""
            status = "pass" if evidence.collected and actual in expected_values else "fail"

        elif check_type == "file_contains":
            evidence = collector.read_file_contains(
                path=check["path"],
                expected_substrings=list(check.get("expected_substrings", [])),
            )

            status = "pass" if evidence.collected and evidence.value == "all expected substrings present" else "fail"

        elif check_type == "command_output_contains":
            evidence = collector.run_command(
                command=check["command"],
                timeout=float(check.get("timeout", 5.0)),
            )

            expected_substrings = check.get("expected_substrings", [])
            allow_command_failure = bool(check.get("allow_command_failure", False))

            if evidence.error and not allow_command_failure:
                status = "fail"
            else:
                status = "pass" if all(text in evidence.value for text in expected_substrings) else "fail"

        elif check_type == "command_output_not_contains":
            evidence = collector.run_command(
                command=check["command"],
                timeout=float(check.get("timeout", 5.0)),
            )

            forbidden_substrings = check.get("forbidden_substrings", [])
            allow_command_failure = bool(check.get("allow_command_failure", False))

            if evidence.error and not allow_command_failure:
                status = "fail"
            else:
                status = "pass" if not any(text in evidence.value for text in forbidden_substrings) else "fail"

        elif check_type == "path_permission_not_world_writable":
            paths = check["paths"]
            evidence_items = [collector.path_permission(path) for path in paths]

            failed = [
                item
                for item in evidence_items
                if item.collected and "world_writable=True" in item.value
            ]

            combined_value = " | ".join(
                f"{item.source}: {item.value or item.error}" for item in evidence_items
            )

            evidence = Evidence(
                source=";".join(paths),
                collected=any(item.collected for item in evidence_items),
                value=combined_value,
                error=None,
            )

            status = "fail" if failed else "pass"

        elif check_type == "interactive_shell_review":
            evidence = collector.user_shells()
            allowed_users = set(check.get("allowed_users", []))

            observed = evidence.value.split("; ") if evidence.value else []
            risky = []

            for item in observed:
                username = item.split(":", 1)[0]
                if username and username not in allowed_users and item != "no interactive shells observed":
                    risky.append(item)

            if risky:
                evidence = Evidence(
                    source=evidence.source,
                    collected=evidence.collected,
                    value="; ".join(risky),
                    error=evidence.error,
                )
                status = "fail"
            else:
                status = "pass"

        else:
            evidence = Evidence(
                source=check_type,
                collected=False,
                value="",
                error=f"Unsupported check type: {check_type}",
            )
            status = "fail"

        return _build_finding(rule, status, evidence)


def _validate_rule(rule: Any, file_path: Path) -> None:
    required = [
        "id",
        "title",
        "platform",
        "category",
        "check",
        "severity",
        "cvss",
        "mappings",
        "description",
        "recommendation",
        "references",
    ]

    if not isinstance(rule, dict):
        raise RuleLoadError(f"Invalid rule object in {file_path}")

    for key in required:
        if key not in rule:
            raise RuleLoadError(f"Rule {rule.get('id', '<unknown>')} missing {key}")

    if not isinstance(rule["check"], dict) or "type" not in rule["check"]:
        raise RuleLoadError(f"Rule {rule['id']} check must include type.")

    cvss = rule["cvss"]
    if not isinstance(cvss, dict) or "score" not in cvss or "vector" not in cvss:
        raise RuleLoadError(f"Rule {rule['id']} cvss must include score and vector.")


def _build_finding(rule: dict[str, Any], status: str, evidence: Evidence) -> ControlFinding:
    cvss = rule["cvss"]
    mappings = rule["mappings"]

    return ControlFinding(
        rule_id=str(rule["id"]),
        title=str(rule["title"]),
        platform=str(rule["platform"]),
        category=str(rule["category"]),
        status=status,
        severity=str(rule["severity"]),
        cvss=CvssMetadata(
            version=str(cvss["version"]),
            vector=str(cvss["vector"]),
            score=float(cvss["score"]),
        ),
        mappings=FrameworkMapping(
            nist_sp_800_53=list(mappings.get("nist_sp_800_53", [])),
            disa_stig=list(mappings.get("disa_stig", [])),
            mitre_attack=list(mappings.get("mitre_attack", [])),
            cwe=list(mappings.get("cwe", [])),
        ),
        description=str(rule["description"]).strip(),
        recommendation=str(rule["recommendation"]).strip(),
        evidence=evidence,
        references=list(rule.get("references", [])),
    )
