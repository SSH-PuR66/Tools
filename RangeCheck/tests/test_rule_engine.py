from pathlib import Path

from rangecheck.models import ServiceFinding
from rangecheck.rule_engine import RuleEngine


def test_rule_engine_matches_port(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "rules.yaml").write_text(
        """
rules:
  - id: RC-TEST-TELNET
    title: "Telnet Exposed"
    category: "test"
    match:
      ports: [23]
    severity: "High"
    cvss:
      version: "3.1"
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
      score: 8.6
    mappings:
      nist_sp_800_53:
        - "SC-8"
      mitre_attack:
        - technique_id: "T1040"
          technique_name: "Network Sniffing"
      cwe:
        - "CWE-319"
    description: "Test description"
    recommendation: "Disable Telnet"
    references: []
""",
        encoding="utf-8",
    )

    engine = RuleEngine.from_directory(rules_dir)

    service = ServiceFinding(
        host="127.0.0.1",
        port=23,
        protocol="tcp",
        state="open",
        service_name="telnet",
        banner=None,
    )

    findings = engine.evaluate_service(service)

    assert len(findings) == 1
    assert findings[0].rule_id == "RC-TEST-TELNET"
    assert findings[0].severity == "High"


def test_rule_engine_matches_banner(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "rules.yaml").write_text(
        """
rules:
  - id: RC-TEST-BANNER
    title: "Technology Disclosure"
    category: "test"
    match:
      banner_regex:
        - "(?i)x-powered-by"
    severity: "Low"
    cvss:
      version: "3.1"
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
      score: 5.3
    mappings:
      nist_sp_800_53:
        - "CM-7"
      mitre_attack:
        - technique_id: "T1592"
          technique_name: "Gather Victim Host Information"
      cwe:
        - "CWE-200"
    description: "Test description"
    recommendation: "Remove header"
    references: []
""",
        encoding="utf-8",
    )

    engine = RuleEngine.from_directory(rules_dir)

    service = ServiceFinding(
        host="127.0.0.1",
        port=80,
        protocol="tcp",
        state="open",
        service_name="http",
        banner="X-Powered-By: PHP/5.6",
    )

    findings = engine.evaluate_service(service)

    assert len(findings) == 1
    assert findings[0].rule_id == "RC-TEST-BANNER"
