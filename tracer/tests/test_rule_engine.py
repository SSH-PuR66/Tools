from pathlib import Path

from controltrace.collectors.linux import LinuxCollector
from controltrace.rule_engine import RuleEngine


def test_file_contains_setting_passes(tmp_path: Path) -> None:
    config = tmp_path / "sshd_config"
    config.write_text("PermitRootLogin no\n", encoding="utf-8")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "ssh.yaml").write_text(
        f"""
rules:
  - id: CT-TEST-SSH-001
    title: "Root Login Disabled"
    platform: "linux"
    category: "access-control"
    check:
      type: "file_contains_setting"
      path: "{config}"
      key: "PermitRootLogin"
      expected_values:
        - "no"
    severity: "High"
    cvss:
      version: "3.1"
      vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
      score: 7.8
    mappings:
      nist_sp_800_53:
        - "AC-6"
      disa_stig:
        - "TEST-STIG"
      mitre_attack:
        - technique_id: "T1078"
          technique_name: "Valid Accounts"
      cwe:
        - "CWE-250"
    description: "Root login should be disabled."
    recommendation: "Set PermitRootLogin no."
    references: []
""",
        encoding="utf-8",
    )

    engine = RuleEngine.from_directory(rules_dir)
    findings = engine.evaluate_linux(LinuxCollector())

    assert len(findings) == 1
    assert findings[0].status == "pass"


def test_file_contains_setting_fails(tmp_path: Path) -> None:
    config = tmp_path / "sshd_config"
    config.write_text("PermitRootLogin yes\n", encoding="utf-8")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "ssh.yaml").write_text(
        f"""
rules:
  - id: CT-TEST-SSH-001
    title: "Root Login Disabled"
    platform: "linux"
    category: "access-control"
    check:
      type: "file_contains_setting"
      path: "{config}"
      key: "PermitRootLogin"
      expected_values:
        - "no"
    severity: "High"
    cvss:
      version: "3.1"
      vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
      score: 7.8
    mappings:
      nist_sp_800_53:
        - "AC-6"
      disa_stig:
        - "TEST-STIG"
      mitre_attack:
        - technique_id: "T1078"
          technique_name: "Valid Accounts"
      cwe:
        - "CWE-250"
    description: "Root login should be disabled."
    recommendation: "Set PermitRootLogin no."
    references: []
""",
        encoding="utf-8",
    )

    engine = RuleEngine.from_directory(rules_dir)
    findings = engine.evaluate_linux(LinuxCollector())

    assert len(findings) == 1
    assert findings[0].status == "fail"
