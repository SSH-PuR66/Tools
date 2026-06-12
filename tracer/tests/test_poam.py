from pathlib import Path

from controltrace.models import (
    AssessmentReport,
    ControlFinding,
    CvssMetadata,
    Evidence,
    FrameworkMapping,
    utc_now,
)
from controltrace.poam import write_poam_csv


def test_poam_exports_failed_findings_only(tmp_path: Path) -> None:
    now = utc_now()

    failed = ControlFinding(
        rule_id="CT-TEST-001",
        title="Test Failed Finding",
        platform="linux",
        category="test",
        status="fail",
        severity="High",
        cvss=CvssMetadata(version="3.1", vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", score=7.8),
        mappings=FrameworkMapping(
            nist_sp_800_53=["AC-6"],
            disa_stig=["TEST-STIG-ID"],
            mitre_attack=[{"technique_id": "T1078", "technique_name": "Valid Accounts"}],
            cwe=["CWE-250"],
        ),
        description="Test description",
        recommendation="Test recommendation",
        evidence=Evidence(source="/tmp/test", collected=True, value="bad=true"),
        references=[],
    )

    passed = ControlFinding(
        rule_id="CT-TEST-002",
        title="Test Passed Finding",
        platform="linux",
        category="test",
        status="pass",
        severity="Low",
        cvss=CvssMetadata(version="3.1", vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", score=0.0),
        mappings=FrameworkMapping(
            nist_sp_800_53=[],
            disa_stig=[],
            mitre_attack=[],
            cwe=[],
        ),
        description="Test description",
        recommendation="Test recommendation",
        evidence=Evidence(source="/tmp/test", collected=True, value="good=true"),
        references=[],
    )

    report = AssessmentReport(
        tool_name="ControlTrace",
        tool_version="0.1.0",
        hostname="test-host",
        platform="linux",
        started_at=now,
        completed_at=now,
        classification="UNCLASSIFIED",
        findings=[failed, passed],
    )

    output = write_poam_csv(report, tmp_path / "poam.csv")
    content = output.read_text(encoding="utf-8")

    assert "CT-TEST-001" in content
    assert "CT-TEST-002" not in content
