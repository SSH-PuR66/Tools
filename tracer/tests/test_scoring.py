from controltrace.scoring import risk_rank, severity_from_cvss


def test_severity_from_cvss() -> None:
    assert severity_from_cvss(9.0) == "Critical"
    assert severity_from_cvss(7.0) == "High"
    assert severity_from_cvss(4.0) == "Medium"
    assert severity_from_cvss(0.1) == "Low"
    assert severity_from_cvss(0.0) == "Informational"


def test_risk_rank() -> None:
    assert risk_rank("Critical") > risk_rank("High")
    assert risk_rank("High") > risk_rank("Medium")
    assert risk_rank("Unknown") == 0
