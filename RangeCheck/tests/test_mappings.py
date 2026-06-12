from rangecheck.mappings import format_attack_technique, nist_control_family


def test_nist_control_family_known() -> None:
    assert nist_control_family("AC-17") == "Access Control"
    assert nist_control_family("SC-7") == "System and Communications Protection"


def test_nist_control_family_unknown() -> None:
    assert nist_control_family("ZZ-1") == "Unknown"


def test_format_attack_technique() -> None:
    value = format_attack_technique(
        {
            "technique_id": "T1021.001",
            "technique_name": "Remote Desktop Protocol",
        }
    )

    assert value == "T1021.001, Remote Desktop Protocol"
