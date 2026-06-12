# ControlTrace Methodology

ControlTrace is inspired by federal security assessment workflows and references the following public documents:

- NIST SP 800-37 Rev. 2, Risk Management Framework
- NIST SP 800-53 Rev. 5, Security and Privacy Controls
- NIST SP 800-53A Rev. 5, Assessing Security and Privacy Controls
- NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments
- DISA STIG public guidance
- MITRE ATT&CK Enterprise
- FIRST CVSS v3.1

ControlTrace is not an official NIST, DISA, or government assessment product.

## Assessment Flow

1. Load version-controlled YAML rules
2. Collect local host evidence
3. Compare evidence to expected secure configuration
4. Mark each rule as pass or fail
5. Map failed rules to controls and adversary techniques
6. Assign risk using CVSS-style metadata
7. Generate HTML, JSON, CSV, and POA&M outputs

## Evidence Collection

Evidence is collected locally from:

- Configuration files
- Command output
- File permissions
- Service status
- Host metadata

ControlTrace avoids exploitation, brute forcing, evasion, persistence, or destructive testing.

## Finding Status

- `pass`: Evidence matched the expected secure configuration
- `fail`: Evidence did not match the expected secure configuration
- `error`: Evidence could not be collected or the check failed unexpectedly

## Manual Validation

All findings should be manually reviewed before remediation.
