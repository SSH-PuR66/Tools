# ControlTrace Methodology

ControlTrace is inspired by federal security assessment workflows and public guidance.

## Public references

- NIST SP 800-37 Rev. 2
- NIST SP 800-53 Rev. 5
- NIST SP 800-53A Rev. 5
- NIST SP 800-30 Rev. 1
- NIST SP 800-92
- DISA STIG public guidance
- MITRE ATT&CK Enterprise
- FIRST CVSS v3.1

ControlTrace is not an official NIST, DISA, or government product.

## Assessment flow

1. Load YAML rules.
2. Collect local host evidence.
3. Compare evidence to expected secure configuration.
4. Mark each rule as pass or fail.
5. Map failed rules to controls and adversary techniques.
6. Assign CVSS metadata.
7. Generate HTML, JSON, CSV, and POA&M outputs.

## Evidence sources

Evidence may come from:

- Configuration files
- Command output
- File permissions
- Local account metadata
- Host metadata

## Finding status

- `pass`: Evidence matched expected configuration.
- `fail`: Evidence did not match expected configuration.
- `error`: Evidence could not be collected or the check failed unexpectedly.

## Manual validation

Findings should be manually reviewed before remediation.
