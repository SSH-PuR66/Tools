# RangeCheck Assessment Methodology

RangeCheck follows an authorized, non-exploitative network exposure assessment methodology.

## Public references

- NIST SP 800-115, Technical Guide to Information Security Testing and Assessment
- NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments
- NIST SP 800-53 Rev. 5, Security and Privacy Controls
- MITRE ATT&CK Enterprise
- FIRST CVSS v3.1
- CWE

RangeCheck is not an official NIST, MITRE, FIRST, or government product.

## Assessment phases

### 1. Scope validation

RangeCheck requires either a YAML scope file with `authorized: true` or the `--confirm-authorized` CLI flag.

### 2. Service discovery

RangeCheck performs TCP connection attempts against configured ports.

### 3. Fingerprinting

Open services are lightly fingerprinted using common port mappings, banner grabbing, and HTTP HEAD requests.

### 4. Rule evaluation

YAML rules classify observations into findings.

### 5. Framework mapping

Findings may map to NIST SP 800-53, MITRE ATT&CK, and CWE.

### 6. Reporting

Reports are generated in HTML, JSON, and CSV formats.

## Limitations

RangeCheck does not prove exploitability. Findings should be manually validated before remediation.
