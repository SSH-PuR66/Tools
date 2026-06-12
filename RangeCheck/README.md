# RangeCheck

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Assessment](https://img.shields.io/badge/type-authorized%20network%20assessment-green)
![Frameworks](https://img.shields.io/badge/mapping-NIST%20%7C%20MITRE%20%7C%20CWE%20%7C%20CVSS-purple)
![Use](https://img.shields.io/badge/use-authorized%20only-red)

RangeCheck is an authorized network exposure assessment tool built to demonstrate practical security engineering for defense, federal, and enterprise environments.

It performs concurrent TCP service discovery, lightweight service fingerprinting, YAML-based finding classification, CVSS metadata assignment, NIST SP 800-53 mapping, MITRE ATT&CK mapping, CWE mapping, and professional HTML, JSON, and CSV reporting.

RangeCheck is not an exploit framework. It does not perform brute force, credential attacks, evasion, persistence, stealth scanning, exploitation, or destructive testing.

## Why this project matters

Many beginner cybersecurity projects stop at a basic port scanner. RangeCheck demonstrates a fuller assessment lifecycle:

1. Define authorized scope.
2. Discover exposed services.
3. Fingerprint safely.
4. Classify findings with explainable YAML rules.
5. Map findings to NIST SP 800-53, MITRE ATT&CK, and CWE.
6. Assign CVSS metadata.
7. Generate reports that support remediation and review.

## Features

- Concurrent TCP scanning with asyncio
- CIDR and single-host target support
- YAML scope files with explicit authorization
- Out-of-scope exclusion support
- Host and port safety limits
- HTTP and HTTPS header fingerprinting
- Generic banner grabbing
- YAML rule engine
- CVSS v3.1 vector validation
- NIST SP 800-53 mapping
- MITRE ATT&CK mapping
- CWE mapping
- HTML, JSON, and CSV outputs
- Rotating file logs
- pytest test suite
- GitHub Actions CI

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/rangecheck.git
cd rangecheck
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Usage

Scan localhost:

```bash
rangecheck 127.0.0.1 --confirm-authorized --ports 22,80,443 --output-dir reports
```

Scan using a scope file:

```bash
rangecheck --scope examples/sample-scope.yaml --ports 22,80,443,445,3389
```

Scan a lab subnet:

```bash
rangecheck 192.168.56.0/24 --confirm-authorized --ports 1-1024 --concurrency 250 --timeout 1.0
```

## Outputs

RangeCheck writes:

- HTML report for human review
- JSON report for automation
- CSV report for remediation tracking

## Public references

- NIST SP 800-53 Rev. 5, Security and Privacy Controls
- NIST SP 800-115, Technical Guide to Information Security Testing and Assessment
- NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments
- MITRE ATT&CK Enterprise
- FIRST CVSS v3.1
- CWE

## Reviewer note

RangeCheck was designed to demonstrate security engineering maturity, not offensive exploitation. It focuses on safe discovery, evidence collection, standards mapping, reporting, and remediation guidance.

## Ethical use

Only use RangeCheck against systems and networks you own or are explicitly authorized to assess.
