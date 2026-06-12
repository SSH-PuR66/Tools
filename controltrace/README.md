# ControlTrace

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Assessment](https://img.shields.io/badge/type-local%20baseline%20assessment-green)
![Frameworks](https://img.shields.io/badge/mapping-NIST%20%7C%20MITRE%20%7C%20STIG-purple)
![Output](https://img.shields.io/badge/output-HTML%20%7C%20JSON%20%7C%20CSV%20%7C%20POA%26M-orange)

ControlTrace is a local security baseline assessment tool built to demonstrate practical security engineering for defense, federal, and enterprise environments.

It performs DISA STIG-style local configuration checks, collects audit evidence, maps failed controls to NIST SP 800-53, provides MITRE ATT&CK context, includes CVSS metadata, and generates audit-ready HTML, JSON, CSV, and POA&M reports.

ControlTrace is designed for authorized assessment, lab validation, and portfolio demonstration.

## Why this project matters

Many beginner cybersecurity projects focus only on scanning. ControlTrace focuses on how security is documented, assessed, and communicated in professional environments.

It demonstrates:

- Secure configuration assessment
- Local evidence collection
- Rule-based detection logic
- NIST SP 800-53 mapping
- DISA STIG-style baseline checks
- MITRE ATT&CK context
- POA&M-style remediation tracking
- Professional reporting
- Python packaging, testing, and CI

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/controltrace.git
cd controltrace
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

```bash
controltrace --rules rules --output-dir reports
```

Verbose mode:

```bash
controltrace --rules rules --output-dir reports --verbose
```

## Outputs

ControlTrace writes:

- `controltrace-report.html`
- `controltrace-report.json`
- `controltrace-findings.csv`
- `controltrace-poam.csv`

## Public references

- NIST SP 800-37 Rev. 2, Risk Management Framework
- NIST SP 800-53 Rev. 5, Security and Privacy Controls
- NIST SP 800-53A Rev. 5, Assessing Security and Privacy Controls
- NIST SP 800-30 Rev. 1, Guide for Conducting Risk Assessments
- NIST SP 800-92, Guide to Computer Security Log Management
- DISA STIG Document Library
- MITRE ATT&CK Enterprise
- FIRST CVSS v3.1
- CWE

## Reviewer note

ControlTrace was designed to show security engineering maturity, not exploitation. It focuses on local evidence collection, control validation, framework mapping, reporting, and remediation tracking.
