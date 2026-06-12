from __future__ import annotations

import argparse
from pathlib import Path
from textwrap import dedent


ROOT = Path.cwd()


def write_file(relative_path: str, content: str, *, overwrite: bool) -> None:
    path = ROOT / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists() and not overwrite:
        print(f"skip existing: {relative_path}")
        return

    path.write_text(dedent(content).lstrip(), encoding="utf-8")
    print(f"wrote: {relative_path}")


MIT_LICENSE = r'''
MIT License

Copyright (c) 2026 Sergio Rodriguez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''


COMMON_GITIGNORE = r'''
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
.venv/
venv/
env/
.env
.env.*
!.env.example

dist/
build/
*.egg-info/

.coverage
coverage.xml
htmlcov/
.pytest_cache/
.mypy_cache/
.ruff_cache/

logs/
reports/*.html
reports/*.json
reports/*.csv
reports/*.sarif
reports/evidence/

.DS_Store
Thumbs.db
.idea/
.vscode/
'''


RANGECHECK_FILES: dict[str, str] = {
    "rangecheck/pyproject.toml": r'''
    [project]
    name = "rangecheck"
    version = "0.2.0"
    description = "Authorized network exposure assessment with NIST SP 800-53, MITRE ATT&CK, CWE, CVSS, and professional reporting."
    authors = [
      { name = "Sergio Rodriguez" }
    ]
    readme = "README.md"
    requires-python = ">=3.11"
    dependencies = [
      "jinja2>=3.1.4",
      "pyyaml>=6.0.2",
      "rich>=13.7.1"
    ]

    [project.optional-dependencies]
    dev = [
      "pytest>=8.2.0",
      "pytest-cov>=5.0.0",
      "ruff>=0.5.0",
      "mypy>=1.10.0"
    ]

    [project.scripts]
    rangecheck = "rangecheck.cli:main"

    [tool.pytest.ini_options]
    testpaths = ["tests"]
    pythonpath = ["src"]

    [tool.ruff]
    line-length = 100
    target-version = "py311"

    [tool.ruff.lint]
    select = ["E", "F", "I", "B", "UP", "SIM"]
    ignore = []

    [tool.mypy]
    python_version = "3.11"
    strict = true
    warn_unused_ignores = true
    warn_return_any = true
    warn_unreachable = true
    ''',

    "rangecheck/.gitignore": COMMON_GITIGNORE,

    "rangecheck/LICENSE": MIT_LICENSE,

    "rangecheck/Makefile": r'''
    .PHONY: install dev lint type test coverage run clean

    install:
    	pip install -e .

    dev:
    	pip install -e ".[dev]"

    lint:
    	ruff check src tests

    type:
    	mypy src

    test:
    	pytest

    coverage:
    	pytest --cov=rangecheck --cov-report=term-missing

    run:
    	rangecheck 127.0.0.1 --confirm-authorized --ports 22,80,443 --output-dir reports

    clean:
    	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info logs
    ''',

    "rangecheck/.github/workflows/ci.yml": r'''
    name: CI

    on:
      push:
        branches: ["main"]
      pull_request:
        branches: ["main"]

    jobs:
      quality:
        runs-on: ubuntu-latest

        steps:
          - name: Checkout
            uses: actions/checkout@v4

          - name: Set up Python
            uses: actions/setup-python@v5
            with:
              python-version: "3.11"

          - name: Install package
            run: |
              python -m pip install --upgrade pip
              pip install -e ".[dev]"

          - name: Ruff
            run: ruff check src tests

          - name: Mypy
            run: mypy src

          - name: Pytest
            run: pytest --cov=rangecheck --cov-report=term-missing
    ''',

    "rangecheck/README.md": r'''
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
    ''',

    "rangecheck/SECURITY.md": r'''
    # Security Policy

    ## Responsible use

    RangeCheck is intended for authorized network exposure assessment, lab validation, and educational portfolio demonstration.

    Do not use RangeCheck against third-party systems, public IP ranges, government systems, corporate networks, or any target without explicit authorization.

    ## Safety controls

    RangeCheck includes:

    - Explicit authorization confirmation
    - YAML scope file support
    - Maximum host limits
    - Maximum port limits
    - Timeout controls
    - Concurrency controls
    - Exclusion lists
    - Non-exploitative fingerprinting

    ## Intentionally excluded behavior

    RangeCheck does not include:

    - Exploit code
    - Credential attacks
    - Brute force logic
    - Persistence
    - Evasion
    - Malware behavior
    - Destructive testing
    - Stealth scanning

    ## Reporting issues

    Please report bugs that could cause unintended scanning behavior, excessive traffic, incorrect scope handling, or incorrect reports.
    ''',

    "rangecheck/SCOPE.md": r'''
    # Scope and Authorization

    RangeCheck is designed for authorized assessment only.

    ## Acceptable targets

    - Localhost
    - Personally owned lab networks
    - Training environments
    - CTF ranges
    - Employer-approved assessment ranges
    - Systems with written authorization

    ## Prohibited targets

    - Public IP ranges without authorization
    - Third-party infrastructure
    - Government systems without explicit permission
    - Corporate networks without written approval
    - Any system where scanning is prohibited

    ## Scope file example

    ```yaml
    engagement:
      name: "Local Lab Exposure Assessment"
      owner: "Sergio Rodriguez"
      purpose: "Portfolio lab assessment against owned systems only"
      authorized: true
      authorization_statement: "Testing is limited to assets owned or explicitly approved by the operator."
    ```
    ''',

    "rangecheck/METHODOLOGY.md": r'''
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
    ''',

    "rangecheck/docs/control-mapping.md": r'''
    # Control Mapping

    RangeCheck maps network exposure observations to public security frameworks.

    ## NIST SP 800-53

    Example mappings:

    - Telnet exposed: AC-17, IA-2, SC-8, SC-13
    - SMB exposed: AC-4, AC-17, CM-7, SC-7
    - RDP exposed: AC-17, IA-2, SC-7, AU-12

    ## MITRE ATT&CK

    Example mappings:

    - RDP exposure: T1021.001, Remote Desktop Protocol
    - SMB exposure: T1021.002, SMB/Windows Admin Shares
    - Banner disclosure: T1592, Gather Victim Host Information

    ## CWE

    Example mappings:

    - CWE-319, Cleartext Transmission of Sensitive Information
    - CWE-200, Exposure of Sensitive Information
    - CWE-284, Improper Access Control

    ## Disclaimer

    Mappings are educational and framework-aligned. They should be reviewed before use in a formal assessment.
    ''',

    "rangecheck/docs/references.md": r'''
    # References

    ## NIST

    - NIST SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
    - NIST SP 800-115: https://csrc.nist.gov/publications/detail/sp/800-115/final
    - NIST SP 800-30 Rev. 1: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
    - NIST Cybersecurity Framework: https://www.nist.gov/cyberframework

    ## MITRE

    - MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/
    - MITRE ATT&CK Techniques: https://attack.mitre.org/techniques/enterprise/
    - CWE: https://cwe.mitre.org/

    ## CVSS

    - FIRST CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
    - FIRST CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document

    ## CISA

    - Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    ''',

    "rangecheck/docs/rule-authoring.md": r'''
    # Rule Authoring Guide

    RangeCheck rules are YAML files in the `rules/` directory.

    ## Minimal rule

    ```yaml
    rules:
      - id: RC-CUSTOM-001
        title: "Example Finding"
        category: "example"
        match:
          ports: [1234]
          services: ["example"]
          banner_regex:
            - "(?i)example"
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
          score: 6.5
        mappings:
          nist_sp_800_53:
            - "SC-7"
          mitre_attack:
            - technique_id: "T1595"
              technique_name: "Active Scanning"
          cwe:
            - "CWE-200"
        description: "What the finding means."
        recommendation: "How to reduce risk."
        references:
          - "https://attack.mitre.org/"
    ```

    A rule matches if any configured match condition is true.
    ''',

    "rangecheck/docs/report-methodology.md": r'''
    # Report Methodology

    RangeCheck reports are designed for technical review and remediation tracking.

    ## HTML

    Human-readable report for review.

    ## JSON

    Machine-readable output for dashboards and automation.

    ## CSV

    Spreadsheet-friendly findings output for remediation tracking.

    ## Evidence

    Evidence is limited to observed service exposure and lightweight fingerprinting data.

    ## Validation

    Findings should be manually validated before remediation.
    ''',

    "rangecheck/docs/sample-engagement-notes.md": r'''
    # Sample Engagement Notes

    ## Objective

    Identify exposed TCP services on approved lab assets and map findings to public security frameworks.

    ## Scope

    - 127.0.0.1
    - 192.168.56.0/24

    ## Out of scope

    - Any public IP address
    - Any third-party system
    - Any system not owned or approved by the operator

    ## Constraints

    - Non-exploitative testing only
    - No credential attacks
    - No brute force
    - No destructive testing
    ''',

    "rangecheck/docs/threat-model.md": r'''
    # Threat Model

    ## Tool objective

    RangeCheck identifies exposed network services and produces framework-aligned findings.

    ## Assets protected

    - Target availability
    - Assessment authorization boundaries
    - Report integrity
    - Operator safety

    ## Misuse risks

    - Scanning unauthorized networks
    - Excessive traffic from high concurrency
    - Misinterpreting findings as confirmed exploitability
    - Publishing sensitive reports

    ## Mitigations

    - Authorization flag
    - Scope file support
    - Host and port limits
    - Timeout controls
    - Non-exploitative checks
    - Clear documentation
    ''',

    "rangecheck/examples/sample-scope.yaml": r'''
    engagement:
      name: "Local Lab Exposure Assessment"
      owner: "Sergio Rodriguez"
      purpose: "Portfolio lab assessment against owned systems only"
      authorized: true
      authorization_statement: "Testing is limited to assets owned or explicitly approved by the operator."

    targets:
      include:
        - "127.0.0.1"
      exclude: []

    limits:
      max_hosts: 256
      max_ports_per_host: 1000
      default_timeout_seconds: 1.5
      default_concurrency: 100

    reporting:
      classification: "UNCLASSIFIED"
      distribution: "Portfolio demonstration, sanitized"
    ''',

    "rangecheck/examples/sample-report.json": r'''
    {
      "tool_name": "RangeCheck",
      "tool_version": "0.2.0",
      "target": "127.0.0.1",
      "classification": "UNCLASSIFIED",
      "total_hosts": 1,
      "total_services": 2,
      "total_vulnerabilities": 1,
      "severity_counts": {
        "Critical": 0,
        "High": 0,
        "Medium": 1,
        "Low": 0,
        "Informational": 0
      },
      "note": "Sample sanitized report. Generate real reports with the CLI."
    }
    ''',

    "rangecheck/examples/sample-report.html": r'''
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>RangeCheck Sample Report</title>
    </head>
    <body>
      <h1>RangeCheck Sample Report</h1>
      <p>This is a sanitized placeholder. Generate a full report with the RangeCheck CLI.</p>
    </body>
    </html>
    ''',

    "rangecheck/rules/exposure-rules.yaml": r'''
    rules:
      - id: RC-EXPOSURE-TELNET-001
        title: "Insecure Telnet Service Exposed"
        category: "cleartext-remote-access"
        match:
          ports: [23]
          services: ["telnet"]
        severity: "High"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
          score: 8.6
        mappings:
          nist_sp_800_53:
            - "AC-17"
            - "IA-2"
            - "SC-8"
            - "SC-13"
          mitre_attack:
            - technique_id: "T1040"
              technique_name: "Network Sniffing"
            - technique_id: "T1557"
              technique_name: "Adversary-in-the-Middle"
            - technique_id: "T1021"
              technique_name: "Remote Services"
          cwe:
            - "CWE-319"
        description: >
          Telnet transmits credentials and session data without encryption.
        recommendation: >
          Disable Telnet and replace it with SSH using strong authentication and network restrictions.
        references:
          - "https://attack.mitre.org/techniques/T1040/"
          - "https://cwe.mitre.org/data/definitions/319.html"

      - id: RC-EXPOSURE-FTP-001
        title: "FTP Service Exposed"
        category: "cleartext-protocol"
        match:
          ports: [21]
          services: ["ftp"]
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
          score: 6.5
        mappings:
          nist_sp_800_53:
            - "AC-17"
            - "SC-8"
            - "SC-13"
          mitre_attack:
            - technique_id: "T1040"
              technique_name: "Network Sniffing"
          cwe:
            - "CWE-319"
        description: >
          FTP may transmit credentials and file data in cleartext.
        recommendation: >
          Replace FTP with SFTP or FTPS and restrict access to trusted networks.
        references:
          - "https://cwe.mitre.org/data/definitions/319.html"

      - id: RC-EXPOSURE-SMB-001
        title: "SMB or NetBIOS Service Exposed"
        category: "lateral-movement-risk"
        match:
          ports: [139, 445]
          services: ["smb", "netbios"]
        severity: "High"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
          score: 8.6
        mappings:
          nist_sp_800_53:
            - "AC-4"
            - "AC-17"
            - "CM-7"
            - "SC-7"
          mitre_attack:
            - technique_id: "T1021.002"
              technique_name: "SMB/Windows Admin Shares"
            - technique_id: "T1135"
              technique_name: "Network Share Discovery"
          cwe:
            - "CWE-200"
        description: >
          SMB and NetBIOS exposure may support share enumeration and lateral movement.
        recommendation: >
          Restrict SMB to trusted networks, disable SMBv1, enforce signing, and monitor access.
        references:
          - "https://attack.mitre.org/techniques/T1021/002/"

      - id: RC-EXPOSURE-RDP-001
        title: "Remote Desktop Service Exposed"
        category: "remote-access-risk"
        match:
          ports: [3389]
          services: ["rdp"]
        severity: "High"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
          score: 9.1
        mappings:
          nist_sp_800_53:
            - "AC-17"
            - "IA-2"
            - "SC-7"
            - "AU-12"
          mitre_attack:
            - technique_id: "T1021.001"
              technique_name: "Remote Desktop Protocol"
            - technique_id: "T1110"
              technique_name: "Brute Force"
            - technique_id: "T1078"
              technique_name: "Valid Accounts"
          cwe:
            - "CWE-284"
        description: >
          Exposed RDP is commonly targeted for credential attacks and unauthorized remote access.
        recommendation: >
          Restrict RDP behind VPN or allowlists, require MFA, enforce lockout policies, and centralize logs.
        references:
          - "https://attack.mitre.org/techniques/T1021/001/"
    ''',

    "rangecheck/rules/banner-rules.yaml": r'''
    rules:
      - id: RC-BANNER-OUTDATED-APACHE-001
        title: "Potentially Outdated Apache Version Disclosed"
        category: "version-disclosure"
        match:
          banner_regex:
            - "Apache/2\\.2"
            - "Apache/2\\.0"
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
          score: 6.3
        mappings:
          nist_sp_800_53:
            - "RA-5"
            - "SI-2"
            - "CM-8"
            - "CM-7"
          mitre_attack:
            - technique_id: "T1592"
              technique_name: "Gather Victim Host Information"
            - technique_id: "T1595"
              technique_name: "Active Scanning"
            - technique_id: "T1190"
              technique_name: "Exploit Public-Facing Application"
          cwe:
            - "CWE-200"
        description: >
          The service banner appears to disclose an outdated Apache version.
        recommendation: >
          Confirm the installed version, apply vendor security updates, and reduce version disclosure.
        references:
          - "https://attack.mitre.org/techniques/T1592/"

      - id: RC-BANNER-XPOWEREDBY-001
        title: "Technology Disclosure Header Present"
        category: "information-disclosure"
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
            - "RA-5"
            - "SC-7"
          mitre_attack:
            - technique_id: "T1592"
              technique_name: "Gather Victim Host Information"
            - technique_id: "T1595"
              technique_name: "Active Scanning"
          cwe:
            - "CWE-200"
        description: >
          The service discloses backend technology information through response headers.
        recommendation: >
          Remove or minimize technology disclosure headers where practical.
        references:
          - "https://cwe.mitre.org/data/definitions/200.html"
    ''',

    "rangecheck/rules/service-hardening-rules.yaml": r'''
    rules:
      - id: RC-SERVICE-REDIS-001
        title: "Redis Service Exposed"
        category: "data-store-exposure"
        match:
          ports: [6379]
          services: ["redis"]
        severity: "High"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
          score: 9.1
        mappings:
          nist_sp_800_53:
            - "AC-3"
            - "AC-6"
            - "CM-7"
            - "SC-7"
          mitre_attack:
            - technique_id: "T1210"
              technique_name: "Exploitation of Remote Services"
            - technique_id: "T1552"
              technique_name: "Unsecured Credentials"
          cwe:
            - "CWE-284"
        description: >
          Redis should not be exposed to untrusted networks.
        recommendation: >
          Bind Redis to localhost or trusted interfaces, require authentication, and restrict network access.
        references:
          - "https://attack.mitre.org/techniques/T1210/"

      - id: RC-SERVICE-VNC-001
        title: "VNC Service Exposed"
        category: "remote-access-risk"
        match:
          ports: [5900]
          services: ["vnc"]
        severity: "High"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
          score: 9.1
        mappings:
          nist_sp_800_53:
            - "AC-17"
            - "IA-2"
            - "SC-7"
          mitre_attack:
            - technique_id: "T1021.005"
              technique_name: "VNC"
            - technique_id: "T1110"
              technique_name: "Brute Force"
          cwe:
            - "CWE-287"
        description: >
          Exposed VNC can permit unauthorized graphical remote access if weakly protected.
        recommendation: >
          Disable VNC if unnecessary, require strong authentication, and restrict access to trusted networks or VPN.
        references:
          - "https://attack.mitre.org/techniques/T1021/005/"

      - id: RC-SERVICE-POSTGRES-001
        title: "PostgreSQL Service Exposed"
        category: "database-exposure"
        match:
          ports: [5432]
          services: ["postgresql"]
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
          score: 7.3
        mappings:
          nist_sp_800_53:
            - "AC-3"
            - "AC-6"
            - "SC-7"
            - "CM-7"
          mitre_attack:
            - technique_id: "T1210"
              technique_name: "Exploitation of Remote Services"
            - technique_id: "T1005"
              technique_name: "Data from Local System"
          cwe:
            - "CWE-200"
        description: >
          Exposed database services increase the risk of unauthorized access, credential attacks, and data exposure.
        recommendation: >
          Restrict PostgreSQL access to trusted application hosts, require strong authentication, and monitor failed login attempts.
        references:
          - "https://attack.mitre.org/techniques/T1210/"
    ''',

    "rangecheck/tests/test_cli_import.py": r'''
    from rangecheck.cli import build_parser


    def test_cli_parser_builds() -> None:
        parser = build_parser()
        assert parser.prog == "rangecheck"
    ''',

    "rangecheck/reports/.gitkeep": "",
}


CONTROLTRACE_FILES: dict[str, str] = {
    "controltrace/pyproject.toml": r'''
    [project]
    name = "controltrace"
    version = "0.1.0"
    description = "Audit-ready local security baseline assessment with NIST, MITRE, DISA STIG-style checks, CVSS metadata, and POA&M export."
    authors = [
      { name = "Sergio Rodriguez" }
    ]
    readme = "README.md"
    requires-python = ">=3.11"
    dependencies = [
      "jinja2>=3.1.4",
      "pyyaml>=6.0.2",
      "rich>=13.7.1"
    ]

    [project.optional-dependencies]
    dev = [
      "pytest>=8.2.0",
      "pytest-cov>=5.0.0",
      "ruff>=0.5.0",
      "mypy>=1.10.0"
    ]

    [project.scripts]
    controltrace = "controltrace.cli:main"

    [tool.pytest.ini_options]
    testpaths = ["tests"]
    pythonpath = ["src"]

    [tool.ruff]
    line-length = 100
    target-version = "py311"

    [tool.ruff.lint]
    select = ["E", "F", "I", "B", "UP", "SIM"]
    ignore = []

    [tool.mypy]
    python_version = "3.11"
    strict = true
    warn_unused_ignores = true
    warn_return_any = true
    warn_unreachable = true
    ''',

    "controltrace/.gitignore": COMMON_GITIGNORE,

    "controltrace/LICENSE": MIT_LICENSE,

    "controltrace/Makefile": r'''
    .PHONY: install dev lint type test coverage run clean

    install:
    	pip install -e .

    dev:
    	pip install -e ".[dev]"

    lint:
    	ruff check src tests

    type:
    	mypy src

    test:
    	pytest

    coverage:
    	pytest --cov=controltrace --cov-report=term-missing

    run:
    	controltrace --rules rules --output-dir reports

    clean:
    	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build *.egg-info logs
    ''',

    "controltrace/.github/workflows/ci.yml": r'''
    name: CI

    on:
      push:
        branches: ["main"]
      pull_request:
        branches: ["main"]

    jobs:
      quality:
        runs-on: ubuntu-latest

        steps:
          - name: Checkout
            uses: actions/checkout@v4

          - name: Set up Python
            uses: actions/setup-python@v5
            with:
              python-version: "3.11"

          - name: Install package
            run: |
              python -m pip install --upgrade pip
              pip install -e ".[dev]"

          - name: Ruff
            run: ruff check src tests

          - name: Mypy
            run: mypy src

          - name: Pytest
            run: pytest --cov=controltrace --cov-report=term-missing
    ''',

    "controltrace/README.md": r'''
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
    ''',

    "controltrace/SECURITY.md": r'''
    # Security Policy

    ## Responsible use

    ControlTrace is intended for local authorized security baseline assessment.

    ## Safety controls

    ControlTrace:

    - Runs locally
    - Reads configuration files
    - Runs non-destructive status commands
    - Produces reports
    - Does not exploit vulnerabilities
    - Does not attempt credential attacks
    - Does not modify system configuration
    - Does not install persistence
    - Does not evade detection

    ## Reporting issues

    Please report bugs that may cause incorrect evidence collection, incorrect finding status, unsafe command behavior, report corruption, or rule parsing errors.
    ''',

    "controltrace/ETHICS.md": r'''
    # Ethics Statement

    ControlTrace is built for authorized defensive security assessment.

    Acceptable uses include:

    - Personal lab assessment
    - Classroom work
    - Portfolio demonstration
    - Internal authorized baseline checks
    - Defensive configuration review

    Unacceptable uses include:

    - Running on systems without permission
    - Misrepresenting results
    - Using reports as proof of compromise
    - Modifying the tool for stealth, persistence, or exploitation

    Security work requires authorization, documentation, and professional judgment.
    ''',

    "controltrace/METHODOLOGY.md": r'''
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
    ''',

    "controltrace/CONTROL-MAPPING.md": r'''
    # Control Mapping Approach

    ControlTrace maps technical baseline checks to public security frameworks.

    ## NIST SP 800-53

    Example:

    - SSH root login enabled
      - AC-2, Account Management
      - AC-6, Least Privilege
      - IA-2, Identification and Authentication
      - CM-6, Configuration Settings

    ## DISA STIG

    DISA STIG IDs are included where a similar public STIG requirement exists.

    These mappings are educational and should be validated against the exact operating system, benchmark, and STIG version used in a formal environment.

    ## MITRE ATT&CK

    Example:

    - SSH password authentication enabled
      - T1110, Brute Force
      - T1021.004, SSH

    ## CWE

    CWE mappings describe weakness classes where applicable.
    ''',

    "controltrace/POAM-GUIDE.md": r'''
    # POA&M Export Guide

    POA&M stands for Plan of Action and Milestones.

    In federal environments, POA&M records are used to track known weaknesses, remediation plans, milestones, risk decisions, and closure evidence.

    ControlTrace exports a POA&M-style CSV for failed findings.

    ## Export fields

    - Weakness ID
    - Weakness Name
    - Source
    - Asset Identifier
    - Original Risk Rating
    - Adjusted Risk Rating
    - NIST Controls
    - MITRE ATT&CK
    - Description
    - Recommendation
    - Evidence
    - Status

    This is not an official agency POA&M template. It demonstrates understanding of remediation tracking workflows.
    ''',

    "controltrace/docs/architecture.md": r'''
    # Architecture

    ControlTrace uses a modular architecture.

    ```txt
    CLI
     |
     v
    Rule Engine
     |
     v
    Collector
     |
     v
    Evidence
     |
     v
    Findings
     |
     v
    Reports
    ```

    ## Components

    ### CLI

    Parses user options and coordinates assessment execution.

    ### Rule engine

    Loads YAML rules, validates rule shape, dispatches checks, and builds findings.

    ### Collectors

    Collect local system evidence. The Linux collector is implemented. The Windows collector is intentionally marked as roadmap.

    ### Reports

    Generate HTML, JSON, CSV, and POA&M outputs.
    ''',

    "controltrace/docs/rule-authoring.md": r'''
    # Rule Authoring

    ControlTrace rules are YAML files stored in the `rules/` directory.

    ## Supported check types

    - `file_contains_setting`
    - `file_contains`
    - `command_output_contains`
    - `command_output_not_contains`
    - `path_permission_not_world_writable`
    - `interactive_shell_review`

    ## Rule quality checklist

    - Clear rule ID
    - Specific check
    - Evidence guidance
    - NIST mapping
    - MITRE mapping
    - CVSS metadata
    - Practical remediation
    ''',

    "controltrace/docs/linux-checks.md": r'''
    # Linux Checks

    ControlTrace currently supports Linux checks.

    ## SSH

    - Root login disabled
    - Password authentication disabled

    ## Firewall

    - UFW active
    - firewalld active

    ## Audit

    - auditd active
    - journald persistence configured

    ## Filesystem

    - Sensitive directories not world-writable
    - Account files not world-writable

    ## Accounts

    - Interactive shell accounts reviewed
    ''',

    "controltrace/docs/windows-roadmap.md": r'''
    # Windows Roadmap

    Planned Windows checks:

    - Microsoft Defender status
    - Windows Firewall profiles
    - Local password policy
    - Account lockout policy
    - Local administrators group review
    - Audit policy status
    - Remote Desktop configuration
    - SMB signing configuration
    - PowerShell logging
    - Windows Event Log service status
    ''',

    "controltrace/docs/nist-rmf-alignment.md": r'''
    # NIST RMF Alignment

    ControlTrace is not an RMF automation platform, but it demonstrates concepts that align with the Risk Management Framework.

    ## Prepare

    Define assessment purpose and target host.

    ## Select

    YAML rules represent selected baseline checks.

    ## Assess

    ControlTrace collects evidence and evaluates rules.

    ## Monitor

    Repeated runs can show whether baseline posture improves or regresses.
    ''',

    "controltrace/docs/sample-assessment-notes.md": r'''
    # Sample Assessment Notes

    ## Objective

    Evaluate selected Linux configuration checks and produce evidence-backed findings.

    ## Constraints

    - Non-destructive checks only
    - No configuration changes
    - No exploitation
    - No credential attacks

    ## Deliverables

    - HTML report
    - JSON report
    - CSV findings
    - POA&M-style export
    ''',

    "controltrace/docs/references.md": r'''
    # References

    ## NIST

    - NIST SP 800-37 Rev. 2: https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final
    - NIST SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
    - NIST SP 800-53A Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final
    - NIST SP 800-30 Rev. 1: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
    - NIST SP 800-92: https://csrc.nist.gov/publications/detail/sp/800-92/final

    ## DISA

    - DISA STIG Document Library: https://public.cyber.mil/stigs/
    - DISA STIG Viewer: https://public.cyber.mil/stigs/srg-stig-tools/

    ## MITRE

    - MITRE ATT&CK Enterprise: https://attack.mitre.org/matrices/enterprise/
    - MITRE D3FEND: https://d3fend.mitre.org/
    - CWE: https://cwe.mitre.org/

    ## CVSS

    - FIRST CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
    ''',

    "controltrace/examples/sample-policy.yaml": r'''
    policy:
      name: "ControlTrace Local Linux Baseline"
      owner: "Sergio Rodriguez"
      classification: "UNCLASSIFIED"
      distribution: "Portfolio demonstration, sanitized"

    execution:
      include_passed: true
      output_dir: "reports"

    rules:
      directory: "rules"

    notes:
      - "This policy file is documentation-oriented in this release."
      - "Future versions may allow direct policy-driven execution."
    ''',

    "controltrace/examples/sample-report.json": r'''
    {
      "tool_name": "ControlTrace",
      "tool_version": "0.1.0",
      "hostname": "sample-host",
      "platform": "linux",
      "classification": "UNCLASSIFIED",
      "total_findings": 3,
      "failed_findings": 1,
      "passed_findings": 2,
      "severity_counts": {
        "Critical": 0,
        "High": 1,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
      },
      "note": "Sample sanitized report. Generate real reports with the CLI."
    }
    ''',

    "controltrace/examples/sample-report.html": r'''
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>ControlTrace Sample Report</title>
    </head>
    <body>
      <h1>ControlTrace Sample Report</h1>
      <p>This is a sanitized placeholder. Generate a full report with the ControlTrace CLI.</p>
    </body>
    </html>
    ''',

    "controltrace/examples/sample-findings.csv": r'''
    rule_id,title,status,severity,cvss_score,platform,category
    CT-LINUX-SSH-ROOT-001,SSH Root Login Is Not Explicitly Disabled,fail,High,7.8,linux,access-control
    ''',

    "controltrace/examples/sample-poam.csv": r'''
    Weakness ID,Weakness Name,Source,Asset Identifier,Original Risk Rating,Adjusted Risk Rating,Status
    CT-LINUX-SSH-ROOT-001,SSH Root Login Is Not Explicitly Disabled,ControlTrace,sample-host,High,High,Open
    ''',

    "controltrace/rules/linux-ssh.yaml": r'''
    rules:
      - id: CT-LINUX-SSH-ROOT-001
        title: "SSH Root Login Is Not Explicitly Disabled"
        platform: "linux"
        category: "access-control"
        check:
          type: "file_contains_setting"
          path: "/etc/ssh/sshd_config"
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
            - "AC-2"
            - "AC-6"
            - "IA-2"
            - "CM-6"
          disa_stig:
            - "RHEL-09-255050"
          mitre_attack:
            - technique_id: "T1078"
              technique_name: "Valid Accounts"
            - technique_id: "T1021.004"
              technique_name: "SSH"
          cwe:
            - "CWE-250"
        description: >
          SSH root login should be explicitly disabled to reduce privileged remote access risk.
        recommendation: >
          Set PermitRootLogin no in /etc/ssh/sshd_config, validate configuration, and restart sshd.
        references:
          - "https://public.cyber.mil/stigs/"
          - "https://attack.mitre.org/techniques/T1078/"

      - id: CT-LINUX-SSH-PASSWORD-001
        title: "SSH Password Authentication Is Enabled"
        platform: "linux"
        category: "authentication"
        check:
          type: "file_contains_setting"
          path: "/etc/ssh/sshd_config"
          key: "PasswordAuthentication"
          expected_values:
            - "no"
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
          score: 5.5
        mappings:
          nist_sp_800_53:
            - "IA-2"
            - "IA-5"
            - "AC-17"
            - "CM-6"
          disa_stig:
            - "RHEL-09-255060"
          mitre_attack:
            - technique_id: "T1110"
              technique_name: "Brute Force"
            - technique_id: "T1021.004"
              technique_name: "SSH"
          cwe:
            - "CWE-287"
        description: >
          Password-based SSH authentication can increase exposure to credential attacks.
        recommendation: >
          Prefer key-based authentication, MFA where available, and disable password authentication when feasible.
        references:
          - "https://attack.mitre.org/techniques/T1110/"
    ''',

    "controltrace/rules/linux-firewall.yaml": r'''
    rules:
      - id: CT-LINUX-FW-UFW-001
        title: "Host Firewall Does Not Appear Enabled"
        platform: "linux"
        category: "boundary-protection"
        check:
          type: "command_output_contains"
          command: "ufw status"
          expected_substrings:
            - "Status: active"
          allow_command_failure: true
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
          score: 5.7
        mappings:
          nist_sp_800_53:
            - "SC-7"
            - "CM-6"
            - "AC-4"
          disa_stig:
            - "RHEL-09-251010"
          mitre_attack:
            - technique_id: "T1046"
              technique_name: "Network Service Discovery"
            - technique_id: "T1021"
              technique_name: "Remote Services"
          cwe:
            - "CWE-693"
        description: >
          A disabled or missing host firewall can increase exposure to unauthorized network access.
        recommendation: >
          Enable and configure a host firewall appropriate for the environment.
        references:
          - "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
    ''',

    "controltrace/rules/linux-audit.yaml": r'''
    rules:
      - id: CT-LINUX-AUDITD-001
        title: "Audit Service Does Not Appear Active"
        platform: "linux"
        category: "audit-and-accountability"
        check:
          type: "command_output_contains"
          command: "systemctl is-active auditd"
          expected_substrings:
            - "active"
          allow_command_failure: true
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L"
          score: 4.4
        mappings:
          nist_sp_800_53:
            - "AU-2"
            - "AU-6"
            - "AU-12"
          disa_stig:
            - "RHEL-09-653010"
          mitre_attack:
            - technique_id: "T1070"
              technique_name: "Indicator Removal"
          cwe:
            - "CWE-778"
        description: >
          Audit logging supports detection, investigation, and accountability.
        recommendation: >
          Enable and start auditd or the platform-approved audit service.
        references:
          - "https://csrc.nist.gov/publications/detail/sp/800-92/final"
    ''',

    "controltrace/rules/linux-filesystem.yaml": r'''
    rules:
      - id: CT-LINUX-FS-WORLDWRITABLE-001
        title: "World-Writable Sensitive Directory Detected"
        platform: "linux"
        category: "filesystem-permissions"
        check:
          type: "path_permission_not_world_writable"
          paths:
            - "/etc"
            - "/var/log"
            - "/usr/bin"
            - "/usr/sbin"
        severity: "High"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
          score: 7.8
        mappings:
          nist_sp_800_53:
            - "AC-6"
            - "CM-6"
            - "SI-7"
          disa_stig:
            - "RHEL-09-232030"
          mitre_attack:
            - technique_id: "T1222"
              technique_name: "File and Directory Permissions Modification"
            - technique_id: "T1574"
              technique_name: "Hijack Execution Flow"
          cwe:
            - "CWE-732"
        description: >
          Sensitive system directories should not be world-writable.
        recommendation: >
          Remove world-writable permissions from sensitive directories and validate package ownership.
        references:
          - "https://attack.mitre.org/techniques/T1222/"
    ''',

    "controltrace/rules/linux-accounts.yaml": r'''
    rules:
      - id: CT-LINUX-ACCOUNTS-SHELLS-001
        title: "Unexpected Interactive Shell Accounts Require Review"
        platform: "linux"
        category: "account-management"
        check:
          type: "interactive_shell_review"
          allowed_users:
            - "root"
        severity: "Medium"
        cvss:
          version: "3.1"
          vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
          score: 5.5
        mappings:
          nist_sp_800_53:
            - "AC-2"
            - "AC-6"
            - "IA-2"
          disa_stig:
            - "RHEL-09-411015"
          mitre_attack:
            - technique_id: "T1078"
              technique_name: "Valid Accounts"
            - technique_id: "T1087"
              technique_name: "Account Discovery"
          cwe:
            - "CWE-266"
        description: >
          Accounts with interactive shells should be reviewed to confirm they are authorized and necessary.
        recommendation: >
          Disable unnecessary accounts, assign nologin shells to service accounts, and document approved interactive users.
        references:
          - "https://attack.mitre.org/techniques/T1078/"
    ''',

    "controltrace/tests/fixtures/sshd_config_secure.txt": r'''
    PermitRootLogin no
    PasswordAuthentication no
    ''',

    "controltrace/tests/fixtures/sshd_config_insecure.txt": r'''
    PermitRootLogin yes
    PasswordAuthentication yes
    ''',

    "controltrace/tests/fixtures/sample_rules.yaml": r'''
    rules:
      - id: CT-FIXTURE-SSH-001
        title: "Fixture SSH Root Login Disabled"
        platform: "linux"
        category: "access-control"
        check:
          type: "file_contains_setting"
          path: "/tmp/sshd_config"
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
        description: "Fixture test rule."
        recommendation: "Set PermitRootLogin no."
        references: []
    ''',

    "controltrace/tests/test_cli_import.py": r'''
    from controltrace.cli import build_parser


    def test_cli_parser_builds() -> None:
        parser = build_parser()
        assert parser.prog == "controltrace"
    ''',

    "controltrace/reports/.gitkeep": "",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing files instead of only filling missing files.",
    )
    args = parser.parse_args()

    print("Completing RangeCheck files...")
    for relative_path, content in RANGECHECK_FILES.items():
        write_file(relative_path, content, overwrite=args.overwrite)

    print()
    print("Completing ControlTrace files...")
    for relative_path, content in CONTROLTRACE_FILES.items():
        write_file(relative_path, content, overwrite=args.overwrite)

    print()
    print("Done.")
    print()
    print("Verify RangeCheck:")
    print("  cd rangecheck")
    print("  pip install -e '.[dev]'")
    print("  ruff check src tests")
    print("  mypy src")
    print("  pytest")
    print("  rangecheck 127.0.0.1 --confirm-authorized --ports 22,80,443 --output-dir reports")
    print()
    print("Verify ControlTrace:")
    print("  cd controltrace")
    print("  pip install -e '.[dev]'")
    print("  ruff check src tests")
    print("  mypy src")
    print("  pytest")
    print("  controltrace --rules rules --output-dir reports")


if __name__ == "__main__":
    main()
