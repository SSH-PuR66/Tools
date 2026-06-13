<div align="center">

#  Security Audit & Verification Tools Suite

<p align="center">
  <img src="assets/banner.gif" alt="Tools Suite Banner" width="100%"/>
</p>

**A monorepo of three production-grade security engineering tools built around real federal and enterprise assessment workflows.**

> Built by [Sergio Rodriguez](https://github.com/SSH-PuR66) — Demonstrating full-lifecycle security engineering: discovery → evidence → mapping → reporting → remediation.

<br/>

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![NIST](https://img.shields.io/badge/NIST%20SP%20800--53-Mapped-0057A8?style=for-the-badge)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-FF0000?style=for-the-badge)](https://attack.mitre.org/)
[![CVSS](https://img.shields.io/badge/CVSS%20v3.1-Scored-FF6B35?style=for-the-badge)](https://www.first.org/cvss/)
[![DISA STIG](https://img.shields.io/badge/DISA%20STIG-Style%20Checks-4CAF50?style=for-the-badge)](https://public.cyber.mil/stigs/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](https://github.com/YOUR_USERNAME/tools/actions)

</div>

---

## 📁 What's Inside

This repo contains three independent, production-packaged Python tools that together cover the full security assessment lifecycle:

| Tool | Purpose | Output |
|------|---------|--------|
| [ RangeCheck](#-rangecheck) | Network exposure assessment & service fingerprinting | HTML · JSON · CSV |
| [ ControlTrace](#-controltrace) | Local baseline compliance & STIG-style checks | HTML · JSON · CSV · POA&M |
| [ Tracer](#-tracer) | System configuration auditing & POAM planning | HTML · JSON · CSV · POA&M |

---

##  RangeCheck

<p align="center">
  <img src="assets/rangecheck-demo.gif" alt="RangeCheck Demo" width="85%"/>
</p>

### What It Does

RangeCheck is an **authorized network exposure assessment tool** — it goes far beyond a basic port scanner. It performs concurrent TCP service discovery, lightweight fingerprinting, rule-based finding classification, and multi-format reporting — all mapped to industry-standard frameworks.

### What I Built / What I Learned

- **Async TCP scanning** with `asyncio` — handling hundreds of concurrent connections efficiently without threading overhead
- **YAML-driven rule engine** — findings are defined declaratively, making the tool extensible without touching source code
- **CVSS v3.1 vector validation** — learned to parse and validate real CVSS strings, not just assign arbitrary scores
- **Framework mapping** — manually mapped findings to NIST SP 800-53, MITRE ATT&CK Enterprise TTP IDs, and CWE
- **Jinja2 HTML templating** — generated professional audit-grade reports from structured scan data
- **Python packaging** with `pyproject.toml`, CLI entrypoints, and `pytest` test suite with coverage
- **GitHub Actions CI** — automated linting (ruff), type checking (mypy), and test runs on every push

### Features

• Concurrent TCP scanning via asyncio • CIDR and single-host targeting • YAML scope files with explicit authorization gates • Out-of-scope IP exclusion support • HTTP/HTTPS header fingerprinting • Generic banner grabbing • YAML rule engine for finding classification • CVSS v3.1 vector validation & metadata • NIST SP 800-53 Rev. • 5 control mapping • MITRE ATT&CK TTP mapping • CWE mapping • HTML, JSON, CSV report generation • Rotating file logs • pytest suite + GitHub Actions CI


### Quick Start

```bash
# Clone and install
git clone https://github.com/YOUR_USERNAME/tools.git
cd tools/RangeCheck
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"

# Scan localhost with specific ports
rangecheck 127.0.0.1 --confirm-authorized --ports 22,80,443 --output-dir reports

# Scan using a YAML scope file
rangecheck --scope examples/sample-scope.yaml --ports 22,80,443,445,3389

# Scan a full lab subnet
rangecheck 192.168.56.0/24 --confirm-authorized --ports 1-1024 --concurrency 250 --timeout 1.0

```
Assesment Lifecycle

┌──────────────────────────────────────────────────────────────────┐
│  1. Scope Validation  →  YAML scope file or --confirm-authorized │
│  2. Service Discovery →  Async TCP connection attempts           │
│  3. Fingerprinting    →  Banner grab + HTTP/S headers            │
│  4. Rule Evaluation   →  YAML rules classify findings            │
│  5. Framework Mapping →  NIST · MITRE ATT&CK · CWE               │
│  6. CVSS Scoring      →  v3.1 vector validation & metadata       │
│  7. Report Generation →  HTML · JSON · CSV                       │
└──────────────────────────────────────────────────────────────────┘

Report Outputs
File's & Purpose
controltrace-report.html -	Human-readable audit report
controltrace-report.json -	Machine-readable for automation
controltrace-findings.csv	- Spreadsheet-ready findings list
controltrace-poam.csv	POA&M - federal remediation tracking format


All three tools are designed for authorized use only.

Only run these tools against systems and networks you own or are explicitly authorized to assess
None of these tools perform exploitation, credential attacks, brute force, evasion, persistence, or destructive testing
These tools are built for defense, compliance validation, lab assessment, and portfolio demonstration
