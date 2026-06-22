---
title: "I Built 3 Security Assessment Tools and Packaged Them as a Monorepo — Here's What I Learned"
published: false
description: "RangeCheck, ControlTrace, and Tracer — a complete authorized security workflow from network exposure review to compliance mapping to threat correlation."
tags: cybersecurity, python, security, portfolio
cover_image: ""
canonical_url:
---

I'm 18, starting a cybersecurity degree this fall, and I wanted my GitHub to look like someone who actually *does* security work — not just someone who completed a Udemy course and called it a day.

So I built three tools that, together, cover the full audit workflow: discover what's exposed, check it against compliance baselines, and correlate findings with threat intelligence. Then I packaged them into one monorepo because that's how real teams organize shared tooling.

Here's what each tool does, the design decisions behind them, and what I'd tell someone trying to build a similar portfolio.

---

## The three tools

### RangeCheck — Network exposure assessment

Think of it as a safe, authorized version of what a pentester does on day one of an engagement: figure out what's listening on the network.

```
Authorized scope → TCP discovery → Banner grabbing → 
YAML rule matching → CVSS scoring → HTML/JSON/CSV report
```

Key decisions:
- **Concurrent TCP scanning** — Python's `asyncio` for fast service discovery without hammering the target
- **YAML-driven rule engine** — findings are classified by rules, not hardcoded `if` statements. Want to add a new check? Write YAML, not Python
- **CVSS metadata** — every finding gets a CVSS v3.1 score so the output looks like a real vulnerability report, not a hobbyist script
- **Framework mapping** — findings map to NIST SP 800-53 controls and MITRE ATT&CK techniques

The output is an HTML report you could hand to an auditor. Not a wall of terminal text.

### ControlTrace — Local baseline assessment

This is the compliance side. ControlTrace runs DISA STIG-style checks on a local system, collects evidence, maps controls to frameworks, and generates audit-ready reports including POA&M (Plan of Action and Milestones) documents.

```
System checks → Evidence collection → Control mapping → 
NIST 800-53 + MITRE ATT&CK → POA&M generation
```

Why this matters for interviews: compliance is boring but it's where the money is. If you can show a hiring manager that you understand POA&M reports and STIG baselines, you're already ahead of most entry-level candidates.

### Tracer — Threat intelligence pipeline

Tracer is the most architecturally ambitious of the three. It's a data pipeline:

```
Feed ingestion (Kafka) → Normalization → Elasticsearch indexing → 
Neo4j graph loading → Flask API for analyst queries
```

It handles:
- **Indicator ingestion** from MISP, OTX, AbuseIPDB feeds
- **Geo/IP enrichment** with LRU-capped caching
- **Risk scoring** based on source weights and severity classification
- **Graph correlation** — Neo4j stores relationships between indicators, sources, tags, and geo data
- **Wazuh/SIEM enrichment** — alerts get enriched with threat context before routing

---

## Why a monorepo?

Real security teams don't keep their scanner, their compliance tool, and their intel pipeline in three separate places. They share models, they share mappings, they share reporting infrastructure.

The monorepo lets me:
- Show a complete workflow in one `git clone`
- Share NIST/MITRE mapping data across tools
- Present it as one project in an interview instead of three disconnected scripts

```
Tools/
├── RangeCheck/      # Exposure assessment
├── controltrace/    # Compliance baseline
├── tracer/          # Threat intelligence
└── README.md        # Ties it all together
```

---

## Testing

Each tool has its own test suite. RangeCheck alone has tests for:
- CVSS scoring calculations
- Rule engine matching
- Scope validation
- Data model serialization
- CLI import verification

I wrote tests because untested security tools are a liability. If your scanner has a bug in its CVSS calculation, your report is wrong, and wrong reports are worse than no report.

---

## What this project says in an interview

| Question | Answer |
|---|---|
| "Do you understand the audit lifecycle?" | Scope → discover → assess → map → report → remediate |
| "Can you write production-quality Python?" | Async I/O, proper logging, YAML configs, framework mapping |
| "Do you know compliance frameworks?" | NIST 800-53, DISA STIGs, MITRE ATT&CK, CVSS v3.1 |
| "Can you work with data pipelines?" | Kafka → Elasticsearch → Neo4j → Flask API |
| "Do you test your code?" | Full test suites for each tool |

---

## What I'd improve

- **Better CI/CD** — run tests and SAST on every push
- **Plugin architecture** — let users drop in custom checks without touching core code
- **Unified CLI** — one command to run all three tools in sequence
- **Better docs** — inline docstrings are good but a proper user guide would be better

---

## The honest part

I'm not pretending these tools replace Nessus or Splunk. They're portfolio projects built by a student. But they demonstrate that I understand *how* these tools work under the hood — and that matters more at the entry level than knowing which button to click in a commercial product.

If you're building a cybersecurity portfolio, my advice: don't just do CTFs. Build tools. Show that you can create, not just consume.

---

*Source: [github.com/SSH-PuR66/Tools](https://github.com/SSH-PuR66/Tools)*
