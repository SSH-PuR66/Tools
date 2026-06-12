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
