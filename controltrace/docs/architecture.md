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
