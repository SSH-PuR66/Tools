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
