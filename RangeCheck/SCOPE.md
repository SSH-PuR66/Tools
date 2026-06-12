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
