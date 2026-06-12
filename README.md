# Security Audit and Verification Tools Suite

A monorepo containing three advanced security audit and assessment tools.

## Projects in this Repository

1. **[RangeCheck](./RangeCheck)** - Service exposure, banner verification, and hardening rules engine.
2. **[controltrace](./controltrace)** - Compliance, security control mapping, and vulnerability assessment tracing.
3. **[tracer](./tracer)** - System configuration auditing, baseline compliance tracking, and automated POAM planning.

## Directory Structure

```text
.
├── RangeCheck/                 # RangeCheck Tool
├── controltrace/               # Controltrace Tool
├── tracer/                     # Tracer Tool
├── complete_missing_files.py   # Workspace utility script
├── README.md                   # Repo guide
└── .gitignore                  # Global Git ignore rules
```

---

## Safe Pushing Checklist

Always verify you aren't committing local configurations:
- Keep root and sub-project `.env` files ignored.
- Never commit active SSH keys or private key files (`.pem`, `.key`).
- Do not commit local run output reports (ignored via `.gitignore` except template mocks).
