# Contributing to Security Tools Suite

Thank you for your interest in contributing to our security tools! We welcome contributions from the community.

## Available Tools

- **RangeCheck** — Network exposure assessment
- **ControlTrace** — Local baseline compliance
- **Tracer** — System configuration auditing

## Getting Started

1. **Fork** the repository
2. **Clone**: `git clone https://github.com/YOUR_USERNAME/tools.git`
3. **Choose a tool** (RangeCheck, ControlTrace, or Tracer)
4. **Create branch**: `git checkout -b feature/tool-name/feature-name`
5. **Make changes** and test
6. **Commit**: `git commit -m "Add feature to [tool]: description"`
7. **Push**: `git push origin feature/...`
8. **Open Pull Request**

## Development Setup

```bash
# Clone
git clone https://github.com/SSH-PuR66/tools.git
cd tools

# Install the tool for development
cd RangeCheck  # or ControlTrace or Tracer
python -m venv .venv
source .venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Check coverage
pytest --cov=<tool_name> --cov-report=term-missing
```

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings
- Use descriptive variable names

Example:

```python
def validate_cvss_vector(vector: str) -> bool:
    """
    Validate CVSS v3.1 vector string.
    
    Args:
        vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")
    
    Returns:
        True if valid, False otherwise
    """
    # Implementation
```

## Testing Requirements

All code contributions must include tests:

```bash
# Run tests for your tool
cd <tool_name>
pytest -v

# Check coverage (aim for >80%)
pytest --cov=<tool_name> --cov-report=term-missing
```

## Framework Mappings

When adding new checks or findings:

1. **NIST SP 800-53**: Map to relevant control (e.g., AC-2, SI-4)
2. **MITRE ATT&CK**: Use Enterprise TTP IDs if applicable
3. **CWE**: Reference Common Weakness Enumeration
4. **CVSS v3.1**: Use valid CVSS vectors

Example in YAML rule:

```yaml
- finding_id: "NET-001"
  title: "Exposed SSH Service"
  nist_controls:
    - AC-2
    - SI-4
  mitre_tactics:
    - "Reconnaissance"
  mitre_techniques:
    - "T1592"
  cwe: "CWE-200"
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
```

## Documentation

- Update README for user-facing changes
- Add docstrings to all functions
- Comment complex logic
- Document new config options
- Update this guide as needed

## Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code follows PEP 8
- [ ] Type hints added
- [ ] Docstrings present
- [ ] No new security warnings
- [ ] Documentation updated
- [ ] No unnecessary dependencies
- [ ] Commits are clean and descriptive

## Reporting Issues

### Security Issues
For security vulnerabilities, **do not** open a public issue. Email the maintainers instead.

### Bug Reports
Include:
- Tool name and version
- Steps to reproduce
- Expected vs actual behavior
- Error logs/stack traces
- Environment (OS, Python version)
- Authorized use confirmation

### Feature Requests
Include:
- Tool name
- Use case
- Proposed approach (optional)
- Related frameworks/standards

## Authorized Use Only

Remember: These are **authorized assessment tools only**.

- Only use against systems you own or have written authorization to assess
- Do not perform exploitation or destructive testing
- Follow all applicable laws and regulations

## Questions?

- Open an issue on GitHub
- Check existing issues first
- Review tool-specific documentation
- Look at example YAML configurations

---

**Thank you for strengthening our security tooling! 🔒**
