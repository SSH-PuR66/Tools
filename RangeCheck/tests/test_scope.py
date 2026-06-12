from pathlib import Path

import pytest

from rangecheck.scope import ScopeValidationError, load_scope


def test_load_valid_scope(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.yaml"

    scope_file.write_text(
        """
engagement:
  name: "Lab"
  owner: "Sergio"
  purpose: "Authorized lab test"
  authorized: true
  authorization_statement: "Owned lab only"

targets:
  include:
    - "127.0.0.1"
  exclude: []

limits:
  max_hosts: 10
  max_ports_per_host: 100
  default_timeout_seconds: 1.5
  default_concurrency: 50

reporting:
  classification: "UNCLASSIFIED"
  distribution: "Portfolio demonstration"
""",
        encoding="utf-8",
    )

    scope = load_scope(scope_file)

    assert scope.engagement_name == "Lab"
    assert scope.authorized is True
    assert scope.include_targets == ["127.0.0.1"]
    assert scope.max_hosts == 10


def test_scope_requires_authorized_true(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.yaml"

    scope_file.write_text(
        """
engagement:
  name: "Lab"
  owner: "Sergio"
  purpose: "Test"
  authorized: false
  authorization_statement: "Not authorized"

targets:
  include:
    - "127.0.0.1"
  exclude: []

limits:
  max_hosts: 10
  max_ports_per_host: 100
  default_timeout_seconds: 1.5
  default_concurrency: 50

reporting:
  classification: "UNCLASSIFIED"
  distribution: "Portfolio"
""",
        encoding="utf-8",
    )

    with pytest.raises(ScopeValidationError):
        load_scope(scope_file)
