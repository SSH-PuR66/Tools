from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

from rangecheck.models import ScopeConfig


class ScopeValidationError(ValueError):
    pass


def load_scope(path: Path) -> ScopeConfig:
    if not path.exists():
        raise ScopeValidationError(f"Scope file does not exist: {path}")

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    if not isinstance(raw, dict):
        raise ScopeValidationError("Scope file must be a YAML object.")

    engagement = _require_dict(raw, "engagement")
    targets = _require_dict(raw, "targets")
    limits = _require_dict(raw, "limits")
    reporting = _require_dict(raw, "reporting")

    authorized = bool(engagement.get("authorized", False))

    if not authorized:
        raise ScopeValidationError("Scope file must explicitly set engagement.authorized: true.")

    include_targets = _require_str_list(targets.get("include", []), "targets.include")
    exclude_targets = _require_str_list(targets.get("exclude", []), "targets.exclude")

    if not include_targets:
        raise ScopeValidationError("At least one included target is required.")

    for target in include_targets + exclude_targets:
        _validate_ip_or_cidr(target)

    max_hosts = int(limits.get("max_hosts", 256))
    max_ports_per_host = int(limits.get("max_ports_per_host", 1000))
    timeout = float(limits.get("default_timeout_seconds", 1.5))
    concurrency = int(limits.get("default_concurrency", 100))

    if max_hosts < 1:
        raise ScopeValidationError("limits.max_hosts must be greater than 0.")

    if max_ports_per_host < 1 or max_ports_per_host > 65535:
        raise ScopeValidationError("limits.max_ports_per_host must be between 1 and 65535.")

    if timeout <= 0:
        raise ScopeValidationError("limits.default_timeout_seconds must be greater than 0.")

    if concurrency < 1:
        raise ScopeValidationError("limits.default_concurrency must be greater than 0.")

    return ScopeConfig(
        engagement_name=_require_str(engagement, "name"),
        owner=_require_str(engagement, "owner"),
        purpose=_require_str(engagement, "purpose"),
        authorized=authorized,
        authorization_statement=_require_str(engagement, "authorization_statement"),
        include_targets=include_targets,
        exclude_targets=exclude_targets,
        max_hosts=max_hosts,
        max_ports_per_host=max_ports_per_host,
        default_timeout_seconds=timeout,
        default_concurrency=concurrency,
        classification=str(reporting.get("classification", "UNCLASSIFIED")),
        distribution=str(reporting.get("distribution", "Authorized use only")),
    )


def _validate_ip_or_cidr(value: str) -> None:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ScopeValidationError(f"Invalid IP or CIDR target: {value}") from exc


def _require_dict(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)

    if not isinstance(value, dict):
        raise ScopeValidationError(f"Missing or invalid section: {key}")

    return value


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)

    if not isinstance(value, str) or not value.strip():
        raise ScopeValidationError(f"Missing or invalid string field: {key}")

    return value.strip()


def _require_str_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScopeValidationError(f"{name} must be a list of strings.")

    return value
