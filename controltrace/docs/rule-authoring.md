# Rule Authoring

ControlTrace rules are YAML files stored in the `rules/` directory.

## Supported check types

- `file_contains_setting`
- `file_contains`
- `command_output_contains`
- `command_output_not_contains`
- `path_permission_not_world_writable`
- `interactive_shell_review`

## Rule quality checklist

- Clear rule ID
- Specific check
- Evidence guidance
- NIST mapping
- MITRE mapping
- CVSS metadata
- Practical remediation
