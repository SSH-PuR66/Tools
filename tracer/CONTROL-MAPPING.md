# Control Mapping Approach

ControlTrace maps technical configuration checks to security frameworks for educational and reporting purposes.

## NIST SP 800-53

NIST mappings identify controls related to the failed configuration. Example:

- SSH root login enabled
  - AC-2, Account Management
  - AC-6, Least Privilege
  - IA-2, Identification and Authentication
  - CM-6, Configuration Settings

## MITRE ATT&CK

MITRE mappings explain how a misconfiguration may relate to adversary behavior. Example:

- SSH password authentication enabled
  - T1110, Brute Force
  - T1021.004, SSH

## DISA STIG

DISA STIG IDs are included where a similar public STIG requirement exists. These mappings are educational and should be validated against the specific operating system and STIG version used in a real assessment.

## CWE

CWE mappings describe software or configuration weakness classes where applicable.
