from __future__ import annotations


NIST_CONTROL_FAMILIES: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "Personally Identifiable Information Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


def nist_control_family(control_id: str) -> str:
    prefix = control_id.split("-", 1)[0].upper()
    return NIST_CONTROL_FAMILIES.get(prefix, "Unknown")


def format_attack_technique(technique: dict[str, str]) -> str:
    technique_id = technique.get("technique_id", "UNKNOWN")
    technique_name = technique.get("technique_name", "Unknown Technique")
    return f"{technique_id}, {technique_name}"
