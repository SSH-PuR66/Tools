from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CvssVector:
    version: str
    vector: str
    score: float
    severity: str


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


def validate_cvss_v3_vector(vector: str) -> bool:
    if not vector.startswith("CVSS:3.1/") and not vector.startswith("CVSS:3.0/"):
        return False

    required_metrics = ["AV:", "AC:", "PR:", "UI:", "S:", "C:", "I:", "A:"]
    parts = vector.split("/")

    return all(any(part.startswith(metric) for part in parts) for metric in required_metrics)


def clamp_cvss(score: float) -> float:
    return round(max(0.0, min(10.0, score)), 1)


def normalize_cvss(version: str, vector: str, score: float) -> CvssVector:
    clean_score = clamp_cvss(score)

    return CvssVector(
        version=version,
        vector=vector,
        score=clean_score,
        severity=severity_from_score(clean_score),
    )
