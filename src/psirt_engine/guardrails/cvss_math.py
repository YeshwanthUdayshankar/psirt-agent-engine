"""Deterministic CVSS v4.0 vector parsing, score computation, and CVE JSON 5.1 expansion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cvss import CVSS4
from cvss.exceptions import CVSS4Error

METRIC_VALUE_MAPS: dict[str, tuple[str, dict[str, str]]] = {
    "AV": ("attackVector", {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}),
    "AC": ("attackComplexity", {"L": "LOW", "H": "HIGH"}),
    "AT": ("attackRequirements", {"N": "NONE", "P": "PRESENT"}),
    "PR": ("privilegesRequired", {"N": "NONE", "L": "LOW", "H": "HIGH"}),
    "UI": ("userInteraction", {"N": "NONE", "P": "PASSIVE", "A": "ACTIVE"}),
    "VC": ("vulnConfidentialityImpact", {"H": "HIGH", "L": "LOW", "N": "NONE"}),
    "VI": ("vulnIntegrityImpact", {"H": "HIGH", "L": "LOW", "N": "NONE"}),
    "VA": ("vulnAvailabilityImpact", {"H": "HIGH", "L": "LOW", "N": "NONE"}),
    "SC": ("subConfidentialityImpact", {"H": "HIGH", "L": "LOW", "N": "NONE"}),
    "SI": ("subIntegrityImpact", {"H": "HIGH", "L": "LOW", "N": "NONE"}),
    "SA": ("subAvailabilityImpact", {"H": "HIGH", "L": "LOW", "N": "NONE"}),
}


@dataclass(frozen=True)
class CVSS4Calculation:
    vector_string: str
    score: float
    severity: str


def calculate_cvss4(vector_string: str) -> CVSS4Calculation:
    """Deterministically compute CVSS v4.0 score and qualitative severity using the cvss library."""
    try:
        parsed = CVSS4(vector_string)
    except CVSS4Error as exc:
        raise ValueError(f"Invalid CVSS v4.0 vector '{vector_string}': {exc}") from exc
    score = round(float(parsed.base_score), 1)
    severity = str(parsed.severity).upper()
    return CVSS4Calculation(
        vector_string=parsed.clean_vector(),
        score=score,
        severity=severity,
    )


def verify_cvss4_score(vector_string: str, claimed_score: float, claimed_severity: str | None = None) -> tuple[bool, str, CVSS4Calculation | None]:
    """Verify that a claimed CVSS v4.0 numeric score & severity match deterministic math."""
    try:
        calc = calculate_cvss4(vector_string)
    except ValueError as exc:
        return False, str(exc), None

    if abs(calc.score - round(float(claimed_score), 1)) > 0.05:
        return (
            False,
            f"CVSS v4.0 score mismatch for {calc.vector_string}: claimed {claimed_score}, calculated {calc.score}",
            calc,
        )
    if claimed_severity and calc.severity != claimed_severity.upper():
        return (
            False,
            f"CVSS v4.0 severity mismatch: claimed {claimed_severity}, calculated {calc.severity}",
            calc,
        )
    return True, "ok", calc


def build_cve5_cvss4_object(vector_string: str) -> dict[str, Any]:
    """Expand a CVSS v4.0 vector into a CVE JSON 5.1 compliant cvssV4_0 metrics object."""
    calc = calculate_cvss4(vector_string)
    obj: dict[str, Any] = {
        "version": "4.0",
        "vectorString": calc.vector_string,
        "baseScore": calc.score,
        "baseSeverity": calc.severity,
    }
    for part in calc.vector_string.split("/")[1:]:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        if k in METRIC_VALUE_MAPS:
            field_name, value_map = METRIC_VALUE_MAPS[k]
            if v in value_map:
                obj[field_name] = value_map[v]
    return obj
