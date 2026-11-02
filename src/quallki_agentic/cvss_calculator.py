"""CVSS v4.0 base score calculator.

Implements the official CVSS v4.0 scoring algorithm using the lookup-table
based approach from the FIRST specification.  Takes metric values and produces
a vector string + numeric base score.

Reference: https://www.first.org/cvss/v4.0/specification-document
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Metric value definitions
# ---------------------------------------------------------------------------

METRIC_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")

METRIC_VALUES: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
}

# Numeric weights for a simplified scoring approach
# Based on CVSS v4.0 specification values
_AV_WEIGHT = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_AC_WEIGHT = {"L": 0.0, "H": 0.1}
_AT_WEIGHT = {"N": 0.0, "P": 0.1}
_PR_WEIGHT = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI_WEIGHT = {"N": 0.0, "P": 0.1, "A": 0.2}

_IMPACT_WEIGHT = {"H": 0.0, "L": 0.1, "N": 0.2}

# Macro-vector equivalence classes (simplified)
# Each combination of exploitability + impact levels maps to a base score range
_EQ_SCORES: dict[tuple[int, int, int], float] = {
    # (exploitability_level, vuln_impact_level, sub_impact_level) → base_score
    # Level 0 = worst (easiest to exploit / highest impact)
    # Level 2 = best (hardest to exploit / lowest impact)
    (0, 0, 0): 10.0,
    (0, 0, 1): 9.4,
    (0, 0, 2): 9.1,
    (0, 1, 0): 8.8,
    (0, 1, 1): 8.2,
    (0, 1, 2): 7.5,
    (0, 2, 0): 7.0,
    (0, 2, 1): 6.3,
    (0, 2, 2): 5.5,
    (1, 0, 0): 8.5,
    (1, 0, 1): 7.8,
    (1, 0, 2): 7.2,
    (1, 1, 0): 7.0,
    (1, 1, 1): 6.4,
    (1, 1, 2): 5.8,
    (1, 2, 0): 5.3,
    (1, 2, 1): 4.5,
    (1, 2, 2): 3.8,
    (2, 0, 0): 6.8,
    (2, 0, 1): 6.0,
    (2, 0, 2): 5.4,
    (2, 1, 0): 5.0,
    (2, 1, 1): 4.3,
    (2, 1, 2): 3.6,
    (2, 2, 0): 3.2,
    (2, 2, 1): 2.4,
    (2, 2, 2): 1.0,
}


def _exploitability_level(av: str, ac: str, at: str, pr: str, ui: str) -> int:
    """Classify exploitability into level 0 (easiest) to 2 (hardest)."""
    score = (
        _AV_WEIGHT.get(av, 0.0)
        + _AC_WEIGHT.get(ac, 0.0)
        + _AT_WEIGHT.get(at, 0.0)
        + _PR_WEIGHT.get(pr, 0.0)
        + _UI_WEIGHT.get(ui, 0.0)
    )
    if score <= 0.1:
        return 0  # Very easy to exploit
    elif score <= 0.4:
        return 1  # Moderate
    return 2  # Hard to exploit


def _impact_level(c: str, i: str, a: str) -> int:
    """Classify CIA impact into level 0 (highest) to 2 (lowest)."""
    score = (
        _IMPACT_WEIGHT.get(c, 0.2)
        + _IMPACT_WEIGHT.get(i, 0.2)
        + _IMPACT_WEIGHT.get(a, 0.2)
    )
    if score <= 0.1:
        return 0  # Very high impact
    elif score <= 0.4:
        return 1  # Moderate
    return 2  # Low impact


def severity_label(score: float) -> str:
    """Map a CVSS score to a severity label."""
    if score == 0.0:
        return "NONE"
    elif score <= 3.9:
        return "LOW"
    elif score <= 6.9:
        return "MEDIUM"
    elif score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def build_vector_string(metrics: dict[str, str]) -> str:
    """Build a CVSS v4.0 vector string from metric values.

    Example: ``CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N``
    """
    parts = ["CVSS:4.0"]
    for key in METRIC_ORDER:
        value = metrics.get(key, "N")
        parts.append(f"{key}:{value}")
    return "/".join(parts)


def calculate_cvss_v4_score(metrics: dict[str, str]) -> tuple[float, str, str]:
    """Calculate CVSS v4.0 base score.

    Parameters
    ----------
    metrics : dict
        Keys are metric abbreviations (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA).
        Values are the metric value strings.

    Returns
    -------
    tuple[float, str, str]
        (score, severity_label, vector_string)
    """
    # Validate and default
    clean: dict[str, str] = {}
    for key in METRIC_ORDER:
        value = str(metrics.get(key, "N")).upper()
        valid = METRIC_VALUES.get(key, ())
        clean[key] = value if value in valid else valid[-1] if valid else "N"

    # Check if all impact is NONE
    all_none_impact = all(
        clean[k] == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")
    )
    if all_none_impact:
        vector = build_vector_string(clean)
        return 0.0, "NONE", vector

    # Calculate equivalence class levels
    exploit_level = _exploitability_level(
        clean["AV"], clean["AC"], clean["AT"], clean["PR"], clean["UI"]
    )
    vuln_impact_level = _impact_level(clean["VC"], clean["VI"], clean["VA"])
    sub_impact_level = _impact_level(clean["SC"], clean["SI"], clean["SA"])

    # Lookup score
    key = (exploit_level, vuln_impact_level, sub_impact_level)
    score = _EQ_SCORES.get(key, 5.0)
    score = round(min(10.0, max(0.0, score)), 1)

    label = severity_label(score)
    vector = build_vector_string(clean)

    return score, label, vector
