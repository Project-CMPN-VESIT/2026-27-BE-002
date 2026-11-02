"""Pydantic result models for the QUAL-KI Agentic SOC revised flow.

Each agent stage produces a typed result object.  A shared IncidentRecord
ties them together via ``incident_id``.
"""
from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Detection Agent
# ---------------------------------------------------------------------------

class DetectionResult(BaseModel):
    """Structured output from the Detection Agent.

    The Detection Agent receives the raw QML model output and converts it
    into a structured incident representation.
    """
    incident_id: str = Field(description="Unique incident identifier, e.g. INC-001")
    attack_type: str = Field(description="Predicted attack category from QML")
    confidence: float = Field(description="QML model confidence score")
    anomaly_score: float = Field(default=0.0, description="QML anomaly score")
    timestamp_range: dict[str, str] = Field(
        default_factory=dict,
        description="Start/end timestamps of the observed events",
    )
    source: dict[str, str] = Field(
        default_factory=dict,
        description="Source entity information (ip, entity, etc.)",
    )
    target: dict[str, str] = Field(
        default_factory=dict,
        description="Target entity information (ip, service, etc.)",
    )
    suspicious_events: list[str] = Field(
        default_factory=list,
        description="List of suspicious events extracted from logs",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence references extracted from logs and analysis",
    )
    qml: dict[str, Any] = Field(
        default_factory=dict,
        description="QML model metadata (model version, prediction, backend)",
    )
    initial_severity: str = Field(
        default="medium",
        description="Initial severity indication (low/medium/high/critical)",
    )
    iocs: list[str] = Field(
        default_factory=list,
        description="Indicators of compromise extracted from logs",
    )


# ---------------------------------------------------------------------------
# Triage Agent
# ---------------------------------------------------------------------------

class ConfirmedAttack(BaseModel):
    """Details of the confirmed attack after triage analysis."""
    category: str = Field(description="Confirmed attack category (e.g. DOS)")
    mechanism: str = Field(description="Specific attack mechanism (e.g. REQUEST_SPAMMING)")
    attack_path: list[str] = Field(
        default_factory=list,
        description="Ordered list of attack steps reconstructed from evidence",
    )


class TriageResult(BaseModel):
    """Structured output from the Triage Agent.

    The Triage Agent confirms the attack and reconstructs the exact
    technical attack path using DetectionResult + original raw logs.
    """
    incident_id: str
    confirmed_attack: ConfirmedAttack
    confidence: float = Field(description="Triage confidence in the confirmed attack")
    timeline: list[dict[str, str]] = Field(
        default_factory=list,
        description="Chronological timeline of attack events",
    )
    affected_assets: list[str] = Field(
        default_factory=list,
        description="Systems and services affected by the attack",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence supporting the triage conclusion",
    )
    root_cause_indicators: list[str] = Field(
        default_factory=list,
        description="Indicators pointing to the root cause",
    )
    impact: dict[str, str] = Field(
        default_factory=lambda: {
            "confidentiality": "NONE",
            "integrity": "NONE",
            "availability": "NONE",
        },
        description="CIA impact assessment",
    )


# ---------------------------------------------------------------------------
# Response Agent
# ---------------------------------------------------------------------------

class ResponseResult(BaseModel):
    """Structured output from the Response Agent."""
    incident_id: str
    confirmed_attack_summary: str = Field(
        description="Brief summary of the confirmed attack for context",
    )
    response_actions: list[str] = Field(
        default_factory=list,
        description="Ordered list of recommended response actions",
    )
    containment_steps: list[str] = Field(
        default_factory=list,
        description="Immediate containment measures",
    )
    recovery_steps: list[str] = Field(
        default_factory=list,
        description="Steps to restore normal operations",
    )
    monitoring_recommendations: list[str] = Field(
        default_factory=list,
        description="Ongoing monitoring recommendations post-incident",
    )


# ---------------------------------------------------------------------------
# Compliance Agent
# ---------------------------------------------------------------------------

class ComplianceAssessment(BaseModel):
    """Sub-structure for compliance assessment details."""
    status: str = Field(default="REVIEW_REQUIRED", description="Overall compliance status")
    controls_affected: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class ComplianceResult(BaseModel):
    """Structured output from the Compliance Agent (healthcare-specific)."""
    incident_id: str
    domain: str = Field(default="HEALTHCARE")
    data_compromised: bool = Field(default=False)
    data_types: list[str] = Field(
        default_factory=list,
        description="Types of data potentially compromised",
    )
    affected_assets: list[str] = Field(default_factory=list)
    exposure_type: str = Field(
        default="NONE",
        description="Type of data exposure (e.g. UNAUTHORIZED_ACCESS, EXFILTRATION)",
    )
    compliance_assessment: ComplianceAssessment = Field(
        default_factory=ComplianceAssessment,
    )
    recommended_compliance_actions: list[str] = Field(default_factory=list)
    compliance_checklist: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Detailed control-by-control evidence mapping",
    )
    compliance_summary: str = Field(
        default="",
        description="Human-readable compliance summary",
    )


# ---------------------------------------------------------------------------
# CVSS Agent
# ---------------------------------------------------------------------------

class CVSSExploitabilityMetrics(BaseModel):
    """CVSS v4.0 exploitability metrics."""
    attack_vector: str = Field(default="N", description="AV: N/A/L/P")
    attack_complexity: str = Field(default="L", description="AC: L/H")
    attack_requirements: str = Field(default="N", description="AT: N/P")
    privileges_required: str = Field(default="N", description="PR: N/L/H")
    user_interaction: str = Field(default="N", description="UI: N/P/A")


class CVSSImpactMetrics(BaseModel):
    """CVSS v4.0 impact metrics."""
    # Vulnerable system
    confidentiality_vuln: str = Field(default="N", description="VC: N/L/H")
    integrity_vuln: str = Field(default="N", description="VI: N/L/H")
    availability_vuln: str = Field(default="N", description="VA: N/L/H")
    # Subsequent system
    confidentiality_sub: str = Field(default="N", description="SC: N/L/H")
    integrity_sub: str = Field(default="N", description="SI: N/L/H")
    availability_sub: str = Field(default="N", description="SA: N/L/H")


class CVSSSupplementalContext(BaseModel):
    """Additional operational context for CVSS assessment."""
    automatable: str = Field(default="No", description="Is the attack automatable?")
    recovery: str = Field(default="User", description="Recovery effort: Automatic/User/Irrecoverable")


class CVSSResult(BaseModel):
    """Structured output from the CVSS Agent (CVSS v4.0)."""
    incident_id: str
    cvss_vector: str = Field(default="", description="CVSS v4.0 vector string")
    cvss_score: float = Field(default=0.0, description="Computed CVSS v4.0 score")
    severity_label: str = Field(default="NONE", description="NONE/LOW/MEDIUM/HIGH/CRITICAL")
    exploitability_metrics: CVSSExploitabilityMetrics = Field(
        default_factory=CVSSExploitabilityMetrics,
    )
    impact_metrics: CVSSImpactMetrics = Field(
        default_factory=CVSSImpactMetrics,
    )
    supplemental_context: CVSSSupplementalContext = Field(
        default_factory=CVSSSupplementalContext,
    )
    supporting_evidence: list[str] = Field(default_factory=list)
    error: Optional[str] = Field(default=None, description="Error message if CVSS calculation failed")


# ---------------------------------------------------------------------------
# Shared Incident Record
# ---------------------------------------------------------------------------

class IncidentRecord(BaseModel):
    """Shared incident object that ties all pipeline stages together."""
    incident_id: str
    raw_logs: list[Any] = Field(default_factory=list)
    qml_result: dict[str, Any] = Field(default_factory=dict)
    detection_result: Optional[dict[str, Any]] = None
    triage_result: Optional[dict[str, Any]] = None
    response_result: Optional[dict[str, Any]] = None
    compliance_result: Optional[dict[str, Any]] = None
    cvss_result: Optional[dict[str, Any]] = None
