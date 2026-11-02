from __future__ import annotations

from typing import Any, TypedDict


class OrchestratorState(TypedDict, total=False):
    """Shared state for the QUAL-KI Agentic SOC pipeline.

    Follows the revised flow: Preprocessing → QML → Detection → Triage →
    Response → Compliance, with CVSS running independently in the background.
    """

    # ── Inputs ──────────────────────────────────────────────────────────
    incident_id: str
    message: str
    source_ip: str
    scenario: str
    asset_type: str
    contains_phi: bool
    clinical_impact: str
    logs: list[str]
    telemetry_signals: dict
    simulation: dict
    compliance_context: dict
    compliance_evidence: dict
    alert_id: str
    event_time: str

    # ── Pipeline stage results ──────────────────────────────────────────
    preprocessed_features: dict       # Output of preprocessing
    qml_result: dict                  # Output of QML model inference
    detection_result: dict            # DetectionResult
    triage_result: dict               # TriageResult
    response_result: dict             # ResponseResult
    compliance_result: dict           # ComplianceResult
    cvss_result: dict                 # CVSSResult (from background thread)

    # ── Legacy / backward-compat keys ───────────────────────────────────
    iocs: list[str]
    compliance_note: str
    compliance_checklist: list[dict]
    compliance_assessment: dict

    # ── Final output ────────────────────────────────────────────────────
    final_report: dict
    final_summary: str
    progress_events: list[dict[str, Any]]
