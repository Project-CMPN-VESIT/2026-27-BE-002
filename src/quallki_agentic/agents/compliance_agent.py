"""Compliance Agent — healthcare-specific compliance and data compromise assessment.

Runs after the Response Agent.  Receives incident evidence and response context
to determine healthcare compliance impact.
"""
from __future__ import annotations

from typing import Any

from quallki_agentic.agents.base_agent import BaseAgent
from quallki_agentic.healthcare.compliance import assess_compliance
from quallki_agentic.progress import Status, get_progress_logger
from quallki_agentic.result_models import ComplianceAssessment, ComplianceResult


class ComplianceAgent(BaseAgent):
    name = "compliance"

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        logger = get_progress_logger()
        incident_id = str(payload.get("incident_id", "INC-000"))

        logger.emit(incident_id, "compliance", "compliance_analysis", Status.RUNNING,
                     "Compliance Agent: Starting healthcare compliance assessment")

        # ── Gather incident context ─────────────────────────────────────
        detection_result = payload.get("detection_result", {})
        triage_result = payload.get("triage_result", {})
        response_result = payload.get("response_result", {})
        logs = payload.get("logs", [])
        contains_phi = bool(payload.get("contains_phi", False))

        # ── Run control-catalog compliance check ────────────────────────
        logger.emit(incident_id, "compliance", "control_mapping", Status.RUNNING,
                     "Mapping incident evidence to compliance controls")

        checklist, summary, assessment = assess_compliance(payload)

        logger.emit(incident_id, "compliance", "control_mapping", Status.COMPLETED,
                     f"Mapped {assessment.get('applicable_controls', 0)} applicable controls")

        # ── LLM-enhanced compliance analysis ────────────────────────────
        logger.emit(incident_id, "compliance", "data_compromise_assessment", Status.RUNNING,
                     "Assessing data compromise and healthcare impact")

        from quallki_agentic.llm_helper import invoke_llm
        from quallki_agentic.log_filter import summarize_logs_for_llm

        confirmed_attack = triage_result.get("confirmed_attack", {}) if isinstance(triage_result, dict) else {}
        impact = triage_result.get("impact", {}) if isinstance(triage_result, dict) else {}
        filtered_logs = summarize_logs_for_llm(logs, detection_result, max_lines=5)

        prompt = f"""You are a healthcare compliance expert and auditor.

Analyze the following security incident in a healthcare environment and determine
the compliance implications.

## Incident Details
- Incident ID: {incident_id}
- Attack Category: {confirmed_attack.get("category", "unknown")}
- Attack Mechanism: {confirmed_attack.get("mechanism", "unknown")}
- Attack Path: {confirmed_attack.get("attack_path", [])}
- Contains PHI: {contains_phi}
- Impact: {impact}

## Suspicious Log Entries
{filtered_logs}

## Task
Determine:
1. Was protected healthcare information (PHI) compromised?
2. What types of data were potentially affected?
3. What type of data exposure occurred?
4. Which compliance controls are relevant?
5. What compliance-related actions should be initiated?

Return strict JSON with these keys:
- data_compromised: boolean
- data_types: list of strings (e.g., "Patient Records", "Personal Information", "Medical Images")
- exposure_type: string (NONE, UNAUTHORIZED_ACCESS, EXFILTRATION, MODIFICATION, DELETION, UNAVAILABLE)
- controls_affected: list of strings (relevant compliance control IDs)
- compliance_evidence: list of strings (evidence supporting your assessment)
- recommended_actions: list of strings (compliance actions to take)
- suggestions: string (detailed explanatory summary of compliance implications)
"""

        parsed = invoke_llm(prompt, agent_name="compliance")

        data_compromised = contains_phi  # Default based on PHI flag
        data_types: list[str] = []
        exposure_type = "NONE"
        controls_affected: list[str] = []
        compliance_evidence: list[str] = []
        recommended_actions: list[str] = []

        if parsed:
            logger.emit(incident_id, "compliance", "data_compromise_assessment", Status.COMPLETED,
                         "Healthcare compliance assessment completed (LLM-enriched)")

            data_compromised = bool(parsed.get("data_compromised", data_compromised))
            data_types = [str(dt) for dt in parsed.get("data_types", [])]
            exposure_type = str(parsed.get("exposure_type", "NONE"))
            controls_affected = [str(c) for c in parsed.get("controls_affected", [])]
            compliance_evidence = [str(e) for e in parsed.get("compliance_evidence", [])]
            recommended_actions = [str(a) for a in parsed.get("recommended_actions", [])]

            suggestions = str(parsed.get("suggestions", ""))
            if suggestions:
                summary += f" LLM Assessment: {suggestions}"
        else:
            logger.emit(incident_id, "compliance", "data_compromise_assessment", Status.COMPLETED,
                         "Healthcare compliance assessment completed (rule-based)")

        # ── Build affected assets list ──────────────────────────────────
        affected_assets = []
        if isinstance(triage_result, dict):
            affected_assets = [str(a) for a in triage_result.get("affected_assets", [])]
        if not affected_assets:
            affected_assets = [str(payload.get("asset_type", "unknown"))]

        # ── Build ComplianceResult ──────────────────────────────────────
        compliance_result = ComplianceResult(
            incident_id=incident_id,
            domain="HEALTHCARE",
            data_compromised=data_compromised,
            data_types=data_types,
            affected_assets=affected_assets,
            exposure_type=exposure_type,
            compliance_assessment=ComplianceAssessment(
                status="REVIEW_REQUIRED" if data_compromised else "LOW_RISK",
                controls_affected=controls_affected,
                evidence=compliance_evidence,
            ),
            recommended_compliance_actions=recommended_actions,
            compliance_checklist=checklist,
            compliance_summary=summary,
        )

        logger.emit(incident_id, "compliance", "compliance_analysis", Status.COMPLETED,
                     f"Compliance Agent completed — data compromised: {data_compromised}, "
                     f"exposure: {exposure_type}")

        return {
            "compliance_result": compliance_result.model_dump(),
            # Keep legacy keys for backward compatibility with existing UI components
            "compliance_note": summary,
            "compliance_checklist": checklist,
            "compliance_assessment": assessment,
        }
