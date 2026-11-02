"""CVSS v4.0 Agent — runs independently in the background.

Consumes raw logs and available incident evidence to calculate a CVSS v4.0
assessment.  Uses the LLM to extract exploitability and impact metrics from
the logs, then passes them through the CVSS v4.0 calculator.
"""
from __future__ import annotations

from typing import Any

from quallki_agentic.agents.base_agent import BaseAgent
from quallki_agentic.cvss_calculator import calculate_cvss_v4_score
from quallki_agentic.progress import Status, get_progress_logger
from quallki_agentic.result_models import (
    CVSSExploitabilityMetrics,
    CVSSImpactMetrics,
    CVSSResult,
    CVSSSupplementalContext,
)


class CVSSAgent(BaseAgent):
    name = "cvss"

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        logger = get_progress_logger()
        incident_id = str(payload.get("incident_id", "INC-000"))
        logs = payload.get("logs", [])
        detection_result = payload.get("detection_result", {})
        triage_result = payload.get("triage_result", {})

        logger.emit(incident_id, "cvss", "cvss_assessment", Status.RUNNING,
                     "CVSS Agent: Starting CVSS v4.0 assessment")

        try:
            # ── Step 1: Extract metrics via LLM ─────────────────────────
            logger.emit(incident_id, "cvss", "evidence_extraction", Status.RUNNING,
                         "Extracting exploitability and impact metrics from logs")

            from quallki_agentic.llm_helper import invoke_llm
            prompt = self._build_prompt(logs, detection_result, triage_result)
            parsed = invoke_llm(prompt, agent_name="cvss")

            if not parsed:
                raise RuntimeError("LLM returned no response for CVSS metric extraction")

            logger.emit(incident_id, "cvss", "evidence_extraction", Status.COMPLETED,
                         "CVSS metric extraction completed")

            # ── Step 2: Parse metrics ───────────────────────────────────
            logger.emit(incident_id, "cvss", "metric_calculation", Status.RUNNING,
                         "Calculating CVSS v4.0 vector and score")

            exploit = CVSSExploitabilityMetrics(
                attack_vector=str(parsed.get("AV", "N")).upper(),
                attack_complexity=str(parsed.get("AC", "L")).upper(),
                attack_requirements=str(parsed.get("AT", "N")).upper(),
                privileges_required=str(parsed.get("PR", "N")).upper(),
                user_interaction=str(parsed.get("UI", "N")).upper(),
            )
            impact = CVSSImpactMetrics(
                confidentiality_vuln=str(parsed.get("VC", "N")).upper(),
                integrity_vuln=str(parsed.get("VI", "N")).upper(),
                availability_vuln=str(parsed.get("VA", "N")).upper(),
                confidentiality_sub=str(parsed.get("SC", "N")).upper(),
                integrity_sub=str(parsed.get("SI", "N")).upper(),
                availability_sub=str(parsed.get("SA", "N")).upper(),
            )
            supplemental = CVSSSupplementalContext(
                automatable=str(parsed.get("automatable", "No")),
                recovery=str(parsed.get("recovery", "User")),
            )
            evidence_notes = parsed.get("evidence", [])
            if isinstance(evidence_notes, str):
                evidence_notes = [evidence_notes]
            if not isinstance(evidence_notes, list):
                evidence_notes = []

            # ── Step 3: Calculate score ─────────────────────────────────
            metrics = {
                "AV": exploit.attack_vector,
                "AC": exploit.attack_complexity,
                "AT": exploit.attack_requirements,
                "PR": exploit.privileges_required,
                "UI": exploit.user_interaction,
                "VC": impact.confidentiality_vuln,
                "VI": impact.integrity_vuln,
                "VA": impact.availability_vuln,
                "SC": impact.confidentiality_sub,
                "SI": impact.integrity_sub,
                "SA": impact.availability_sub,
            }
            score, severity, vector = calculate_cvss_v4_score(metrics)

            result = CVSSResult(
                incident_id=incident_id,
                cvss_vector=vector,
                cvss_score=score,
                severity_label=severity,
                exploitability_metrics=exploit,
                impact_metrics=impact,
                supplemental_context=supplemental,
                supporting_evidence=[str(e) for e in evidence_notes],
            )

            logger.emit(incident_id, "cvss", "metric_calculation", Status.COMPLETED,
                         f"CVSS v4.0 score: {score} ({severity})")
            logger.emit(incident_id, "cvss", "cvss_assessment", Status.COMPLETED,
                         f"CVSS Agent completed — Score: {score} ({severity}), Vector: {vector}")

            return {"cvss_result": result.model_dump()}

        except Exception as exc:
            error_msg = f"CVSS Agent error: {type(exc).__name__}: {exc}"
            logger.emit(incident_id, "cvss", "cvss_assessment", Status.ERROR, error_msg)

            # Return a result with the error so the UI can display it
            error_result = CVSSResult(
                incident_id=incident_id,
                error=error_msg,
            )
            return {"cvss_result": error_result.model_dump()}

    @staticmethod
    def _build_prompt(
        logs: list[Any],
        detection_result: dict[str, Any],
        triage_result: dict[str, Any],
    ) -> str:
        from quallki_agentic.log_filter import summarize_logs_for_llm

        attack_type = detection_result.get("attack_type", "unknown")
        confidence = detection_result.get("confidence", 0.0)
        evidence = detection_result.get("evidence", [])
        confirmed = triage_result.get("confirmed_attack", {})
        filtered_logs = summarize_logs_for_llm(logs, detection_result, max_lines=5)

        return f"""You are a CVSS v4.0 vulnerability scoring expert.

Analyze the following security incident evidence and determine the CVSS v4.0 base metrics.

## Incident Context
- Detected Attack Type: {attack_type}
- Detection Confidence: {confidence}
- Detection Evidence: {evidence}
- Confirmed Attack: {confirmed}

## Suspicious Log Entries
{filtered_logs}

## Task
Determine the following CVSS v4.0 metrics from the evidence:

### Exploitability Metrics
- AV (Attack Vector): N=Network, A=Adjacent, L=Local, P=Physical
- AC (Attack Complexity): L=Low, H=High
- AT (Attack Requirements): N=None, P=Present
- PR (Privileges Required): N=None, L=Low, H=High
- UI (User Interaction): N=None, P=Passive, A=Active

### Impact Metrics (Vulnerable System)
- VC (Confidentiality): H=High, L=Low, N=None
- VI (Integrity): H=High, L=Low, N=None
- VA (Availability): H=High, L=Low, N=None

### Impact Metrics (Subsequent System)
- SC (Confidentiality): H=High, L=Low, N=None
- SI (Integrity): H=High, L=Low, N=None
- SA (Availability): H=High, L=Low, N=None

### Supplemental Context
- automatable: Yes/No (can the attack be automated?)
- recovery: Automatic/User/Irrecoverable

Return strict JSON with keys: AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, automatable, recovery, evidence (list of strings explaining your choices).
"""
