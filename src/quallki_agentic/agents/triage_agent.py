"""Triage Agent — confirms the attack and reconstructs the exact attack path.

Receives two inputs:
1. DetectionResult (structured detection output)
2. Original Raw Logs (for evidence-based analysis)

The Triage Agent uses the raw evidence to determine what exactly happened
and through which technical path the attack occurred.
"""
from __future__ import annotations

from typing import Any

from quallki_agentic.agents.base_agent import BaseAgent
from quallki_agentic.progress import Status, get_progress_logger
from quallki_agentic.result_models import ConfirmedAttack, TriageResult


class TriageAgent(BaseAgent):
    name = "triage"

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        logger = get_progress_logger()
        incident_id = str(payload.get("incident_id", "INC-000"))

        logger.emit(incident_id, "triage", "triage_analysis", Status.RUNNING,
                     "Triage Agent: Starting attack confirmation and path analysis")

        # ── Read inputs ─────────────────────────────────────────────────
        detection_result = payload.get("detection_result", {})
        if not isinstance(detection_result, dict):
            detection_result = {}
        raw_logs = payload.get("logs", [])
        if not isinstance(raw_logs, list):
            raw_logs = []

        attack_type = str(detection_result.get("attack_type", "unknown"))
        confidence = float(detection_result.get("confidence", 0.0))
        evidence = detection_result.get("evidence", [])
        iocs = detection_result.get("iocs", [])
        source = detection_result.get("source", {})
        target = detection_result.get("target", {})
        timestamp_range = detection_result.get("timestamp_range", {})

        # ── Correlate evidence via LLM ──────────────────────────────────
        logger.emit(incident_id, "triage", "evidence_correlation", Status.RUNNING,
                     "Correlating network, application, and system events")

        from quallki_agentic.llm_helper import invoke_llm
        from quallki_agentic.log_filter import summarize_logs_for_llm

        filtered_logs = summarize_logs_for_llm(raw_logs, detection_result, max_lines=6)

        prompt = f"""You are the Triage Agent in a Security Operations Center.

The QML detection model identified a potential attack. Your job is to:
1. CONFIRM the attack type by analyzing the raw logs
2. Determine the EXACT attack mechanism (not just the category)
3. Reconstruct the precise ATTACK PATH step by step
4. Identify all affected assets and the impact

## Detection Result
- Attack Type: {attack_type}
- Confidence: {confidence}
- Source: {source}
- Target: {target}
- Timestamps: {timestamp_range}
- Evidence: {evidence}
- IOCs: {iocs}

## Suspicious Log Entries
{filtered_logs}

## Required Output
Return strict JSON with these keys:
- category: string (confirmed attack category, e.g. "DOS", "RANSOMWARE", "SQL_INJECTION", "CREDENTIAL_THEFT", "RECON")
- mechanism: string (specific mechanism, e.g. "REQUEST_SPAMMING", "BUFFER_OVERFLOW", "BRUTE_FORCE")
- attack_path: list of strings (ordered steps of the attack progression)
- confidence: float (your confidence in the confirmation, 0-1)
- timeline: list of objects with "timestamp" and "event" keys
- affected_assets: list of strings (systems/services affected)
- evidence: list of strings (evidence supporting your conclusions)
- root_cause_indicators: list of strings (indicators of root cause)
- confidentiality_impact: string (NONE/LOW/HIGH)
- integrity_impact: string (NONE/LOW/HIGH)
- availability_impact: string (NONE/LOW/HIGH)
"""

        parsed = invoke_llm(prompt, agent_name="triage")

        if parsed:
            logger.emit(incident_id, "triage", "evidence_correlation", Status.COMPLETED,
                         "Evidence correlation completed")

            logger.emit(incident_id, "triage", "attack_path_reconstruction", Status.RUNNING,
                         "Reconstructing attack path from evidence")

            confirmed = ConfirmedAttack(
                category=str(parsed.get("category", attack_type)),
                mechanism=str(parsed.get("mechanism", "UNKNOWN")),
                attack_path=[str(s) for s in parsed.get("attack_path", [])],
            )

            timeline_raw = parsed.get("timeline", [])
            timeline = []
            if isinstance(timeline_raw, list):
                for item in timeline_raw:
                    if isinstance(item, dict):
                        timeline.append({
                            "timestamp": str(item.get("timestamp", "")),
                            "event": str(item.get("event", "")),
                        })

            affected_assets = [str(a) for a in parsed.get("affected_assets", [])]
            triage_evidence = [str(e) for e in parsed.get("evidence", [])]
            root_cause = [str(r) for r in parsed.get("root_cause_indicators", [])]

            triage_result = TriageResult(
                incident_id=incident_id,
                confirmed_attack=confirmed,
                confidence=float(parsed.get("confidence", confidence)),
                timeline=timeline,
                affected_assets=affected_assets,
                evidence=triage_evidence,
                root_cause_indicators=root_cause,
                impact={
                    "confidentiality": str(parsed.get("confidentiality_impact", "NONE")),
                    "integrity": str(parsed.get("integrity_impact", "NONE")),
                    "availability": str(parsed.get("availability_impact", "NONE")),
                },
            )

            logger.emit(incident_id, "triage", "attack_path_reconstruction", Status.COMPLETED,
                         f"Attack path: {confirmed.category} → {confirmed.mechanism}")

        else:
            # LLM unavailable — create a basic result from detection data
            logger.emit(incident_id, "triage", "evidence_correlation", Status.COMPLETED,
                         "Evidence correlation completed (without LLM enrichment)")

            confirmed = ConfirmedAttack(
                category=attack_type,
                mechanism="UNDETERMINED",
                attack_path=[f"Detected {attack_type} activity"],
            )

            triage_result = TriageResult(
                incident_id=incident_id,
                confirmed_attack=confirmed,
                confidence=confidence,
                timeline=[],
                affected_assets=[str(source.get("entity", "unknown"))],
                evidence=[str(e) for e in evidence],
                root_cause_indicators=[],
                impact={
                    "confidentiality": "NONE",
                    "integrity": "NONE",
                    "availability": "NONE",
                },
            )

        logger.emit(incident_id, "triage", "triage_analysis", Status.COMPLETED,
                     f"Triage completed — {triage_result.confirmed_attack.category} "
                     f"via {triage_result.confirmed_attack.mechanism}")

        return {"triage_result": triage_result.model_dump()}
