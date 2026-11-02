"""Orchestrator nodes for the revised QUAL-KI Agentic SOC pipeline.

Pipeline: Preprocessing → QML Inference → Detection → Triage → Response →
Compliance → Finalize

CVSS Agent runs independently in a background thread, launched after Detection.
"""
from __future__ import annotations

import threading
import uuid
from typing import Any

from quallki_agentic.agents import (
    ComplianceAgent,
    CVSSAgent,
    DetectionAgent,
    ResponseAgent,
    TriageAgent,
)
from quallki_agentic.config import Settings
from quallki_agentic.messaging import build_message_bus
from quallki_agentic.orchestrator.schema import now_iso
from quallki_agentic.orchestrator.state import OrchestratorState
from quallki_agentic.progress import Status, get_progress_logger
from quallki_agentic.qml_stub import infer_with_metadata

# ── Agent singletons ────────────────────────────────────────────────────
detection_agent = DetectionAgent()
triage_agent = TriageAgent()
response_agent = ResponseAgent()
compliance_agent = ComplianceAgent()
cvss_agent = CVSSAgent()

settings = Settings.from_env()
message_bus = build_message_bus(settings)

# ── Background CVSS result storage ─────────────────────────────────────
_cvss_result_lock = threading.Lock()
_cvss_result_store: dict[str, dict[str, Any]] = {}


def _publish(topic: str, event: dict[str, object]) -> None:
    if not settings.enable_event_bus:
        return
    try:
        message_bus.publish(topic, event)
    except Exception:
        return


def _run_cvss_background(payload: dict[str, Any], incident_id: str) -> None:
    """Run the CVSS agent in a background thread."""
    try:
        result = cvss_agent.run(payload)
        with _cvss_result_lock:
            _cvss_result_store[incident_id] = result.get("cvss_result", {})
    except Exception as exc:
        logger = get_progress_logger()
        logger.emit(incident_id, "cvss", "cvss_assessment", Status.ERROR,
                     f"CVSS background thread error: {exc}")
        with _cvss_result_lock:
            _cvss_result_store[incident_id] = {
                "incident_id": incident_id,
                "error": str(exc),
                "cvss_score": 0.0,
                "cvss_vector": "",
                "severity_label": "NONE",
            }


# =========================================================================
# Pipeline Nodes
# =========================================================================

def preprocessing_node(state: OrchestratorState) -> OrchestratorState:
    """Step 1 — Log ingestion and preprocessing.

    Parses raw logs, extracts basic fields, and prepares features for QML.
    """
    logger = get_progress_logger()
    incident_id = state.get("incident_id", f"INC-{uuid.uuid4().hex[:6].upper()}")

    logger.emit(incident_id, "preprocessing", "log_ingestion", Status.RUNNING,
                 "Receiving and preprocessing raw security logs")

    logs = state.get("logs", [])
    message = state.get("message", "")
    source_ip = state.get("source_ip", "0.0.0.0")

    # If we have raw logs but no message, try to extract context via LLM
    if source_ip == "0.0.0.0" and not message and logs:
        logger.emit(incident_id, "preprocessing", "log_parsing", Status.RUNNING,
                     "Parsing raw logs to extract key fields via LLM")

        from quallki_agentic.llm_helper import invoke_llm
        prompt = (
            "You are a SOC parser. Extract the following from the raw logs provided below. "
            "Return strict JSON with keys: message, source_ip, asset_type, clinical_impact, contains_phi (boolean). "
            "Guess impact (low/medium/high/critical) and asset_type (e.g. ehr_server, pacs, endpoint) from context.\n\n"
            f"Logs: {logs}"
        )
        parsed = invoke_llm(prompt, agent_name="preprocessing")
        if parsed:
            logger.emit(incident_id, "preprocessing", "log_parsing", Status.COMPLETED,
                         "Log fields extracted via LLM")
            return {
                "incident_id": incident_id,
                "message": str(parsed.get("message", message)),
                "source_ip": str(parsed.get("source_ip", source_ip)),
                "asset_type": str(parsed.get("asset_type", state.get("asset_type", "unknown"))),
                "clinical_impact": str(parsed.get("clinical_impact", state.get("clinical_impact", "medium"))),
                "contains_phi": bool(parsed.get("contains_phi", state.get("contains_phi", False))),
                "preprocessed_features": {"status": "parsed_from_logs"},
            }

        logger.emit(incident_id, "preprocessing", "log_parsing", Status.COMPLETED,
                     "Log parsing completed (no LLM enrichment needed)")

    logger.emit(incident_id, "preprocessing", "log_ingestion", Status.COMPLETED,
                 f"Preprocessing completed — {len(logs)} log entries processed")

    return {
        "incident_id": incident_id,
        "preprocessed_features": {"status": "ready", "log_count": len(logs)},
    }


def qml_inference_node(state: OrchestratorState) -> OrchestratorState:
    """Step 2 — QML Model inference.

    Runs the Quantum Machine Learning model on the preprocessed features
    to produce anomaly/threat detection signals.
    """
    logger = get_progress_logger()
    incident_id = state.get("incident_id", "INC-000")

    logger.emit(incident_id, "qml", "model_inference", Status.RUNNING,
                 "QML Model: Running anomaly/threat detection inference")

    try:
        qml_result = infer_with_metadata(state)

        qml_label = str(qml_result.get("label", "unknown"))
        qml_backend = str(qml_result.get("backend", "unknown"))
        classical_label = str(qml_result.get("classical_label", "unknown"))

        logger.emit(incident_id, "qml", "model_inference", Status.COMPLETED,
                     f"QML inference completed — prediction: {qml_label} "
                     f"(backend: {qml_backend})")

        return {
            "qml_result": {
                "label": qml_label,
                "backend": qml_backend,
                "classical_label": classical_label,
                "model_version": "qml-v1",
                "confidence": 0.0,  # Will be enriched by detection agent
                "anomaly_score": 0.0,
            },
        }

    except Exception as exc:
        error_msg = f"QML inference error: {type(exc).__name__}: {exc}"
        logger.emit(incident_id, "qml", "model_inference", Status.ERROR, error_msg)
        # Surface the error — no fallback
        raise RuntimeError(error_msg) from exc


def detection_node(state: OrchestratorState) -> OrchestratorState:
    """Step 3 — Detection Agent.

    Interprets QML output and creates a structured DetectionResult.
    Also launches the CVSS Agent in a background thread.
    """
    logger = get_progress_logger()
    incident_id = state.get("incident_id", "INC-000")

    logger.emit(incident_id, "detection", "detection_start", Status.RUNNING,
                 "Detection Agent: Starting")

    result = detection_agent.run(state)
    incident_id = result.get("incident_id", incident_id)

    _publish("agent.detection.completed", {
        "incident_id": incident_id,
        "attack_type": result.get("detection_result", {}).get("attack_type"),
    })

    # ── Launch CVSS Agent in background ─────────────────────────────────
    logger.emit(incident_id, "cvss", "cvss_assessment", Status.PENDING,
                 "CVSS Agent: Queued for background execution")

    cvss_payload = {
        **state,
        "incident_id": incident_id,
        "detection_result": result.get("detection_result", {}),
    }
    cvss_thread = threading.Thread(
        target=_run_cvss_background,
        args=(cvss_payload, incident_id),
        daemon=True,
        name=f"cvss-{incident_id}",
    )
    cvss_thread.start()

    return result


def triage_node(state: OrchestratorState) -> OrchestratorState:
    """Step 4 — Triage Agent.

    Receives DetectionResult + Original Raw Logs.
    Confirms the attack and reconstructs the exact attack path.
    """
    logger = get_progress_logger()
    incident_id = state.get("incident_id", "INC-000")

    logger.emit(incident_id, "triage", "triage_start", Status.RUNNING,
                 "Triage Agent: Starting attack confirmation")

    result = triage_agent.run(state)

    _publish("agent.triage.completed", {
        "incident_id": incident_id,
        "triage": result.get("triage_result", {}),
    })

    return result


def response_node(state: OrchestratorState) -> OrchestratorState:
    """Step 5 — Response Agent.

    Receives TriageResult and determines operational response actions.
    """
    logger = get_progress_logger()
    incident_id = state.get("incident_id", "INC-000")

    logger.emit(incident_id, "response", "response_start", Status.RUNNING,
                 "Response Agent: Starting")

    result = response_agent.run(state)

    _publish("agent.response.completed", {
        "incident_id": incident_id,
        "actions": result.get("response_result", {}).get("response_actions", []),
    })

    return result


def compliance_node(state: OrchestratorState) -> OrchestratorState:
    """Step 6 — Compliance Agent.

    Healthcare-specific compliance and data compromise assessment.
    """
    logger = get_progress_logger()
    incident_id = state.get("incident_id", "INC-000")

    logger.emit(incident_id, "compliance", "compliance_start", Status.RUNNING,
                 "Compliance Agent: Starting healthcare compliance assessment")

    result = compliance_agent.run(state)

    _publish("agent.compliance.completed", {
        "incident_id": incident_id,
    })

    return result


def finalize_node(state: OrchestratorState) -> OrchestratorState:
    """Step 7 — Finalize.

    Waits for CVSS result (with timeout) and combines all results into
    the final incident report.
    """
    logger = get_progress_logger()
    incident_id = state.get("incident_id", "INC-000")

    logger.emit(incident_id, "finalize", "finalize", Status.RUNNING,
                 "Assembling final incident report")

    # ── Wait for CVSS result (with timeout) ─────────────────────────────
    logger.emit(incident_id, "finalize", "cvss_wait", Status.RUNNING,
                 "Waiting for CVSS Agent background result...")

    import time
    max_wait = 60  # seconds
    waited = 0.0
    cvss_result = None
    while waited < max_wait:
        with _cvss_result_lock:
            if incident_id in _cvss_result_store:
                cvss_result = _cvss_result_store.pop(incident_id)
                break
        time.sleep(0.5)
        waited += 0.5

    if cvss_result is None:
        logger.emit(incident_id, "finalize", "cvss_wait", Status.ERROR,
                     f"CVSS Agent timed out after {max_wait}s")
        cvss_result = {
            "incident_id": incident_id,
            "error": f"CVSS calculation timed out after {max_wait}s",
            "cvss_score": 0.0,
            "cvss_vector": "",
            "severity_label": "NONE",
        }
    else:
        cvss_error = cvss_result.get("error")
        if cvss_error:
            logger.emit(incident_id, "finalize", "cvss_wait", Status.ERROR,
                         f"CVSS Agent reported error: {cvss_error}")
        else:
            logger.emit(incident_id, "finalize", "cvss_wait", Status.COMPLETED,
                         f"CVSS result received — Score: {cvss_result.get('cvss_score', 0)}")

    # ── Build final report ──────────────────────────────────────────────
    detection_result = state.get("detection_result", {})
    triage_result = state.get("triage_result", {})
    response_result = state.get("response_result", {})
    compliance_result = state.get("compliance_result", {})

    # Gather progress events
    progress_events = logger.get_events()

    final_report = {
        "incident_id": incident_id,
        "detection": detection_result,
        "triage": triage_result,
        "response": response_result,
        "compliance": compliance_result,
        "cvss": cvss_result,
        "progress_events": progress_events,
        "generated_at": now_iso(),
    }

    # Build human-readable summary
    attack_type = detection_result.get("attack_type", "unknown") if isinstance(detection_result, dict) else "unknown"
    confidence = detection_result.get("confidence", 0.0) if isinstance(detection_result, dict) else 0.0
    confirmed = triage_result.get("confirmed_attack", {}) if isinstance(triage_result, dict) else {}
    mechanism = confirmed.get("mechanism", "unknown") if isinstance(confirmed, dict) else "unknown"
    response_actions = response_result.get("response_actions", []) if isinstance(response_result, dict) else []
    cvss_score = cvss_result.get("cvss_score", 0.0) if isinstance(cvss_result, dict) else 0.0
    cvss_severity = cvss_result.get("severity_label", "NONE") if isinstance(cvss_result, dict) else "NONE"

    summary = (
        f"Incident {incident_id}: "
        f"Detected {attack_type} (confidence {confidence:.2f}). "
        f"Confirmed via triage as {confirmed.get('category', attack_type)} "
        f"via {mechanism}. "
        f"{len(response_actions)} response actions recommended. "
        f"CVSS v4.0: {cvss_score} ({cvss_severity})."
    )

    logger.emit(incident_id, "finalize", "finalize", Status.COMPLETED,
                 "Final incident report assembled")

    _publish("agent.orchestrator.finalized", {"incident_id": incident_id})

    return {
        "final_report": final_report,
        "cvss_result": cvss_result,
        "progress_events": progress_events,
        "final_summary": summary,
    }
