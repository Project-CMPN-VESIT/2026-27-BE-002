from __future__ import annotations

from typing import Any

from quallki_agentic.healthcare import HOSPITAL_DEMO_CASES
from quallki_agentic.healthcare.attack_simulator import AttackSimulator
from quallki_agentic.orchestrator import build_orchestrator_graph
from quallki_agentic.progress import get_progress_logger, reset_progress_logger


def run_alert_payload(payload: dict[str, Any], scenario: dict[str, Any] | None = None) -> dict[str, object]:
    """Run an arbitrary normalized alert through the compiled LangGraph."""
    if not isinstance(payload, dict):
        raise TypeError("Alert payload must be a JSON object")

    # Reset the progress logger for each run
    logger = reset_progress_logger()

    scenario = scenario or {
        "title": "Live alert",
        "message": payload.get("message", ""),
        "asset_type": payload.get("asset_type", "unknown"),
        "contains_phi": payload.get("contains_phi", False),
        "clinical_impact": payload.get("clinical_impact", "medium"),
        "source_ip": payload.get("source_ip", "unknown"),
    }

    workflow_trace: list[dict[str, object]] = []
    result: dict[str, object] = {}
    for update in build_orchestrator_graph().stream(payload, stream_mode="updates"):
        if not isinstance(update, dict):
            continue
        for node_name, node_output in update.items():
            output = node_output if isinstance(node_output, dict) else {"value": node_output}
            workflow_trace.append({"node": node_name, "output": output})
            result.update(output)

    # ── Gather results ──────────────────────────────────────────────────
    detection_result = result.get("detection_result", {})
    incident_id = result.get("incident_id", "unknown")
    qml_result = result.get("qml_result", {})

    label = str(detection_result.get("attack_type", "unknown")) if isinstance(detection_result, dict) else "unknown"
    confidence = float(detection_result.get("confidence", 0.0)) if isinstance(detection_result, dict) else 0.0
    qml_backend = str(qml_result.get("backend", "unknown")) if isinstance(qml_result, dict) else "unknown"

    # Collect progress events
    progress_events = logger.get_events()

    return {
        "scenario_key": str(payload.get("scenario", "live_alert")),
        "scenario": scenario,
        "incident_id": incident_id,
        "label": label,
        "confidence": confidence,
        "qml_backend": qml_backend,
        "result": result,
        "payload": payload,
        "logs": payload.get("logs", []),
        "workflow_trace": workflow_trace,
        "progress_events": progress_events,
    }


def run_healthcare_demo_scenario(scenario_key: str) -> dict[str, object]:
    if scenario_key not in HOSPITAL_DEMO_CASES:
        raise ValueError(f"Unknown scenario: {scenario_key}")
    payload = AttackSimulator().simulate(scenario_key)
    return run_alert_payload(payload, HOSPITAL_DEMO_CASES[scenario_key])
