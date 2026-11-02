"""Detection Agent — interprets QML model output into a structured DetectionResult.

The Detection Agent does NOT run QML inference.  It receives the QML output
from the previous pipeline stage and converts it into a structured incident
representation (DetectionResult).
"""
from __future__ import annotations

import uuid
from typing import Any

from quallki_agentic.agents.base_agent import BaseAgent
from quallki_agentic.log_analyzer import analyze
from quallki_agentic.orchestrator.schema import now_iso
from quallki_agentic.progress import Status, get_progress_logger
from quallki_agentic.result_models import DetectionResult
from quallki_agentic.scoring import aggregate_confidence, score_cwss


class DetectionAgent(BaseAgent):
    name = "detection"

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        logger = get_progress_logger()
        incident_id = str(payload.get("incident_id", f"INC-{uuid.uuid4().hex[:6].upper()}"))

        logger.emit(incident_id, "detection", "interpret_qml", Status.RUNNING,
                     "Detection Agent: Interpreting QML model output")

        # ── Read QML output from the previous pipeline stage ────────────
        qml_result = payload.get("qml_result", {})
        if not isinstance(qml_result, dict):
            qml_result = {}

        qml_label = str(qml_result.get("label", "unknown"))
        qml_confidence = float(qml_result.get("confidence", 0.0))
        qml_anomaly_score = float(qml_result.get("anomaly_score", 0.0))
        qml_backend = str(qml_result.get("backend", "unknown"))
        qml_model_version = str(qml_result.get("model_version", "qml-v1"))

        logger.emit(incident_id, "detection", "interpret_qml", Status.COMPLETED,
                     f"QML prediction: {qml_label} (confidence: {qml_confidence:.2f})")

        # ── Extract context from payload ────────────────────────────────
        message = str(payload.get("message", ""))
        source_ip = str(payload.get("source_ip", "0.0.0.0"))
        event_time = str(payload.get("event_time", now_iso()))
        asset_type = str(payload.get("asset_type", "unknown"))
        contains_phi = bool(payload.get("contains_phi", False))
        clinical_impact = str(payload.get("clinical_impact", "medium"))
        logs = payload.get("logs", [])

        # ── Analyze logs for evidence, IOCs, attack vector ──────────────
        logger.emit(incident_id, "detection", "log_analysis", Status.RUNNING,
                     "Analyzing logs for evidence and indicators of compromise")

        analysis = analyze(payload, qml_label)
        iocs = analysis["iocs"]

        logger.emit(incident_id, "detection", "log_analysis", Status.COMPLETED,
                     f"Found {len(iocs)} IOC(s), attack vector: {analysis.get('attack_vector', 'unknown')}")

        # ── Score severity ──────────────────────────────────────────────
        logger.emit(incident_id, "detection", "severity_scoring", Status.RUNNING,
                     "Computing severity score")

        cwss = score_cwss(qml_label, analysis, clinical_impact)
        composite_confidence = aggregate_confidence(
            qml_label, analysis, cwss, payload.get("telemetry_signals")
        )

        # Use composite_confidence if QML didn't provide one
        if qml_confidence == 0.0:
            qml_confidence = composite_confidence

        logger.emit(incident_id, "detection", "severity_scoring", Status.COMPLETED,
                     f"Severity score: {cwss.get('score', 0.0)}, confidence: {composite_confidence:.2f}")

        # ── Determine initial severity ──────────────────────────────────
        cwss_score = float(cwss.get("score", 0.0))
        if cwss_score >= 8.0:
            initial_severity = "critical"
        elif cwss_score >= 6.0:
            initial_severity = "high"
        elif cwss_score >= 4.0:
            initial_severity = "medium"
        else:
            initial_severity = "low"

        # ── Extract timestamps from logs ────────────────────────────────
        timestamp_range = {"start": event_time, "end": event_time}
        if isinstance(logs, list) and logs:
            first_ts = str(logs[0]).split(" ", 1)[0] if logs[0] else event_time
            last_ts = str(logs[-1]).split(" ", 1)[0] if logs[-1] else event_time
            timestamp_range = {"start": first_ts, "end": last_ts}

        # ── Build DetectionResult ───────────────────────────────────────
        logger.emit(incident_id, "detection", "build_result", Status.RUNNING,
                     "Building structured DetectionResult")

        detection_result = DetectionResult(
            incident_id=incident_id,
            attack_type=qml_label,
            confidence=qml_confidence,
            anomaly_score=qml_anomaly_score,
            timestamp_range=timestamp_range,
            source={"ip": source_ip, "entity": asset_type},
            target={"ip": "target", "service": analysis.get("attack_vector", "unknown")},
            suspicious_events=[str(e) for e in analysis.get("evidence", [])],
            evidence=[str(e) for e in analysis.get("evidence", [])],
            qml={
                "model": qml_model_version,
                "prediction": qml_label,
                "backend": qml_backend,
                "confidence": qml_confidence,
                "anomaly_score": qml_anomaly_score,
            },
            initial_severity=initial_severity,
            iocs=iocs,
        )

        logger.emit(incident_id, "detection", "build_result", Status.COMPLETED,
                     f"DetectionResult created: {qml_label} ({initial_severity})")

        logger.emit(incident_id, "detection", "detection_complete", Status.COMPLETED,
                     f"Detection Agent completed — {qml_label} with {initial_severity} severity")

        return {
            "incident_id": incident_id,
            "detection_result": detection_result.model_dump(),
            "iocs": iocs,
        }
