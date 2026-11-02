from __future__ import annotations

from typing import Any

from quallki_agentic.config import Settings
from quallki_agentic.qml_model import QMLVQCClassifier, canonical_label


_classifier: QMLVQCClassifier | None = None
_classical: Any = None


def infer_with_metadata(payload: dict[str, Any]) -> dict[str, str]:
    global _classifier, _classical
    has_model_input = any(
        key in payload for key in ("feature_vector", "features", "qml_input", "logs")
    )
    qml_label = payload.get("qml_label")
    if qml_label and not has_model_input:
        return {"label": str(qml_label), "backend": "explicit_label"}
    
    if _classifier is None:
        settings = Settings.from_env()
        _classifier = QMLVQCClassifier(
            settings.qml_model_path,
            settings.qml_autoencoder_path,
            settings.qml_preprocessing_path,
        )
    
    if _classical is None:
        try:
            from quallki_agentic.classical_model import ClassicalClassifier
            _classical = ClassicalClassifier("best_regularized_model.joblib")
        except Exception:
            _classical = None
            
    result = {}
    heuristic = _heuristic_label(payload)
    
    if _classifier and _classifier.available:
        raw_label, qml_confidence = _classifier.predict_with_confidence(payload)
        qml_label_canonical = canonical_label(raw_label)

        # Cross-check: if QML confidence is low and heuristic has a strong
        # signal from the actual log content, prefer the heuristic. This
        # handles cases where the VQC was trained on network-flow features
        # but receives log-derived features that produce unreliable predictions.
        if qml_confidence < 0.50 and heuristic != "unknown" and heuristic != qml_label_canonical:
            result["label"] = heuristic
            result["backend"] = "qml_vqc+heuristic_override"
            result["qml_raw_label"] = qml_label_canonical
            result["qml_confidence"] = f"{qml_confidence:.4f}"
            result["override_reason"] = (
                f"QML confidence {qml_confidence:.2%} below threshold; "
                f"heuristic detected '{heuristic}' from log content"
            )
        else:
            result["label"] = qml_label_canonical
            result["backend"] = "qml_vqc"
            result["qml_confidence"] = f"{qml_confidence:.4f}"
    else:
        result["label"] = heuristic
        result["backend"] = "heuristic_stub"
        
    if _classical and _classical.available:
        result["classical_label"] = canonical_label(_classical.predict_label(payload))
    else:
        result["classical_label"] = "unknown"
        
    return result


def _heuristic_label(payload: dict[str, Any]) -> str:
    message = str(payload.get("message", "")).lower()
    logs = payload.get("logs", [])
    log_text = " ".join(str(l) for l in logs).lower() if isinstance(logs, list) else ""
    combined = f"{message} {log_text}"
    if "ransom" in combined or "encrypt" in combined:
        return "ransomware"
    if any(tok in combined for tok in ("dos", "flood", "ddos", "rate_limit", "rate-limit",
                                        "oom", "out of memory", "503", "service unavailable",
                                        "req/s", "connection pool", "all_busy", "memory exhaustion",
                                        "memory pressure", "oom-kill", "http_flood")):
        return "dos"
    if "sql" in combined or "select " in combined:
        return "sql-injection"
    if "credential" in combined or "login failed" in combined or "failed login" in combined:
        return "credential-theft"
    if "malware" in combined or "trojan" in combined or "backdoor" in combined:
        return "malware"
    if "scan" in combined or "recon" in combined or "probe" in combined or "enumerat" in combined:
        return "recon"
    if "exfil" in combined or "data transfer" in combined:
        return "exfiltration"
    return "unknown"


def infer(payload: dict[str, Any]) -> dict[str, str]:
    """Return only a QML attack category label for the current demo stub."""
    return {"label": infer_with_metadata(payload)["label"]}