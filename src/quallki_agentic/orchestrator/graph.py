"""Orchestrator graph — revised linear pipeline.

Preprocessing → QML → Detection → Triage → Response → Compliance → Finalize

No conditional routing, no auto-close, no branching.
CVSS Agent runs independently in a background thread (launched from detection_node).
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from quallki_agentic.orchestrator.nodes import (
    compliance_node,
    detection_node,
    finalize_node,
    preprocessing_node,
    qml_inference_node,
    response_node,
    triage_node,
)
from quallki_agentic.orchestrator.state import OrchestratorState


def build_orchestrator_graph():
    workflow = StateGraph(OrchestratorState)

    # ── Register nodes ──────────────────────────────────────────────────
    workflow.add_node("preprocessing", preprocessing_node)
    workflow.add_node("qml_inference", qml_inference_node)
    workflow.add_node("detection", detection_node)
    workflow.add_node("triage", triage_node)
    workflow.add_node("response", response_node)
    workflow.add_node("compliance", compliance_node)
    workflow.add_node("finalize", finalize_node)

    # ── Linear sequential edges ─────────────────────────────────────────
    workflow.add_edge(START, "preprocessing")
    workflow.add_edge("preprocessing", "qml_inference")
    workflow.add_edge("qml_inference", "detection")
    workflow.add_edge("detection", "triage")
    workflow.add_edge("triage", "response")
    workflow.add_edge("response", "compliance")
    workflow.add_edge("compliance", "finalize")
    workflow.add_edge("finalize", END)

    return workflow.compile()
