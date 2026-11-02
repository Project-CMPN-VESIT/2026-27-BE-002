"""Core package for Quallki agentic SOC workflow."""

from quallki_agentic.orchestrator.graph import build_orchestrator_graph

# Backward compatibility alias
build_graph = build_orchestrator_graph

__all__ = ["build_orchestrator_graph", "build_graph"]
