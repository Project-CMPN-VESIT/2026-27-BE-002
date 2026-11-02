"""Thread-safe progress logging for the QUAL-KI Agentic SOC pipeline.

Every major operation emits a structured ``ProgressEvent``.  The Streamlit UI
reads these events to render live execution status with
PENDING / RUNNING / COMPLETED / ERROR states.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Status(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


@dataclass
class ProgressEvent:
    """A single structured progress event."""
    timestamp: str
    incident_id: str
    agent: str
    stage: str
    status: Status
    message: str
    duration_ms: float | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "incident_id": self.incident_id,
            "agent": self.agent,
            "stage": self.stage,
            "status": self.status.value,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "detail": self.detail,
        }


@dataclass
class ProgressLogger:
    """Thread-safe progress event collector.

    Agents call ``emit()`` to record progress.  The Streamlit UI reads
    ``get_events()`` / ``get_pipeline_status()`` to render the live panel.
    """
    _events: list[ProgressEvent] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _start_times: dict[str, float] = field(default_factory=dict)

    # -- emitting --------------------------------------------------------

    def emit(
        self,
        incident_id: str,
        agent: str,
        stage: str,
        status: Status,
        message: str,
        detail: str | None = None,
    ) -> None:
        """Record a progress event."""
        key = f"{agent}.{stage}"
        duration_ms = None

        if status == Status.RUNNING:
            self._start_times[key] = time.monotonic()
        elif status in (Status.COMPLETED, Status.ERROR):
            start = self._start_times.pop(key, None)
            if start is not None:
                duration_ms = round((time.monotonic() - start) * 1000, 1)

        event = ProgressEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            incident_id=incident_id,
            agent=agent,
            stage=stage,
            status=status,
            message=message,
            duration_ms=duration_ms,
            detail=detail,
        )
        with self._lock:
            self._events.append(event)

    # -- reading ---------------------------------------------------------

    def get_events(self) -> list[dict[str, Any]]:
        """Return all events as dicts (safe for JSON / Streamlit)."""
        with self._lock:
            return [e.to_dict() for e in self._events]

    def get_pipeline_status(self) -> dict[str, dict[str, Any]]:
        """Return the latest status for each agent stage.

        Returns a dict keyed by agent name → {status, message, duration_ms, stage}.
        """
        result: dict[str, dict[str, Any]] = {}
        with self._lock:
            for event in self._events:
                result[event.agent] = {
                    "status": event.status.value,
                    "message": event.message,
                    "stage": event.stage,
                    "duration_ms": event.duration_ms,
                    "timestamp": event.timestamp,
                }
        return result

    def get_agent_substeps(self, agent: str) -> list[dict[str, Any]]:
        """Return all events for a specific agent (sub-step detail)."""
        with self._lock:
            return [
                e.to_dict()
                for e in self._events
                if e.agent == agent
            ]

    def clear(self) -> None:
        """Reset for a new run."""
        with self._lock:
            self._events.clear()
            self._start_times.clear()


# ---------------------------------------------------------------------------
# Global singleton — accessible from all agents and the UI
# ---------------------------------------------------------------------------

_global_logger: ProgressLogger | None = None
_logger_lock = threading.Lock()


def get_progress_logger() -> ProgressLogger:
    """Return the global progress logger singleton."""
    global _global_logger
    with _logger_lock:
        if _global_logger is None:
            _global_logger = ProgressLogger()
        return _global_logger


def reset_progress_logger() -> ProgressLogger:
    """Reset and return a fresh global progress logger."""
    global _global_logger
    with _logger_lock:
        _global_logger = ProgressLogger()
        return _global_logger
