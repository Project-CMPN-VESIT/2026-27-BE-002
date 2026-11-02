from __future__ import annotations

from datetime import datetime, timedelta, timezone


def make_time_window(seconds: int = 1) -> dict[str, str]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(seconds=seconds)
    return {"start": start.isoformat(), "end": end.isoformat(), "size_seconds": str(seconds)}
