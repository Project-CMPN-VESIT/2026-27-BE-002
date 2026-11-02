"""Filter raw logs to extract only security-relevant lines before sending to LLMs.

This drastically reduces prompt size and LLM latency by sending only the
suspicious / high-signal log lines instead of the full log corpus.
"""
from __future__ import annotations

import re
from typing import Any

# Keywords that mark a log line as security-relevant
_SEVERITY_KEYWORDS = frozenset({
    "critical", "alert", "error", "warn", "warning", "fail", "failed",
    "denied", "blocked", "rejected", "unauthorized", "forbidden",
})

_ATTACK_KEYWORDS = frozenset({
    "flood", "ddos", "dos", "oom", "out of memory", "oom-kill",
    "rate_limit", "rate-limit", "brute", "exploit", "inject",
    "ransom", "encrypt", "malware", "trojan", "backdoor",
    "exfil", "lateral", "privilege", "escalat", "scan", "recon",
    "credential", "phishing", "c2", "command and control",
    "503", "timeout", "timed out", "connection refused",
    "killed", "crash", "segfault", "memory pressure",
    "suspicious", "anomal", "abuse", "violation",
})

_SYSTEM_KEYWORDS = frozenset({
    "ids", "ips", "suricata", "snort", "siem", "firewall",
    "waf", "rate_limit", "health_check", "monitoring",
    "prometheus", "zabbix", "nagios", "splunk",
})

# Regex for IPs, ports, high numeric values (request rates, etc.)
_IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_HIGH_RATE_PATTERN = re.compile(r"\b(\d{3,})\s*req/s\b", re.IGNORECASE)


def filter_suspicious_logs(
    logs: list[str],
    detection_result: dict[str, Any] | None = None,
    max_lines: int = 15,
) -> list[str]:
    """Return only the security-relevant log lines.

    Scoring:
      - Severity keywords (CRITICAL, ERROR, etc.)  → +3
      - Attack-related keywords                     → +2
      - Security system keywords (IDS, firewall)    → +2
      - IOC matches from DetectionResult            → +3
      - High request rates                          → +1
      - Baseline (all other lines)                  → 0

    Lines with score > 0 are kept, sorted by score descending,
    capped at ``max_lines``.
    """
    if not isinstance(logs, list) or not logs:
        return []

    # Extract IOCs from detection result for matching
    iocs: set[str] = set()
    if isinstance(detection_result, dict):
        for ioc in detection_result.get("iocs", []):
            iocs.add(str(ioc).lower())
        src = detection_result.get("source", "")
        if src:
            iocs.add(str(src).lower())
        tgt = detection_result.get("target", "")
        if tgt:
            iocs.add(str(tgt).lower())

    scored: list[tuple[int, int, str]] = []  # (score, original_index, line)

    for idx, raw_line in enumerate(logs):
        line = str(raw_line)
        lower = line.lower()
        score = 0

        # Severity keywords
        for kw in _SEVERITY_KEYWORDS:
            if kw in lower:
                score += 3
                break

        # Attack keywords
        for kw in _ATTACK_KEYWORDS:
            if kw in lower:
                score += 2
                break

        # Security system keywords
        for kw in _SYSTEM_KEYWORDS:
            if kw in lower:
                score += 2
                break

        # IOC matches
        if iocs:
            for ioc in iocs:
                if ioc in lower:
                    score += 3
                    break

        # High request rates
        if _HIGH_RATE_PATTERN.search(lower):
            score += 1

        if score > 0:
            scored.append((score, idx, line))

    # Sort by score descending, then by original order
    scored.sort(key=lambda x: (-x[0], x[1]))

    # Cap at max_lines
    result = [line for _, _, line in scored[:max_lines]]
    return result


def summarize_logs_for_llm(
    logs: list[str],
    detection_result: dict[str, Any] | None = None,
    max_lines: int = 15,
) -> str:
    """Return a compact string of filtered logs ready for LLM prompts."""
    filtered = filter_suspicious_logs(logs, detection_result, max_lines)
    if not filtered:
        return "(no suspicious log entries found)"

    total = len(logs) if isinstance(logs, list) else 0
    header = f"[{len(filtered)} of {total} log lines selected by relevance]"
    return header + "\n" + "\n".join(filtered)
