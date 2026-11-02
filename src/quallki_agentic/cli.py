from __future__ import annotations

import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

from quallki_agentic.healthcare import HOSPITAL_DEMO_CASES
from quallki_agentic.healthcare.demo_runner import run_alert_payload, run_healthcare_demo_scenario


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="QUAL-KI Agentic SOC runner")
    parser.add_argument(
        "--scenario",
        choices=sorted(HOSPITAL_DEMO_CASES.keys()),
        help="Run a built-in synthetic healthcare scenario",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Run a real normalized alert from a JSON file or JSONL file",
    )
    return parser.parse_args()


def _load_input(path: Path) -> list[dict[str, object]]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError("Input file is empty")
    try:
        parsed = json.loads(text)
        records = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not all(isinstance(record, dict) for record in records):
        raise ValueError("Each input record must be a JSON object")
    return records


def main() -> None:
    args = parse_args()
    load_dotenv()
    if bool(args.scenario) == bool(args.input):
        raise SystemExit("Choose exactly one of --scenario or --input")
    run_data_list = (
        [run_healthcare_demo_scenario(args.scenario)]
        if args.scenario
        else [run_alert_payload(record) for record in _load_input(args.input)]
    )
    for run_data in run_data_list:
        _print_run(run_data)


def _print_run(run_data: dict[str, object]) -> None:
    scenario = run_data["scenario"]
    result = run_data["result"]

    print("\n" + "=" * 60)
    print(f"  QUAL-KI Agentic SOC — Incident Report")
    print("=" * 60)
    print(f"Scenario: {run_data['scenario_key']} — {scenario['title']}")
    print(f"Incident ID: {run_data.get('incident_id', 'N/A')}")

    # ── Pipeline Execution Log ──────────────────────────────────────────
    progress_events = run_data.get("progress_events", [])
    if progress_events:
        print("\n--- Pipeline Execution Log ---")
        STATUS_ICON = {"PENDING": "○", "RUNNING": "⟳", "COMPLETED": "✓", "ERROR": "✗"}
        for event in progress_events:
            icon = STATUS_ICON.get(event.get("status", ""), "·")
            agent = event.get("agent", "")
            msg = event.get("message", "")
            dur = event.get("duration_ms")
            dur_str = f" ({dur:.0f}ms)" if dur else ""
            print(f"  {icon} [{agent}] {msg}{dur_str}")

    # ── Workflow trace ──────────────────────────────────────────────────
    trace = run_data.get("workflow_trace", [])
    if isinstance(trace, list):
        nodes = [str(item.get("node")) for item in trace if isinstance(item, dict)]
        print(f"\nLangGraph nodes: {' → '.join(nodes)}")

    # ── Detection ───────────────────────────────────────────────────────
    detection = result.get("detection_result", {})
    if isinstance(detection, dict) and detection:
        print(f"\n--- Detection ---")
        print(f"Attack Type: {detection.get('attack_type', 'unknown')}")
        print(f"Confidence: {float(detection.get('confidence', 0)):.2f}")
        print(f"Severity: {detection.get('initial_severity', 'unknown')}")
        print(f"QML Backend: {detection.get('qml', {}).get('backend', 'unknown')}")
        print(f"IOCs: {', '.join(detection.get('iocs', [])) or 'none'}")

    # ── Triage ──────────────────────────────────────────────────────────
    triage = result.get("triage_result", {})
    if isinstance(triage, dict) and triage:
        confirmed = triage.get("confirmed_attack", {})
        print(f"\n--- Triage ---")
        print(f"Confirmed: {confirmed.get('category', 'unknown')}")
        print(f"Mechanism: {confirmed.get('mechanism', 'unknown')}")
        path = confirmed.get("attack_path", [])
        if path:
            print(f"Attack Path: {' → '.join(path)}")
        impact = triage.get("impact", {})
        if impact:
            print(f"Impact: C={impact.get('confidentiality', 'N')} "
                  f"I={impact.get('integrity', 'N')} "
                  f"A={impact.get('availability', 'N')}")

    # ── Response ────────────────────────────────────────────────────────
    response = result.get("response_result", {})
    if isinstance(response, dict) and response:
        print(f"\n--- Response ---")
        print(f"Summary: {response.get('confirmed_attack_summary', '')}")
        actions = response.get("response_actions", [])
        if actions:
            print("Actions:")
            for i, action in enumerate(actions, 1):
                print(f"  {i}. {action}")

    # ── Compliance ──────────────────────────────────────────────────────
    compliance = result.get("compliance_result", {})
    if isinstance(compliance, dict) and compliance:
        print(f"\n--- Compliance ---")
        print(f"Data Compromised: {compliance.get('data_compromised', False)}")
        print(f"Exposure Type: {compliance.get('exposure_type', 'NONE')}")
        if compliance.get("recommended_compliance_actions"):
            print("Actions:")
            for action in compliance["recommended_compliance_actions"]:
                print(f"  • {action}")

    # ── CVSS ────────────────────────────────────────────────────────────
    cvss = result.get("cvss_result", {})
    if isinstance(cvss, dict) and cvss:
        print(f"\n--- CVSS v4.0 ---")
        cvss_error = cvss.get("error")
        if cvss_error:
            print(f"⚠️  Error: {cvss_error}")
        print(f"Score: {cvss.get('cvss_score', 0)} ({cvss.get('severity_label', 'NONE')})")
        print(f"Vector: {cvss.get('cvss_vector', 'N/A')}")

    # ── Summary ─────────────────────────────────────────────────────────
    print(f"\n--- SOC Summary ---")
    print(result.get("final_summary", "No summary generated."))
    print("=" * 60)


if __name__ == "__main__":
    main()
