"""QUAL-KI Agentic SOC — Streamlit Dashboard with Live Execution Status.

Revised UI matching the new pipeline:
Preprocessing → QML → Detection → Triage → Response → Compliance + CVSS (background)

Features live execution status panel showing PENDING/RUNNING/COMPLETED/ERROR
for every pipeline stage, with sub-step details and elapsed time.
"""
from __future__ import annotations

import json
import time

import streamlit as st

from quallki_agentic.healthcare import HOSPITAL_DEMO_CASES
from quallki_agentic.healthcare.demo_runner import run_alert_payload, run_healthcare_demo_scenario

# ── Page config ─────────────────────────────────────────────────────────
st.set_page_config(page_title="QUAL-KI Agentic SOC", layout="wide")

st.title("🛡️ QUAL-KI Agentic SOC")
st.caption(
    "Quantum-enhanced agentic cybersecurity pipeline — "
    "Preprocessing → QML → Detection → Triage → Response → Compliance + CVSS"
)

# ── Sidebar ─────────────────────────────────────────────────────────────
input_mode = st.sidebar.radio("Input source", ["Live JSON/JSONL", "Synthetic demo"], index=0)
scenario_key = None
uploaded_file = None

if input_mode == "Synthetic demo":
    scenario_key = st.sidebar.selectbox(
        "Select Hospital Scenario",
        options=sorted(HOSPITAL_DEMO_CASES.keys()),
        index=0,
    )
else:
    uploaded_file = st.sidebar.file_uploader("Upload alert JSON or JSONL", type=["json", "jsonl", "txt"])

run_clicked = st.sidebar.button("🚀 Run Agentic SOC", use_container_width=True)

# ── Run Pipeline ────────────────────────────────────────────────────────
if run_clicked:
    if input_mode == "Synthetic demo" and scenario_key:
        with st.spinner("Running pipeline..."):
            st.session_state["run_data"] = run_healthcare_demo_scenario(scenario_key)
            st.session_state["run_mode"] = input_mode
    elif uploaded_file is not None:
        raw_text = uploaded_file.getvalue().decode("utf-8").strip()
        try:
            parsed = json.loads(raw_text)
            record = parsed[0] if isinstance(parsed, list) else parsed
            if not isinstance(record, dict):
                raise ValueError("The uploaded JSON must contain an object or a list of objects")
            with st.spinner("Running pipeline..."):
                st.session_state["run_data"] = run_alert_payload(record)
                st.session_state["run_mode"] = input_mode
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            st.error(f"Could not load alert input: {exc}")

# ── Get run data ────────────────────────────────────────────────────────
run_data = st.session_state.get("run_data") if st.session_state.get("run_mode") == input_mode else None
if run_data is None:
    if input_mode == "Synthetic demo" and scenario_key:
        run_data = run_healthcare_demo_scenario(scenario_key)
    else:
        st.info("Upload a real JSON/JSONL alert and click Run Agentic SOC.")
        st.stop()

# ── Extract results ─────────────────────────────────────────────────────
result = run_data["result"]
scenario = run_data["scenario"]
progress_events = run_data.get("progress_events", [])
detection_result = result.get("detection_result", {})
triage_result = result.get("triage_result", {})
response_result = result.get("response_result", {})
compliance_result = result.get("compliance_result", {})
cvss_result = result.get("cvss_result", {})
final_report = result.get("final_report", {})

# ── Top metrics ─────────────────────────────────────────────────────────
metric_cols = st.columns(5)
metric_cols[0].metric("Attack Type", str(detection_result.get("attack_type", "—")))
metric_cols[1].metric("Confidence", f"{float(detection_result.get('confidence', 0)):.2f}")
metric_cols[2].metric("Severity", str(detection_result.get("initial_severity", "—")).upper())
metric_cols[3].metric("CVSS Score", f"{float(cvss_result.get('cvss_score', 0)):.1f}")
metric_cols[4].metric("Scenario", run_data["scenario_key"])

qml_result = result.get("qml_result", {})
st.caption(f"QML backend: {qml_result.get('backend', 'unknown')} | Incident: {result.get('incident_id', 'N/A')}")


# =========================================================================
# TABS
# =========================================================================

(
    tab_execution,
    tab_overview,
    tab_detection,
    tab_triage,
    tab_response,
    tab_compliance,
    tab_cvss,
    tab_report,
    tab_trace,
) = st.tabs([
    "⟳ Execution Log",
    "📋 Overview",
    "🔍 Detection",
    "🎯 Triage",
    "🛡️ Response",
    "📜 Compliance",
    "📊 CVSS",
    "📝 Final Report",
    "🔗 LangGraph Trace",
])


# ── Tab: Live Execution Log ────────────────────────────────────────────
with tab_execution:
    st.subheader("Live Pipeline Execution Status")
    st.caption("Real-time progress of every pipeline stage, LLM call, and background process.")

    STATUS_ICON = {
        "PENDING": "○",
        "RUNNING": "⟳",
        "COMPLETED": "✓",
        "ERROR": "✗",
    }
    STATUS_COLOR = {
        "PENDING": "#888888",
        "RUNNING": "#3b82f6",
        "COMPLETED": "#22c55e",
        "ERROR": "#ef4444",
    }

    # Pipeline stages overview
    pipeline_stages = ["preprocessing", "qml", "detection", "triage", "response", "compliance", "cvss", "finalize"]
    stage_labels = {
        "preprocessing": "Preprocessing",
        "qml": "QML Model",
        "detection": "Detection Agent",
        "triage": "Triage Agent",
        "response": "Response Agent",
        "compliance": "Compliance Agent",
        "cvss": "CVSS Agent (Background)",
        "finalize": "Finalize Report",
    }

    # Build per-agent status from events
    agent_status: dict[str, dict] = {}
    agent_events: dict[str, list] = {s: [] for s in pipeline_stages}
    for event in progress_events:
        agent = event.get("agent", "")
        if agent in agent_events:
            agent_events[agent].append(event)
            agent_status[agent] = event

    # Render status panel
    for stage in pipeline_stages:
        latest = agent_status.get(stage, {})
        status = latest.get("status", "PENDING")
        icon = STATUS_ICON.get(status, "○")
        color = STATUS_COLOR.get(status, "#888")
        label = stage_labels.get(stage, stage)
        message = latest.get("message", "")
        duration = latest.get("duration_ms")

        duration_text = f" ({duration:.0f}ms)" if duration else ""
        badge = f'<span style="color:{color};font-weight:bold;font-size:1.1em">{icon}</span>'

        st.markdown(
            f'{badge} **{label}** [{status}]{duration_text}',
            unsafe_allow_html=True,
        )

        # Show sub-steps
        events = agent_events.get(stage, [])
        if events and len(events) > 1:
            sub_lines = []
            for ev in events:
                sub_icon = STATUS_ICON.get(ev.get("status", ""), "·")
                sub_msg = ev.get("message", "")
                sub_dur = ev.get("duration_ms")
                dur_str = f" ({sub_dur:.0f}ms)" if sub_dur else ""
                sub_lines.append(f"&nbsp;&nbsp;&nbsp;&nbsp;{sub_icon} {sub_msg}{dur_str}")
            st.markdown("<br>".join(sub_lines), unsafe_allow_html=True)

        st.markdown("---")

    # Full event log
    with st.expander("📜 Full Event Log (JSON)", expanded=False):
        st.json(progress_events)


# ── Tab: Overview ───────────────────────────────────────────────────────
with tab_overview:
    st.subheader(str(scenario.get("title", run_data["scenario_key"])))
    st.write(str(scenario.get("message", "")))
    st.write({
        "asset_type": scenario.get("asset_type"),
        "contains_phi": scenario.get("contains_phi"),
        "clinical_impact": scenario.get("clinical_impact"),
        "source_ip": scenario.get("source_ip"),
        "simulation": run_data.get("payload", {}).get("simulation", {}),
    })
    st.subheader("Raw Security Logs")
    st.code("\n".join(run_data.get("logs", [])) or "No logs generated.", language="text")


# ── Tab: Detection ──────────────────────────────────────────────────────
with tab_detection:
    st.subheader("Detection Agent Output")
    st.caption("Interprets QML model output and creates a structured DetectionResult.")

    if isinstance(detection_result, dict) and detection_result:
        col1, col2, col3 = st.columns(3)
        col1.metric("Attack Type", detection_result.get("attack_type", "—"))
        col2.metric("Confidence", f"{float(detection_result.get('confidence', 0)):.2f}")
        col3.metric("Initial Severity", str(detection_result.get("initial_severity", "—")).upper())

        st.subheader("QML Model Info")
        st.json(detection_result.get("qml", {}))

        st.subheader("Evidence & IOCs")
        st.write("**Evidence:**", detection_result.get("evidence", []))
        st.write("**IOCs:**", detection_result.get("iocs", []))
        st.write("**Suspicious Events:**", detection_result.get("suspicious_events", []))

        with st.expander("Full DetectionResult JSON"):
            st.json(detection_result)
    else:
        st.info("No detection result available")


# ── Tab: Triage ─────────────────────────────────────────────────────────
with tab_triage:
    st.subheader("Triage Agent Output")
    st.caption("Confirms attack type and reconstructs exact attack path using DetectionResult + raw logs.")

    if isinstance(triage_result, dict) and triage_result:
        confirmed = triage_result.get("confirmed_attack", {})
        if isinstance(confirmed, dict):
            col1, col2, col3 = st.columns(3)
            col1.metric("Confirmed Category", confirmed.get("category", "—"))
            col2.metric("Mechanism", confirmed.get("mechanism", "—"))
            col3.metric("Triage Confidence", f"{float(triage_result.get('confidence', 0)):.2f}")

            st.subheader("Attack Path")
            path = confirmed.get("attack_path", [])
            if path:
                path_text = " → ".join(path)
                st.info(f"**{path_text}**")
            else:
                st.write("No attack path reconstructed")

        st.subheader("Impact Assessment")
        impact = triage_result.get("impact", {})
        if isinstance(impact, dict):
            icols = st.columns(3)
            icols[0].metric("Confidentiality", impact.get("confidentiality", "NONE"))
            icols[1].metric("Integrity", impact.get("integrity", "NONE"))
            icols[2].metric("Availability", impact.get("availability", "NONE"))

        st.subheader("Timeline")
        timeline = triage_result.get("timeline", [])
        if isinstance(timeline, list) and timeline:
            for item in timeline:
                if isinstance(item, dict):
                    st.write(f"**{item.get('timestamp', '')}** — {item.get('event', '')}")
        else:
            st.write("No timeline reconstructed")

        st.subheader("Affected Assets")
        st.write(triage_result.get("affected_assets", []))

        with st.expander("Full TriageResult JSON"):
            st.json(triage_result)
    else:
        st.info("No triage result available")


# ── Tab: Response ───────────────────────────────────────────────────────
with tab_response:
    st.subheader("Response Agent Output")
    st.caption("Operational response actions tied to the confirmed attack path.")

    if isinstance(response_result, dict) and response_result:
        st.write(f"**Summary:** {response_result.get('confirmed_attack_summary', '')}")

        st.subheader("Response Actions")
        for i, action in enumerate(response_result.get("response_actions", []), 1):
            st.write(f"{i}. {action}")

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Containment Steps")
            for step in response_result.get("containment_steps", []):
                st.write(f"• {step}")
        with col2:
            st.subheader("Recovery Steps")
            for step in response_result.get("recovery_steps", []):
                st.write(f"• {step}")

        st.subheader("Monitoring Recommendations")
        for rec in response_result.get("monitoring_recommendations", []):
            st.write(f"• {rec}")

        with st.expander("Full ResponseResult JSON"):
            st.json(response_result)
    else:
        st.info("No response result available")


# ── Tab: Compliance ─────────────────────────────────────────────────────
with tab_compliance:
    st.subheader("Healthcare Compliance Assessment")
    st.warning(
        "This is an evidence assessment, not a compliance certification. "
        "A qualified control owner or auditor must validate the evidence."
    )

    if isinstance(compliance_result, dict) and compliance_result:
        ccols = st.columns(4)
        ccols[0].metric("Data Compromised", "Yes" if compliance_result.get("data_compromised") else "No")
        ccols[1].metric("Exposure Type", compliance_result.get("exposure_type", "NONE"))
        ccols[2].metric("Domain", compliance_result.get("domain", "HEALTHCARE"))
        ccols[3].metric("Status", compliance_result.get("compliance_assessment", {}).get("status", "—"))

        if compliance_result.get("data_types"):
            st.subheader("Affected Data Types")
            for dt in compliance_result["data_types"]:
                st.write(f"• {dt}")

        if compliance_result.get("recommended_compliance_actions"):
            st.subheader("Recommended Compliance Actions")
            for action in compliance_result["recommended_compliance_actions"]:
                st.write(f"• {action}")

        st.subheader("Compliance Summary")
        st.write(compliance_result.get("compliance_summary", ""))

        with st.expander("Full ComplianceResult JSON"):
            st.json(compliance_result)
    else:
        st.info("No compliance result available")

    # Legacy compliance checklist
    checklist = result.get("compliance_checklist", [])
    compliance_assessment = result.get("compliance_assessment", {})
    if isinstance(checklist, list) and checklist:
        st.divider()
        st.subheader("Control-by-Control Evidence Mapping")

        if isinstance(compliance_assessment, dict):
            acols = st.columns(4)
            acols[0].metric("Applicable Controls", compliance_assessment.get("applicable_controls", 0))
            acols[1].metric("✅ Evidence Complete", compliance_assessment.get("evidence_complete", 0))
            acols[2].metric("⚠️ Partial", compliance_assessment.get("partial", 0))
            acols[3].metric("❌ Not Evidenced", compliance_assessment.get("not_evidenced", 0))

        STATUS_ICON_COMP = {
            "evidence_complete": "✅",
            "partial": "⚠️",
            "not_evidenced": "❌",
            "not_applicable": "⚪",
        }
        order = ["evidence_complete", "partial", "not_evidenced", "not_applicable"]
        grouped: dict[str, list] = {s: [] for s in order}
        for row in checklist:
            s = row.get("status", "not_applicable")
            grouped.setdefault(s, []).append(row)

        for status_key in order:
            rows = grouped.get(status_key, [])
            if not rows:
                continue
            icon = STATUS_ICON_COMP.get(status_key, "")
            label = status_key.replace("_", " ").title()
            st.markdown(f"### {icon} {label}")
            for row in rows:
                ctrl_id = row.get("id", "—")
                framework = row.get("framework", "—")
                with st.expander(f"{icon}  {ctrl_id}  |  {framework}"):
                    st.markdown(f"**Control:** {row.get('control', '—')}")
                    st.markdown(f"**Owner:** `{row.get('owner', '—')}`")
                    present = row.get("evidence_present", [])
                    missing = row.get("evidence_missing", [])
                    if present:
                        st.markdown(f"**Evidence Present:** `{'`, `'.join(present)}`")
                    if missing:
                        st.markdown(f"**Evidence Missing:** `{'`, `'.join(missing)}`")


# ── Tab: CVSS ───────────────────────────────────────────────────────────
with tab_cvss:
    st.subheader("CVSS v4.0 Assessment")
    st.caption("Calculated independently by the background CVSS Agent.")

    if isinstance(cvss_result, dict) and cvss_result:
        cvss_error = cvss_result.get("error")
        if cvss_error:
            st.error(f"⚠️ CVSS Agent Error: {cvss_error}")

        ccols = st.columns(3)
        ccols[0].metric("CVSS Score", f"{float(cvss_result.get('cvss_score', 0)):.1f}")
        ccols[1].metric("Severity", cvss_result.get("severity_label", "NONE"))
        ccols[2].metric("Vector", cvss_result.get("cvss_vector", "—"))

        exploit = cvss_result.get("exploitability_metrics", {})
        if isinstance(exploit, dict) and exploit:
            st.subheader("Exploitability Metrics")
            ecols = st.columns(5)
            ecols[0].metric("Attack Vector", exploit.get("attack_vector", "—"))
            ecols[1].metric("Attack Complexity", exploit.get("attack_complexity", "—"))
            ecols[2].metric("Attack Requirements", exploit.get("attack_requirements", "—"))
            ecols[3].metric("Privileges Required", exploit.get("privileges_required", "—"))
            ecols[4].metric("User Interaction", exploit.get("user_interaction", "—"))

        impact = cvss_result.get("impact_metrics", {})
        if isinstance(impact, dict) and impact:
            st.subheader("Impact Metrics")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Vulnerable System**")
                vcols = st.columns(3)
                vcols[0].metric("Confidentiality", impact.get("confidentiality_vuln", "—"))
                vcols[1].metric("Integrity", impact.get("integrity_vuln", "—"))
                vcols[2].metric("Availability", impact.get("availability_vuln", "—"))
            with col2:
                st.markdown("**Subsequent System**")
                scols = st.columns(3)
                scols[0].metric("Confidentiality", impact.get("confidentiality_sub", "—"))
                scols[1].metric("Integrity", impact.get("integrity_sub", "—"))
                scols[2].metric("Availability", impact.get("availability_sub", "—"))

        supplemental = cvss_result.get("supplemental_context", {})
        if isinstance(supplemental, dict) and supplemental:
            st.subheader("Supplemental Context")
            scols = st.columns(2)
            scols[0].metric("Automatable", supplemental.get("automatable", "—"))
            scols[1].metric("Recovery", supplemental.get("recovery", "—"))

        evidence = cvss_result.get("supporting_evidence", [])
        if evidence:
            st.subheader("Supporting Evidence")
            for e in evidence:
                st.write(f"• {e}")

        with st.expander("Full CVSSResult JSON"):
            st.json(cvss_result)
    else:
        st.info("No CVSS result available")


# ── Tab: Final Report ───────────────────────────────────────────────────
with tab_report:
    st.subheader("Final Incident Report")
    st.caption("Combined output from Detection + Triage + Response + Compliance + CVSS.")

    summary = result.get("final_summary", "")
    if summary:
        st.info(summary)

    if isinstance(final_report, dict) and final_report:
        st.subheader("Incident Overview")
        st.write(f"**Incident ID:** {final_report.get('incident_id', 'N/A')}")
        st.write(f"**Generated At:** {final_report.get('generated_at', 'N/A')}")

        # Summary cards
        det = final_report.get("detection", {})
        tri = final_report.get("triage", {})
        resp = final_report.get("response", {})
        comp = final_report.get("compliance", {})
        cvss = final_report.get("cvss", {})

        st.markdown("---")
        st.markdown("### Detection")
        st.write(f"**{det.get('attack_type', 'N/A')}** — {float(det.get('confidence', 0)):.0%} QML confidence")

        st.markdown("### Triage")
        confirmed = tri.get("confirmed_attack", {})
        if isinstance(confirmed, dict):
            path = " → ".join(confirmed.get("attack_path", []))
            st.write(f"**{confirmed.get('mechanism', 'N/A')}** — {path or 'No path'}")

        st.markdown("### Response")
        resp_actions = resp.get("response_actions", [])
        st.write(f"{len(resp_actions)} actions: " + ("; ".join(resp_actions[:3]) + ("..." if len(resp_actions) > 3 else "") if resp_actions else "None"))

        st.markdown("### Compliance")
        st.write(comp.get("compliance_summary", "N/A")[:200] if isinstance(comp, dict) else "N/A")

        st.markdown("### CVSS")
        st.write(f"Vector: {cvss.get('cvss_vector', 'N/A')}")
        st.write(f"Score: {cvss.get('cvss_score', 0)} ({cvss.get('severity_label', 'NONE')})")

        with st.expander("Full Final Report JSON"):
            st.json(final_report)
    else:
        st.write(summary or "No final report generated.")


# ── Tab: LangGraph Trace ───────────────────────────────────────────────
with tab_trace:
    st.subheader("LangGraph Execution Trace")
    st.caption("Each entry is the state update returned by a real graph node for this run.")
    trace = run_data.get("workflow_trace", [])
    if isinstance(trace, list) and trace:
        for index, entry in enumerate(trace, start=1):
            if not isinstance(entry, dict):
                continue
            node = str(entry.get("node", "unknown"))
            with st.expander(f"{index}. {node}", expanded=index == 1):
                st.json(entry.get("output", {}))
    else:
        st.info("No streamed graph updates available.")
