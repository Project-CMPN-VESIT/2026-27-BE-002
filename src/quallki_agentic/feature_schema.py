from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

FEATURE_NAMES: tuple[str, ...] = (
    "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
    "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fwd_header_len", "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts",
    "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
    "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt", "down_up_ratio",
    "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts",
    "active_max", "active_min", "active_mean", "active_std",
    "idle_max", "idle_min", "idle_mean", "idle_std",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
    "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "cwr_flag_count", "subflow_fwd_pkts", "subflow_bwd_pkts", "subflow_fwd_byts",
    "subflow_bwd_byts", "os_event_volume", "os_severity_max", "os_severity_sum",
    "os_sysmon_proc_cnt", "os_pam_sudo_cnt", "os_high_severity_cnt",
    "dst_port_443", "dst_port_53", "dst_port_80", "dst_port_7680",
    "dst_port_8888", "dst_port_1514", "dst_port_22", "dst_port_3389", "dst_port_other",
    "src_port_ephemeral", "src_port_wellknown", "src_port_443", "src_port_80", "src_port_53",
    "proto_tcp", "proto_udp", "proto_other",
)


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def build_feature_vector(payload: Mapping[str, Any]) -> tuple[list[float], str]:
    """Build the supplied 99-feature vector before QML reduction.

    Callers may provide ``feature_vector`` as a sequence or ``features`` as a
    mapping. Missing values are zero-filled so synthetic demo events remain
    runnable while real telemetry can provide the full schema.
    """
    raw_vector = payload.get("feature_vector")
    if isinstance(raw_vector, Sequence) and not isinstance(raw_vector, (str, bytes)):
        values = [_number(value) for value in raw_vector]
        if len(values) != len(FEATURE_NAMES):
            raise ValueError(f"feature_vector must contain {len(FEATURE_NAMES)} values")
        return values, "provided_vector"

    raw_features = payload.get("features", {})
    features = raw_features if isinstance(raw_features, Mapping) else {}
    values = [_number(features.get(name, 0.0)) for name in FEATURE_NAMES]
    logs = payload.get("logs", [])
    log_text = " ".join(str(log) for log in logs) if isinstance(logs, list) else ""
    message = f"{payload.get('message', '')} {log_text}".lower()

    def set_value(name: str, value: float) -> None:
        values[FEATURE_NAMES.index(name)] = value

    if not features:
        set_value("os_event_volume", float(len(logs) if isinstance(logs, list) else 0))
        severity = 10.0 if any(token in message for token in ("ransom", "encrypt")) else 5.0
        set_value("os_severity_max", severity)
        set_value("os_severity_sum", severity * (len(logs) if isinstance(logs, list) else 0))
        set_value("os_sysmon_proc_cnt", float(message.count("powershell")))
        set_value("os_pam_sudo_cnt", float(message.count("sudo")))
        set_value("os_high_severity_cnt", float(any(token in message for token in ("ransom", "credential", "failed login"))))
        set_value("dst_port_443", float("https" in message or "443" in message))
        set_value("dst_port_22", float("ssh" in message or "22" in message))
        set_value("dst_port_80", float("http" in message or "80" in message))
        set_value("dst_port_other", 1.0)
        set_value("src_port_ephemeral", 1.0)
        set_value("proto_tcp", 1.0)
        set_value("proto_other", 0.0)

        # ── DOS / DDoS signal extraction from log text ──────────────────
        import re

        # High request rate → high flow_pkts_s / flow_byts_s
        rate_matches = re.findall(r"(\d+)\s*req/s", message)
        if rate_matches:
            max_rate = max(float(r) for r in rate_matches)
            set_value("flow_pkts_s", max_rate)
            set_value("fwd_pkts_s", max_rate)
            set_value("flow_byts_s", max_rate * 512)  # est. bytes

        # Connection exhaustion → high tot_fwd_pkts
        conn_matches = re.findall(r"connections?\s+(\d+)/(\d+)", message)
        if conn_matches:
            active, total = float(conn_matches[-1][0]), float(conn_matches[-1][1])
            set_value("tot_fwd_pkts", active)
            set_value("totlen_fwd_pkts", active * 1024)

        # 503 errors = service unavailable → signature of successful DOS
        count_503 = message.count("503")
        if count_503 > 0:
            set_value("rst_flag_cnt", float(count_503))
            set_value("fin_flag_cnt", float(count_503))

        # OOM / memory exhaustion signals
        oom_signals = sum(1 for tok in ("oom", "out of memory", "oom-kill", "memory pressure",
                                         "memory exhaustion") if tok in message)
        if oom_signals:
            set_value("os_high_severity_cnt", float(oom_signals))
            set_value("os_severity_max", 10.0)
            set_value("flow_duration", 1.0)  # very short attack window

        # Flood / rate-limit triggers → high pkt volume
        if any(tok in message for tok in ("flood", "rate_limit", "rate-limit", "all_busy", "ddos")):
            set_value("flow_pkts_s", max(values[FEATURE_NAMES.index("flow_pkts_s")], 1000.0))
            set_value("syn_flag_cnt", 1.0)
            set_value("psh_flag_cnt", 1.0)

    return values, "derived_demo" if not features else "provided_features"
