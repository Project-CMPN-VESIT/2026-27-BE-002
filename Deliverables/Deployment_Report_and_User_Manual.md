# QUAL-KĪ: Research Deployment Report and User Manual

**Department of Computer Engineering, Vivekanand Education Society’s Institute of Technology (VESIT)**  
*Capstone Project – II (Academic Year 2026–27) | Group ID: BE-002*  
*Project Repository: Project-CMPN-VESIT / 2026-27-BE-002*

---

### Project Metadata
- **Project Title:** QUAL-KĪ: A Quantum-Resilient Zero Trust Security Framework: QML-Based Intrusion Detection, Eight-Agent SOC Orchestration, and Post-Quantum/QKD Communication
- **Project Mentor:** Dr. (Mrs.) Nupur Giri, Professor & Head, Department of Computer Engineering, VESIT
- **Industry Mentor:** Mr. Nikhil Kant, Affinity Solutions NYC
- **Team Members:**
  - Veda Patki (Roll No. 43)
  - Soham Patil (Roll No. 40)
  - Jai Desar (Roll No. 12)
  - Aadi Singh Chauhan (Roll No. 09)

---

## 1. Research Deployment Scope & Disclaimer

> [!NOTE] Research Prototype & Experimental Testbed Context
> **QUAL-KĪ is an advanced academic research prototype and empirical testbed.** In accordance with the project scope approved by the Department of Computer Engineering, this system is **not currently deployed in a live, commercial cloud production environment**. 
> 
> Instead, all experimental evaluations, model training, and agentic SOC workflows were conducted within a controlled, local **32-VM emulation testbed** executing automated MITRE Caldera adversary campaigns and local quantum circuit simulations.
> 
> The repository is engineered to be **100% self-contained and reproducible** in local research environments without requiring live network connections to external infrastructure, live hospital networks, or physical quantum computers.

---

## 2. System Architecture & Component Inventory

The QUAL-KĪ codebase integrates four functional planes:

```
+-----------------------------------------------------------------------------------+
|                           QUAL-KĪ REPOSITORY STRUCTURE                            |
+-----------------------------------------------------------------------------------+
|  src/quallki_agentic/                                                             |
|  ├── agents/              # 8 Specialized LangGraph SOC Agents                    |
|  │   ├── ingestion.py     # Multi-modal telemetry schema validator               |
|  │   ├── detection.py     # QML expectation & heuristic fusion                   |
|  │   ├── triage.py        # Severity scoring & 88.2% noise suppression           |
|  │   ├── threat_intel.py  # MITRE ATT&CK technique mapping                       |
|  │   ├── cwss_agent.py    # Common Weakness Scoring System (CWSS v1.0)           |
|  │   ├── response.py      # nftables firewall rules & HITL containment            |
|  │   ├── forensics.py     # Chronological attack graph generator                 |
|  │   └── compliance.py    # SOC 2, HIPAA, ISO 27001 regulatory auditor           |
|  ├── crypto/              # BB84 QKD simulation & ML-KEM-768 failover engine     |
|  ├── quantum/             # PyTorch Autoencoder (99->6) & PennyLane 6-qubit VQC   |
|  ├── orchestrator/        # LangGraph stateful workflow graph & HITL interrupts  |
|  ├── telemetry/           # 11-second sliding window cross-modal fusion engine    |
|  └── ui/                  # Streamlit Real-Time Autonomous SOC Console           |
+-----------------------------------------------------------------------------------+
|  Deliverables/            # All Capstone Project II Evaluation Deliverables       |
|  best_qml_autoencoder_6q.pt # Pre-trained PyTorch Autoencoder weights (99->6)     |
|  best_qml_vqc_6q.pt       # Pre-trained PennyLane 6-Qubit VQC weights             |
|  MasterDatasetProcessed_Clean.csv # Master 149k-row evaluation dataset            |
+-----------------------------------------------------------------------------------+
```

---

## 3. Hardware & Software Requirements

### 3.1 Recommended Hardware (Research Workstation)
- **Processor:** Intel Core i7 / AMD Ryzen 7 (8 cores or higher)
- **Memory (RAM):** 16 GB minimum (32 GB recommended for full dataset evaluation)
- **Storage:** 10 GB available SSD space
- **GPU (Optional):** NVIDIA GPU with CUDA 11.8+ (for accelerated PyTorch autoencoder training; CPU simulation supported out of the box)

### 3.2 Software Prerequisites
- **Operating System:** Windows 10/11, Ubuntu 22.04 LTS, or macOS (Sonoma+)
- **Python Runtime:** Python **3.10** or **3.11** (tested and verified)
- **Git:** Git 2.34 or higher

---

## 4. Installation & Environment Configuration

### Step 1: Clone Repository
```powershell
# In PowerShell or Terminal:
git clone https://github.com/Project-CMPN-VESIT/2026-27-BE-002.git
cd 2026-27-BE-002
```

### Step 2: Create & Activate Virtual Environment
```powershell
# Windows PowerShell:
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Package & Dependencies
```powershell
# Install package in editable mode with all dependencies
python -m pip install --upgrade pip
python -m pip install -e .
```

*Key dependencies installed:*
- `torch>=2.0.0` (Deep learning autoencoder)
- `pennylane>=0.35.0` (Quantum circuit simulation)
- `langgraph>=0.0.26`, `langchain>=0.1.0` (Agentic state orchestration)
- `streamlit>=1.30.0` (Interactive SOC analyst dashboard)
- `pydantic>=2.0.0` (Strict schema validation and prompt injection defenses)
- `lightgbm`, `xgboost`, `scikit-learn` (Classical benchmark baselines)

### Step 4: Environment Variables (`.env`)
Create a `.env` file in the repository root by copying `.env.example`:
```powershell
Copy-Item .env.example .env
```

*Configuration parameters:*
```ini
# Optional LLM API Keys (System includes built-in offline heuristic stubs):
GEMINI_API_KEY=your_gemini_api_key_here
NVIDIA_API_KEY=your_nvidia_nemotron_key_here

# LangSmith Tracing (Disabled by default for local execution):
ENABLE_LANGSMITH=false
LANGCHAIN_API_KEY=your_langchain_key_here

# Quantum Execution Mode:
QML_SIMULATOR_DEVICE=default.qubit
QML_NUM_QUBITS=6
```

> [!TIP] Offline Operation
> If no external API keys are provided, QUAL-KĪ automatically uses its internal rule-based heuristic fallback engine and pre-trained local model weights (`best_qml_autoencoder_6q.pt` and `best_qml_vqc_6q.pt`). You do not need paid API accounts to run the demo!

---

## 5. User Manual & Execution Modes

QUAL-KĪ supports three execution interfaces:

### Mode 1: Interactive Streamlit SOC Console (GUI)
Launch the full analyst dashboard with real-time telemetry tracking, QML expectation gauges, and containment controls:

```powershell
# Start Streamlit application
python src/app.py
# Or directly via streamlit:
streamlit run src/quallki_agentic/ui/streamlit_app.py
```
*Access in browser:* `http://localhost:8501`

**Dashboard Walkthrough:**
1. **Left Sidebar:** Select test scenario (e.g., `EHR Ransomware Outbreak`, `Radiology PACS Recon`, or `Infusion Pump Access`). View live cryptographic status (BB84 QBER rate: 3.42%, ML-KEM-768 session key).
2. **Top Execution Pipeline:** Watch the LangGraph state indicator transition across Ingestion, QML Detection, Triage, Threat Intel, Response, and Compliance.
3. **Main Incident Card:** Inspect QML Pauli-Z expectation probabilities, CWSS v1.0 weakness score (e.g., 87.4/100 on CWE-287), and MITRE ATT&CK techniques (T1021.002).
4. **Human-in-the-Loop Interlock:** Review proposed firewall containment rule (`nft add rule ...`). Click **Approve Containment** to authorize isolation.
5. **Right & Bottom Panels:** Review real-time SOC 2 / HIPAA compliance audit briefs and forensic event reconstruction graphs.

---

### Mode 2: Headless Command-Line Interface (CLI)
Execute automated analysis on pre-packaged attack scenarios or external telemetry files:

```powershell
# Run pre-configured healthcare attack scenario:
quallki-cli --scenario ehr_ransomware

# Run with custom JSON alert telemetry input:
quallki-cli --input test_ransomware.json

# Run Denial of Service test scenario:
quallki-cli --scenario test_dos
```

**Sample CLI Output:**
```text
======================================================================
QUAL-KĪ AGENTIC SOC — INCIDENT EXECUTION TRACE
======================================================================
[+] Ingestion Agent: Validated 99-feature multi-modal vector.
[+] QML Engine: Autoencoder compression (99->6) MSE=0.0142.
[+] QML Engine: 6-Qubit VQC evaluated on PennyLane default.qubit.
    Top Label: Ransac (Class 7) | Pauli-Z Probability: 0.894
[+] Triage Agent: Verdict = P1_CRITICAL (Escalated to IR Team)
[+] Threat Intel Agent: MITRE ATT&CK T1021.002, T1078.
[+] CWSS Agent: Weakness CWE-287 | CWSS Score = 87.4 / 100.
[+] Response Agent: Generated nftables drop rule for 172.16.16.27.
[+] HITL Gate: Simulation auto-approved containment.
[+] Compliance Agent: Audit brief verified (SOC 2 CC6.8, HIPAA §164.312).
[+] End-to-End Latency: 18.4 seconds.
======================================================================
```

---

### Mode 3: Automated Diagnostic & Regression Test Suite
Verify model accuracy, quantum circuit unitarity, and model agreement:

```powershell
# 1. Classical Model Verification:
python test_classical.py

# 2. Quantum Circuit & Autoencoder Check:
python test_qml.py

# 3. Model Consensus & Agreement Testing:
python test_dual_model.py

# 4. LLM API & Structured Output Verification:
python test_gemini.py
```

---

## 6. Telemetry Ingress & Feature Schema

The system ingests 99 continuous and discrete features structured into four domains:

| Feature Category | Count | Example Metrics |
| :--- | :---: | :--- |
| **Network Protocol Features** | 17 | `protocol`, `src_port`, `dst_port`, `flags_syn`, `flags_ack`, `flags_rst` |
| **Flow Dynamics Features** | 23 | `flow_duration`, `total_fpackets`, `total_bpackets`, `flow_bytes_s`, `flow_packets_s` |
| **Packet Distribution Features** | 18 | `fpacket_len_mean`, `bpacket_len_std`, `inter_arrival_mean`, `window_size` |
| **Endpoint Host OS Features** | 41 | Wazuh Sysmon EventID counts (Event 1 Process Create, Event 3 Network Connect, Event 7 Image Load, Event 11 File Create) |

All continuous features are normalized via $z$-score and bounded into $[0, 1]$ before passing into the PyTorch autoencoder.

---

## 7. Safety Interlocks & Containment Safeguards

To prevent inadvertent network disruption during research demonstrations:
1. **Dry-Run Containment Mode:** All firewall commands (`nftables`, `iptables`, `wazuh active response`) are generated as structured bash payloads and logged to audit files. They are executed on the host OS only if `--enable-live-containment` is explicitly passed in privileged environments.
2. **Human-in-the-Loop Pause Gate:** The LangGraph state machine enforces an interrupt before applying containment, preventing autonomous lockout of essential services.
3. **Air-Gapped Operation:** All model checkpoints, datasets, and heuristic rules reside locally on disk, ensuring zero external data leakage.

---

## 8. Summary of Research Verification

QUAL-KĪ successfully demonstrates that a unified quantum-classical architecture can be deployed and evaluated within local laboratory testbeds to achieve:
- **Parameter-efficient quantum classification** using just 142 parameters.
- **Sub-20 second autonomous incident triage and containment**.
- **Provable immunity against adversarial prompt injections and quantum eavesdropping**.

**User Manual Status:** **FINALIZED FOR PROJECT CMPN REPOSITORY**  
*Project CMPN Group BE-002: Veda Patki, Soham Patil, Jai Desar, Aadi Singh Chauhan.*
