# QUAL-KI Agentic SOC --- Revised Agent Flow

## 1. Purpose

This document defines the revised **QUAL-KI Agentic SOC** execution
flow.

The system is an agentic cybersecurity pipeline in which raw security
logs are first analyzed by a **Quantum Machine Learning (QML) model**,
followed by specialized agents that progressively enrich the incident
understanding:

``` text
Logs
  ↓
Preprocessing
  ↓
QML Detection Model
  ↓
Detection Agent
  ↓
Triage Agent
  ↓
Response Agent
  ↓
Compliance Agent
  ↓
Final Incident Report
```

A separate **CVSS Agent** runs independently in the background and
calculates the incident/vulnerability severity using **CVSS v4.0** from
the available logs and post-attack evidence.

### Important architectural constraint

**No fallback logic is required in the current version.**

The pipeline should follow the defined path directly:

> Logs → Preprocessing → QML → Detection → Triage → Response →
> Compliance

If a component fails, the system should surface the failure clearly
rather than silently switching to another model, rule engine, or
alternative path.

------------------------------------------------------------------------

# 2. High-Level Architecture

``` text
                         ┌──────────────────────┐
                         │      Raw Logs         │
                         │ Network / App / OS    │
                         │ Auth / Stack Traces   │
                         │ DB / File / API Logs  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    Preprocessing      │
                         │ Parse / Clean /       │
                         │ Normalize / Features  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │     QML Model         │
                         │ Anomaly / Threat      │
                         │ Detection              │
                         └──────────┬───────────┘
                                    │
                                    ▼
                  ┌──────────────────────────────────┐
                  │        Detection Agent            │
                  │                                  │
                  │ Interprets QML output and        │
                  │ extracts important incident      │
                  │ details                           │
                  └────────────────┬─────────────────┘
                                   │
                         DetectionResult Object
                                   │
                                   ▼
                  ┌──────────────────────────────────┐
                  │          Triage Agent             │
                  │                                  │
                  │ DetectionResult + Original Logs  │
                  │                                  │
                  │ Confirms attack type, reconstructs│
                  │ exact attack path and evidence    │
                  └────────────────┬─────────────────┘
                                   │
                            TriageResult Object
                                   │
                                   ▼
                  ┌──────────────────────────────────┐
                  │         Response Agent            │
                  │                                  │
                  │ Determines recommended response  │
                  │ actions based on confirmed        │
                  │ incident                          │
                  └────────────────┬─────────────────┘
                                   │
                            ResponseResult
                                   │
                                   ▼
                  ┌──────────────────────────────────┐
                  │        Compliance Agent           │
                  │                                  │
                  │ Healthcare-specific compliance   │
                  │ and data compromise assessment   │
                  └────────────────┬─────────────────┘
                                   │
                                   ▼
                         ┌──────────────────────┐
                         │ Final SOC Report      │
                         │ Detection             │
                         │ Triage                │
                         │ Response              │
                         │ Compliance            │
                         │ CVSS                  │
                         └──────────────────────┘


              ┌──────────────────────────────────────┐
              │          CVSS Agent                   │
              │      Runs independently               │
              │                                      │
              │ Logs + attack evidence + system      │
              │ impact → CVSS v4.0 calculation       │
              └──────────────────────────────────────┘
                              │
                              ▼
                         CVSS Result
```

------------------------------------------------------------------------

# 3. End-to-End Flow

## Step 1 --- Log Ingestion

The system receives the raw security logs associated with the monitored
environment.

Possible inputs include:

-   Network logs
-   Authentication logs
-   Application logs
-   API request logs
-   System logs
-   Database query logs
-   File integrity logs
-   CPU/memory/availability metrics
-   Stack traces
-   Process execution logs
-   Network traffic / PCAP-derived information
-   Session/token information
-   Data egress logs

The original logs must be retained because later agents need the raw
evidence.

### Output

``` text
RawLogSet
```

Example:

``` json
{
  "incident_id": "INC-001",
  "timestamp_range": {
    "start": "...",
    "end": "..."
  },
  "logs": [
    {
      "source": "api",
      "timestamp": "...",
      "message": "..."
    },
    {
      "source": "application",
      "timestamp": "...",
      "message": "..."
    }
  ]
}
```

------------------------------------------------------------------------

# 4. Step 2 --- Preprocessing

The logs are passed into the preprocessing layer before reaching the QML
model.

The preprocessing pipeline depends on the actual QML model and its
expected input representation.

Typical preprocessing operations can include:

1.  Log parsing
2.  Timestamp normalization
3.  Field extraction
4.  Missing-value handling
5.  Categorical encoding
6.  Numerical normalization
7.  Feature extraction
8.  Sequence construction
9.  Feature selection
10. Conversion into the exact tensor/vector representation expected by
    the QML model

The preprocessing stage must produce a deterministic model-ready
representation.

``` text
Raw Logs
   ↓
Parse
   ↓
Normalize
   ↓
Feature Extraction
   ↓
Feature Encoding
   ↓
Model Input
```

### Output

``` text
PreprocessedLogFeatures
```

The original logs remain available separately.

This distinction is important:

``` text
Raw Logs ────────────────┐
                         │
                         ├──→ Triage Agent
                         │
Preprocessed Features ──→ QML Model
```

The triage agent should **not rely only on the transformed QML
features**. It needs access to the original evidence to reconstruct how
the attack actually happened.

------------------------------------------------------------------------

# 5. Step 3 --- QML Detection Model

The QML model is the first intelligence component.

Its responsibility is:

> Analyze the preprocessed security telemetry and identify whether the
> observed behavior corresponds to anomalous or potentially malicious
> activity.

The model can produce outputs such as:

-   Anomaly score
-   Predicted attack category
-   Class probabilities
-   Confidence
-   Relevant model features
-   Detection label

Example:

``` json
{
  "prediction": "DOS",
  "confidence": 0.94,
  "anomaly_score": 0.91,
  "model_version": "qml-v1"
}
```

The QML model is **not responsible for reconstructing the complete
attack path**.

It provides the initial machine-learning detection signal.

------------------------------------------------------------------------

# 6. Step 4 --- Detection Agent

The Detection Agent receives the QML output.

Its job is to convert the model output into a structured incident
representation.

It should capture the important information that the previous detection
logic already extracted, such as:

-   Incident ID
-   Detected attack category
-   Confidence
-   Anomaly score
-   Relevant timestamps
-   Affected source
-   Affected destination
-   Suspicious entities
-   Relevant events
-   Initial severity indication
-   QML model information
-   Evidence references

The Detection Agent creates a structured object.

## DetectionResult

``` json
{
  "incident_id": "INC-001",
  "attack_type": "DOS",
  "confidence": 0.94,
  "anomaly_score": 0.91,
  "timestamp_range": {
    "start": "...",
    "end": "..."
  },
  "source": {
    "ip": "...",
    "entity": "..."
  },
  "target": {
    "ip": "...",
    "service": "..."
  },
  "suspicious_events": [],
  "evidence": [],
  "qml": {
    "model": "qml-v1",
    "prediction": "DOS"
  }
}
```

This object becomes the primary structured input to the Triage Agent.

------------------------------------------------------------------------

# 7. Step 5 --- Triage Agent

The Triage Agent is responsible for **confirming and explaining the
attack**.

It receives two inputs:

``` text
DetectionResult
      +
Original Raw Logs
```

This is a critical design decision.

The Detection Agent tells the triage system:

> "The QML model detected something that looks like a DoS attack."

The Triage Agent then uses the raw evidence to determine:

> "What exactly happened, and through which technical path did it
> happen?"

------------------------------------------------------------------------

## 7.1 Attack Confirmation

The Triage Agent should correlate:

-   QML detection
-   Network events
-   Application events
-   Authentication events
-   Stack traces
-   Process information
-   Resource utilization
-   API requests
-   Database activity
-   File/system changes
-   Temporal relationships

It should determine whether the detected attack is supported by the
available evidence.

------------------------------------------------------------------------

# 7.2 Exact Attack Path

The Triage Agent should go beyond the high-level attack category.

For example:

``` text
Attack Type:
DOS

Possible mechanisms:
├── Request spamming
├── Resource exhaustion
├── Connection exhaustion
├── Memory exhaustion
└── Buffer overflow
```

The raw logs determine the actual path.

### Example A --- Request Spamming

Evidence:

``` text
Client
  ↓
Thousands of HTTP requests
  ↓
API endpoint
  ↓
Request queue saturation
  ↓
CPU utilization spike
  ↓
Service becomes unavailable
```

The Triage Agent can conclude:

``` text
DOS → Request Spamming → Resource Exhaustion
```

### Example B --- Buffer Overflow

Evidence could include:

``` text
Malformed payload
      ↓
Application process
      ↓
Stack trace
      ↓
Memory access violation
      ↓
Process crash
      ↓
Service unavailable
```

The resulting path becomes:

``` text
DOS / Availability Impact
      ↓
Memory Corruption
      ↓
Buffer Overflow
      ↓
Process Crash
      ↓
Service Unavailable
```

The exact classification must be derived from evidence rather than
assumed from the QML label.

------------------------------------------------------------------------

# 7.3 TriageResult

The Triage Agent should generate a structured object.

``` json
{
  "incident_id": "INC-001",
  "confirmed_attack": {
    "category": "DOS",
    "mechanism": "REQUEST_SPAMMING",
    "attack_path": [
      "High-volume API requests",
      "Request queue saturation",
      "CPU exhaustion",
      "Service degradation"
    ]
  },
  "confidence": 0.96,
  "timeline": [],
  "affected_assets": [],
  "evidence": [],
  "root_cause_indicators": [],
  "impact": {
    "confidentiality": "NONE",
    "integrity": "NONE",
    "availability": "HIGH"
  }
}
```

------------------------------------------------------------------------

# 8. Step 6 --- Response Agent

The Response Agent receives the output of the Triage Agent.

``` text
TriageResult
      ↓
Response Agent
```

Its responsibility is to determine what operational response should be
taken.

The Response Agent should consider:

-   Confirmed attack type
-   Exact attack mechanism
-   Affected assets
-   Attack path
-   Current system state
-   Observed impact
-   Evidence
-   Severity
-   Required containment
-   Recovery requirements

Example:

``` text
Confirmed:
DOS → Request Spamming → Resource Exhaustion

Response:
1. Rate-limit the affected endpoint
2. Block or restrict the identified malicious source
3. Preserve relevant logs
4. Monitor resource utilization
5. Restore affected service capacity
6. Continue monitoring for repeated requests
```

The response should be tied directly to the confirmed attack path.

------------------------------------------------------------------------

# 9. Step 7 --- Compliance Agent

The Compliance Agent runs after the response analysis.

``` text
ResponseResult
      +
Incident Evidence
      ↓
Compliance Agent
```

The compliance layer is **case-specific**.

The rest of the detection architecture is intended for general
cybersecurity use cases, while the compliance implementation in the
current project is specifically designed for the **healthcare use
case**.

------------------------------------------------------------------------

# 9.1 Healthcare Compliance Analysis

The Compliance Agent determines:

1.  What data was compromised?
2.  Was protected/sensitive healthcare information involved?
3.  Which systems or records were affected?
4.  What type of operation occurred?
    -   Read
    -   Modified
    -   Deleted
    -   Exfiltrated
    -   Unavailable
5.  What was the scope of the exposure?
6.  Does the incident trigger the applicable healthcare compliance
    requirements?
7.  What evidence supports the determination?
8.  What compliance-related actions should be initiated?

The agent should produce an evidence-backed result rather than simply
outputting a compliance label.

------------------------------------------------------------------------

# 9.2 ComplianceResult

``` json
{
  "incident_id": "INC-001",
  "domain": "HEALTHCARE",
  "data_compromised": true,
  "data_types": [
    "Patient Records",
    "Personal Information"
  ],
  "affected_assets": [],
  "exposure_type": "UNAUTHORIZED_ACCESS",
  "compliance_assessment": {
    "status": "REVIEW_REQUIRED",
    "controls_affected": [],
    "evidence": []
  },
  "recommended_compliance_actions": []
}
```

The compliance framework should remain modular so that a future
deployment can replace the healthcare-specific compliance layer with
another regulatory/control framework without changing the general
Detection → Triage → Response pipeline.

------------------------------------------------------------------------

# 10. Step 8 --- CVSS Agent

The CVSS Agent runs **independently in the background**.

It does not block the main agent chain.

``` text
                         ┌── Detection
Logs → QML → Detection ──┼── Triage → Response → Compliance
                         │
                         └── CVSS Agent
```

The CVSS Agent consumes the available incident evidence and calculates
the CVSS v4.0 assessment.

The purpose is to quantify the technical severity based on the
characteristics of the vulnerability/attack and observed impact.

------------------------------------------------------------------------

# 11. CVSS v4.0 Data Extraction

The CVSS Agent should reconstruct the relevant metrics from logs and
post-attack evidence.

## 11.1 Exploitability Metrics

### Attack Vector (AV)

Source:

-   Source IP
-   Network logs
-   PCAP/network evidence
-   Access path

Determine whether exploitation required:

-   Network
-   Adjacent network
-   Local access
-   Physical access

------------------------------------------------------------------------

### Attack Complexity (AC)

Source:

-   Repeated exploit attempts
-   Security-control bypass attempts
-   Race conditions
-   Timing requirements
-   Exploit sequence

Determine whether exploitation was straightforward or required
additional conditions.

------------------------------------------------------------------------

### Attack Requirements (AT)

Determine whether successful exploitation required a specific
prerequisite or system condition.

Example:

``` text
Specific non-default configuration required
→ AT = Present

No special prerequisite
→ AT = None
```

------------------------------------------------------------------------

### Privileges Required (PR)

Inspect:

-   Authentication logs
-   Session information
-   Access tokens
-   User roles
-   Privilege levels

Possible levels:

``` text
Unauthenticated → None
Standard account → Low
Administrative account → High
```

------------------------------------------------------------------------

### User Interaction (UI)

Inspect whether a legitimate user had to perform an action.

Example:

``` text
Automated API exploit
→ UI = None

User must open malicious document
→ UI = Required
```

------------------------------------------------------------------------

# 12. CVSS Impact Metrics

The agent should inspect:

-   Database query logs
-   File integrity monitoring
-   System changes
-   Data access logs
-   Data egress
-   Availability metrics

CVSS v4.0 distinguishes impacts on the vulnerable system from impacts on
subsequent systems.

### Vulnerable-system impact

``` text
VC — Confidentiality
VI — Integrity
VA — Availability
```

### Subsequent-system impact

``` text
SC — Confidentiality
SI — Integrity
SA — Availability
```

------------------------------------------------------------------------

## 12.1 Confidentiality

Evidence sources:

-   Data egress logs
-   Database access logs
-   File access logs
-   API responses

Example interpretation:

``` text
No sensitive data accessed → None
Limited information exposed → Low
Significant sensitive data exposed → High
```

------------------------------------------------------------------------

## 12.2 Integrity

Evidence sources:

-   Database write logs
-   File modification logs
-   Configuration changes
-   System binary changes

Example:

``` text
No modification → None
Limited modification → Low
Critical system/data modification → High
```

------------------------------------------------------------------------

## 12.3 Availability

Evidence sources:

-   CPU utilization
-   Memory utilization
-   Service health
-   Container/process state
-   Uptime monitoring
-   Request latency

Example:

``` text
No service impact → None
Degradation → Low
Major outage / crash → High
```

------------------------------------------------------------------------

# 13. Supplemental CVSS Context

The project can additionally capture the operational context available
from the simulated incident.

Examples include:

### Automatable

Determine whether the observed attack can be repeatedly executed using
automation.

Example evidence:

``` text
Hundreds/thousands of requests per second
→ Automatable = Yes
```

### Recovery

Determine how the affected system recovered.

Possible observed states include:

``` text
Automatic recovery
User intervention required
Permanent/irrecoverable impact
```

These values should be recorded separately from the core attack
evidence.

------------------------------------------------------------------------

# 14. CVSS Execution Flow

``` text
                    ┌──────────────────────┐
                    │ Raw Logs              │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Timeline             │
                    │ Reconstruction       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Evidence Extraction  │
                    └──────────┬───────────┘
                               │
             ┌─────────────────┼─────────────────┐
             ▼                 ▼                 ▼
       Exploitability       Impact          Operational
         Metrics           Metrics            Context
             │                 │                 │
             └─────────────────┼─────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │ CVSS v4.0 Calculator │
                    └──────────┬───────────┘
                               ▼
                    ┌──────────────────────┐
                    │ CVSS Result           │
                    │ Vector + Score        │
                    └──────────────────────┘
```

The CVSS result is eventually attached to the incident record/final
report.

------------------------------------------------------------------------

# 15. Parallelism Model

The main pipeline is sequential:

``` text
Logs
 ↓
Preprocessing
 ↓
QML
 ↓
Detection Agent
 ↓
Triage Agent
 ↓
Response Agent
 ↓
Compliance Agent
```

The CVSS calculation is independent:

``` text
Logs
 ↓
CVSS Agent
 ↓
CVSS Result
```

Therefore:

``` text
                       ┌───────────────→ CVSS Agent
                       │                     │
Logs → QML → Detection ├→ Triage → Response → Compliance
                       │
                       └───────────────→ Incident Evidence
```

The final system combines both outputs:

``` text
Main Agent Pipeline
        +
CVSS Result
        ↓
Final Incident Record
```

------------------------------------------------------------------------

# 16. Shared Incident Object

A common incident identifier should connect all stages.

``` json
{
  "incident_id": "INC-001",
  "raw_logs": {},
  "qml_result": {},
  "detection_result": {},
  "triage_result": {},
  "response_result": {},
  "compliance_result": {},
  "cvss_result": {}
}
```

Each agent should add its result rather than duplicating the entire
dataset unnecessarily.

A better implementation can use typed objects:

``` text
Incident
 ├── RawLogSet
 ├── QMLResult
 ├── DetectionResult
 ├── TriageResult
 ├── ResponseResult
 ├── ComplianceResult
 └── CVSSResult
```

------------------------------------------------------------------------

# 17. UI Execution Logs

Because multiple stages may involve model inference and agent
processing, the UI must expose **live execution status**.

The user should always be able to see what the system is currently
doing.

Example UI:

``` text
┌─────────────────────────────────────────────────────────┐
│ QUAL-KI Agentic SOC                                     │
├─────────────────────────────────────────────────────────┤
│ ✓ Logs received                                         │
│ ✓ Preprocessing logs                                    │
│ ✓ QML model inference completed                        │
│ ✓ Detection Agent completed                            │
│ ⟳ Triage Agent analyzing attack path...                │
│                                                         │
│   ├─ Correlating network events                         │
│   ├─ Checking application logs                          │
│   ├─ Inspecting stack traces                            │
│   └─ Reconstructing attack timeline                     │
│                                                         │
│ ○ Response Agent                                        │
│ ○ Compliance Agent                                      │
│ ⟳ CVSS Agent running in background                     │
└─────────────────────────────────────────────────────────┘
```

------------------------------------------------------------------------

# 18. Required Execution Log Format

Every major operation should emit a structured progress event.

Example:

``` json
{
  "timestamp": "...",
  "incident_id": "INC-001",
  "agent": "triage",
  "stage": "evidence_correlation",
  "status": "running",
  "message": "Correlating network and application logs"
}
```

Completion:

``` json
{
  "timestamp": "...",
  "incident_id": "INC-001",
  "agent": "triage",
  "stage": "evidence_correlation",
  "status": "completed",
  "message": "Evidence correlation completed",
  "duration_ms": 842
}
```

Error:

``` json
{
  "timestamp": "...",
  "incident_id": "INC-001",
  "agent": "triage",
  "stage": "stack_trace_analysis",
  "status": "error",
  "message": "Unable to parse stack trace"
}
```

No fallback should automatically execute after this error.

The error should be surfaced to the UI.

------------------------------------------------------------------------

# 19. UI Status States

Each component should expose one of:

``` text
PENDING
RUNNING
COMPLETED
ERROR
```

Example:

``` text
QML Model       [COMPLETED]
Detection       [COMPLETED]
Triage          [RUNNING]
Response        [PENDING]
Compliance      [PENDING]
CVSS            [RUNNING]
```

The UI should also show elapsed execution time for long-running
operations.

Example:

``` text
Triage Agent
Running for 2.84s
```

This makes model/agent latency visible to the user.

------------------------------------------------------------------------

# 20. No-Fallback Principle

The current implementation intentionally uses a direct execution path.

### Do not implement:

``` text
QML fails
   ↓
Classical ML fallback
```

or:

``` text
Triage fails
   ↓
Rule-based fallback
```

or:

``` text
LLM unavailable
   ↓
Alternative model
```

Instead:

``` text
Component fails
      ↓
ERROR event
      ↓
Display error in UI
      ↓
Preserve available evidence
```

This makes the architecture deterministic and easier to evaluate during
the prototype phase.

------------------------------------------------------------------------

# 21. Agent Responsibilities

  ------------------------------------------------------------------------------
  Component         Primary               Input               Output
                    Responsibility                            
  ----------------- --------------------- ------------------- ------------------
  Preprocessor      Convert raw logs into Raw logs            Features
                    model-ready features                      

  QML Model         Detect                Features            QML result
                    anomalous/threat                          
                    behavior                                  

  Detection Agent   Interpret QML output  QML result          DetectionResult
                    and structure                             
                    incident                                  

  Triage Agent      Confirm attack and    DetectionResult +   TriageResult
                    reconstruct exact     raw logs            
                    path                                      

  Response Agent    Determine operational TriageResult        ResponseResult
                    response                                  

  Compliance Agent  Assess                Incident evidence + ComplianceResult
                    healthcare-specific   response            
                    compliance impact                         

  CVSS Agent        Calculate CVSS v4.0   Logs + attack       CVSSResult
                    assessment            evidence            

  UI Logger         Show live system      Agent events        User-visible
                    progress                                  execution log
  ------------------------------------------------------------------------------

------------------------------------------------------------------------

# 22. Example Complete Execution

Consider a simulated DoS incident.

### Input

``` text
API and system logs
```

### QML

``` text
Prediction: DOS
Confidence: 94%
```

### Detection Agent

Creates:

``` text
DetectionResult
Attack category = DOS
Confidence = 94%
Affected endpoint = /api/patient
```

### Triage Agent

Reads the original logs and discovers:

``` text
10,000+ requests/minute
       ↓
Same endpoint
       ↓
Request queue saturation
       ↓
CPU spike
       ↓
API latency increases
       ↓
Service becomes unavailable
```

Therefore:

``` text
Confirmed attack:
DOS

Exact mechanism:
Request Spamming

Attack path:
Request Flooding
→ Queue Saturation
→ Resource Exhaustion
→ Service Unavailability
```

### Response Agent

Produces actions such as:

``` text
Rate limit endpoint
Block malicious source
Preserve evidence
Restore service
Monitor recurrence
```

### Compliance Agent

For healthcare:

``` text
Check whether patient data was accessed
Check whether protected healthcare information was exposed
Determine affected systems/records
Map evidence to applicable healthcare controls
Generate compliance actions
```

### CVSS Agent

Independently evaluates:

``` text
Attack Vector
Attack Complexity
Attack Requirements
Privileges Required
User Interaction
Confidentiality
Integrity
Availability
Subsequent-system impacts where applicable
Operational context
```

and produces:

``` text
CVSS Vector
CVSS Score
Supporting evidence
```

------------------------------------------------------------------------

# 23. Final Incident Output

The final incident view should combine the outputs.

``` text
┌──────────────────────────────────────────────────────────┐
│ INCIDENT INC-001                                         │
├──────────────────────────────────────────────────────────┤
│ Detection                                                │
│ DOS — 94% QML confidence                                │
│                                                          │
│ Triage                                                   │
│ Request Spamming → Queue Saturation → Resource Exhaust. │
│                                                          │
│ Response                                                 │
│ Rate limit + block source + preserve evidence            │
│                                                          │
│ Compliance                                               │
│ Healthcare data exposure assessment                      │
│                                                          │
│ CVSS                                                     │
│ Vector: <generated vector>                               │
│ Score: <generated score>                                 │
│                                                          │
│ Evidence                                                 │
│ • Network logs                                           │
│ • API logs                                               │
│ • Resource metrics                                       │
│ • Application events                                     │
└──────────────────────────────────────────────────────────┘
```

------------------------------------------------------------------------

# 24. Core Design Principles

1.  **QML is the first detection layer.**
2.  **Detection Agent converts QML output into structured incident
    information.**
3.  **Triage Agent gets both the structured detection result and
    original logs.**
4.  **Triage determines the exact technical attack path using
    evidence.**
5.  **Response Agent acts on the confirmed triage result.**
6.  **Compliance is case-specific; the current implementation targets
    healthcare.**
7.  **CVSS Agent operates independently in the background.**
8.  **Original logs remain available throughout the investigation.**
9.  **Every long-running operation emits live UI progress logs.**
10. **No automatic fallback logic is implemented in this version.**
11. **Every stage produces a structured, traceable result.**
12. **A shared incident ID maintains correlation across all agents.**
13. **Evidence should be retained alongside conclusions so the SOC
    analyst can understand why an agent reached a result.**
14. **The system should expose execution time for computationally
    expensive stages.**

------------------------------------------------------------------------

# 25. Target Flow

The final intended architecture is:

``` text
                         RAW SECURITY LOGS
                                │
                                ▼
                         PREPROCESSING
                                │
                                ▼
                          QML MODEL
                                │
                                ▼
                       DETECTION AGENT
                                │
                    DetectionResult Object
                                │
             ┌──────────────────┴──────────────────┐
             │                                     │
             ▼                                     ▼
       TRIAGE AGENT                           CVSS AGENT
             │                              (Background)
      DetectionResult                            │
             +                                   │
        Original Logs                            │
             │                                   │
             ▼                                   │
       TRIAGE RESULT                             │
             │                                   │
             ▼                                   │
      RESPONSE AGENT                             │
             │                                   │
             ▼                                   │
     RESPONSE RESULT                             │
             │                                   │
             ▼                                   │
    COMPLIANCE AGENT                             │
   (Healthcare-specific)                         │
             │                                   │
             └──────────────────┬────────────────┘
                                ▼
                       FINAL INCIDENT REPORT
                                │
                                ▼
                           SOC DASHBOARD
```

This is the baseline flow for the revised **QUAL-KI Agentic SOC**
implementation.
