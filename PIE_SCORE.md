# Priority Intelligence Engine (PIE) Score

The **Priority Intelligence Engine (PIE)** is a core threat triage component of **DNSentinel**. Unlike static threat engines that only compute the probability of a domain being malicious, PIE is an **actionability and prioritization framework**. It translates raw detection probabilities (ML scores) along with threat intelligence feeds, behavioral analytics, asset criticality, and attack category tags into a single normalized **PIE Score (0–100)** and a matching SOC priority level.

---

## Table of Contents
1. [Core Philosophy](#core-philosophy)
2. [Mathematical Formulation](#mathematical-formulation)
3. [Input Vectors & Configurable Weights](#input-vectors--configurable-weights)
4. [Triage Priorities & Response Actions](#triage-priorities--response-actions)
5. [Contextual Explainability Engine](#contextual-explainability-engine)
6. [Dual-Tier Deployment Architecture](#dual-tier-deployment-architecture)
   - [Server-Side FastAPI Engine (`pie_engine.py`)](#1-server-side-fastapi-engine-pie_enginepy)
   - [Client-Side Chrome Extension (`heuristics.js`)](#2-client-side-chrome-extension-heuristicsjs)
7. [Why PIE Matters: Risk vs. Actionability](#why-pie-matters-risk-vs-actionability)

---

## Core Philosophy

In a high-throughput Security Operations Center (SOC), security analysts are plagued by alert fatigue. A raw Machine Learning model might flag a DNS query as having a `90%` probability of being a DGA domain. However:
- If that query originated from an isolated sandbox machine with an asset value of `10/100`, the priority is **low**.
- If that query originated from a domain-controller with an asset value of `100/100` and threat intelligence confirms active C2 beaconing on that domain, the priority is **CRITICAL**.

> [!IMPORTANT]
> **Risk Score $\neq$ SOC Priority.**
> *Risk* is the likelihood that a particular activity is malicious. *SOC Priority* is the urgency with which a security analyst must contain the host. PIE bridges this gap.

```mermaid
graph TD
    A[Incoming DNS Query] --> B[Feature Extraction & Parsing]
    B --> C[ML Classifier / Local Heuristics]
    B --> D[Threat Intel Feeds]
    B --> E[Asset Directory Lookup]
    B --> F[Host Behavioral Analytics]

    C -->|Raw Risk Score| G[Priority Intelligence Engine]
    D -->|Intel Hit / Reputation| G
    E -->|Asset Criticality Value| G
    F -->|Query Rate Anomaly| G

    G --> H{PIE Formula Calculation}
    H -->|">= 85"| I[CRITICAL: Immediate SOAR Blocking & Isolation]
    H -->|">= 70"| J[HIGH / BLOCK: High Priority Alert Queue]
    H -->|">= 50"| K[MEDIUM / ALERT: Standard Alert Triage Feed]
    H -->|"< 50"| L[LOW / MONITOR: Passive Auditing & Baseline Logging]
```

---

## Mathematical Formulation

The PIE Score is calculated as a bounded weighted sum of five key security dimensions. The result is strictly mapped to the interval $[0, 100]$.

$$\text{PIE Score} = \min\left(\max\left(\sum_{i=1}^{n} W_i \cdot S_i, \; 0\right), \; 100\right)$$

Where:
- $W_i$ represents the configurable weight of a dimension.
- $S_i$ represents the raw score of that dimension.

Expanding this to our five active system dimensions:

$$\text{PIE Score} = W_{\text{risk}} \cdot S_{\text{risk}} + W_{\text{intel}} \cdot S_{\text{intel}} + W_{\text{asset}} \cdot S_{\text{asset}} + W_{\text{behavior}} \cdot S_{\text{behavior}} + W_{\text{attack}} \cdot S_{\text{attack\_type}}$$

---

## Input Vectors & Configurable Weights

The engine utilizes the following weights (defined in [pie_engine.py](backend/pie_engine.py)):

| Dimension Name | Constant / Config | Default Weight | Description |
| :--- | :---: | :---: | :--- |
| **Risk Score** ($S_{\text{risk}}$) | `risk_score` | **0.35** | Raw ML model prediction probability ($0 \text{ to } 100$). Measures statistical structural anomalies. |
| **Threat Intel** ($S_{\text{intel}}$) | `intel_score` | **0.25** | Reputation feed scoring (VirusTotal, AbuseIPDB) indicating known malicious signatures or IPs. |
| **Asset Value** ($S_{\text{asset}}$) | `asset_value` | **0.20** | Criticality index of the originating host ($0 \text{ to } 100$). Servers/Domain Controllers hold higher default values. |
| **Behavior Score** ($S_{\text{behavior}}$) | `behavior_score` | **0.10** | Statistical anomalies observed over a sliding time window (e.g., sudden burst in query rates). |
| **Attack Weight** ($S_{\text{attack\_type}}$) | `attack_weight` | **0.10** | Boost weight determined by the classified attack type. |

### Attack Type Severity Scale ($S_{\text{attack\_type}}$)

Different kinds of DNS threats present differing levels of impact. The engine dynamically maps the threat category output into a base score:

* **Exfiltration** ($90/100$): Highest severity. Indicates active, outbound intellectual property/data loss.
* **Tunneling** ($70/100$): High severity. Indicates bypass of security policy via DNS encapsulations (potential active remote C2 shell).
* **DGA (Domain Generation Algorithm)** ($40/100$): Medium severity. Suggests malware beaconing attempts.
* **Normal / Benign** ($0/100$): Standard, expected network behavior.

---

## Triage Priorities & Response Actions

Once the final score is calculated, it is mapped to a priority tier. Each tier triggers specific platform policies:

```
┌────────────────────────────────────────────────────────────────────────┐
│                                                                        │
│  [85 - 100]  CRITICAL  ──▶ Auto-Containment / SOAR Firewall Block│
│                                                                        │
│  [70 - 84]   HIGH      ──▶ Analyst Alert Feed + DNS Sinkholing      │
│                                                                        │
│  [50 - 69]   MEDIUM    ──▶ Triage Queue + SIEM Correlative Auditing │
│                                                                        │
│  [0 - 49]    LOW       ──▶ Passive Monitoring                       │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

| Score Range | Priority Level | UI/Analyst Action | Automatic SOAR Playbook |
| :---: | :---: | :--- | :--- |
| **$\ge 85$** | **CRITICAL** | Red badge in Triage Feed. Immediate workstation popup. | **Auto-block** originating IP via generated firewall/sinkhole rules (24h auto-expiry). Restrict network egress. |
| **$70 \text{ to } 84$** | **HIGH** | Orange badge. Prioritized in analyst workbook. | **DNS Sinkholing** for the targeted domain (redirects to loopback `127.0.0.1`). |
| **$50 \text{ to } 69$** | **MEDIUM** | Yellow badge. Appears in standard SOC feed. | Queue for human-in-the-loop audit. Log parameters for ML retraining cycles. |
| **$< 50$** | **LOW / MONITOR** | Green badge. Filtered from primary triage list. | Allowed. Logged inside SQLite table (`dns_logs`) for baseline reference. |

---

## Contextual Explainability Engine

A crucial feature of PIE is its **human-readable explainability string**. SOC analysts must know *why* an alert was prioritized. The engine matches specific conditions to append descriptive context:

- **Criticality Trigger**: If the priority evaluates to `CRITICAL`, it adds `"Immediate containment required."`
- **Threat Intel Hit**: If the `intel_score > 80`, it appends `"Confirmed threat intelligence hit."`
- **Asset Criticality**: If the target host has `asset_value > 80`, it appends `"High-value asset target."`

### Example Explanations
* `"PIE Score 92.5 (CRITICAL). Immediate containment required. Confirmed threat intelligence hit. High-value asset target."`
* `"PIE Score 74.0 (HIGH). Confirmed threat intelligence hit."`
* `"PIE Score 24.5 (LOW)."`

---

## Dual-Tier Deployment Architecture

PIE is implemented in two distinct layers of the DNSentinel workspace, ensuring continuous security posture even when offline or operating in localized extension mode:

### 1. Server-Side FastAPI Engine (`pie_engine.py`)
Deployed in the python backend [pie_engine.py](backend/pie_engine.py), it leverages Python classes to handle fully telemetry-backed computations:

```python
class PriorityIntelligenceEngine:
    def __init__(self):
        self.weights = {
            "risk_score": 0.35,
            "intel_score": 0.25,
            "asset_value": 0.20,
            "behavior_score": 0.10,
            "attack_weight": 0.10
        }
        self.attack_type_weights = {
            "DGA": 40,
            "tunneling": 70,
            "exfiltration": 90,
            "normal": 0
        }

    def calculate_priority(self, risk_score, intel_score=0, asset_value=50, behavior_score=0, attack_type="normal"):
        attack_weight = self.attack_type_weights.get(attack_type, 0)

        pie_score = (
            (self.weights["risk_score"] * risk_score) +
            (self.weights["intel_score"] * intel_score) +
            (self.weights["asset_value"] * asset_value) +
            (self.weights["behavior_score"] * behavior_score) +
            (self.weights["attack_weight"] * attack_weight)
        )

        pie_score = min(max(pie_score, 0), 100)

        if pie_score >= 85: priority = "CRITICAL"
        elif pie_score >= 70: priority = "HIGH"
        elif pie_score >= 50: priority = "MEDIUM"
        else: priority = "LOW"

        explanation = self._generate_explanation(pie_score, priority, intel_score, asset_value)
        return {
            "severity": risk_score,
            "priority_score": round(pie_score, 2),
            "priority": priority,
            "explanation": explanation
        }
```

### 2. Browser extension (`heuristics.js`)

The extension computes an immediate local score in its service worker
([heuristics.js](extension/background/heuristics.js)) before the API's ML
verdict arrives. It uses the same five PIE weights, with every input derived
from observed data:

| Input | Local source |
|---|---|
| Structural risk | `12 x entropy + min(length, 20) + 35 x digit_ratio`, capped at 100 |
| Intel | The backend's local heuristics: +20 for a risky TLD, +25 per tunnelling-tool keyword |
| Behaviour | Distinct subdomains of the same zone in a 30 s window: 30 for a structured burst, 15 for high velocity |
| Asset value | 60 (a standard workstation) |
| Attack weight | 40 when entropy > 4.2 or length > 25 (DGA-like), else 0 |

The function is deterministic: the same browsing always produces the same
scores. When the API is reachable, its verdict replaces the local one.

---

## Why PIE Matters: Risk vs. Actionability

Traditional security systems present SOC teams with a flat list of anomaly probabilities. If a system gets 10,000 queries per second, a 0.1% false-positive rate produces **10 alerts per second**. By adjusting the classification logic through the **PIE scoring framework**, DNSentinel:
1. **Reduces Noise**: Demotes low-criticality assets even if the domain is slightly unusual.
2. **Orders the queue**: PIE decides what an analyst looks at first. Automatic containment is separate: it is triggered by the risk score (> 80), creates a rule that expires after 24 h, and runs in dry-run mode unless explicitly enabled.
3. **Improves Analyst Trust**: Provides transparent, deterministic logic showing precisely how the priority score was derived.
