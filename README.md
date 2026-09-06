# DNSentinel — DNS Threat Detection & SOC Platform

[![CI](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/codeql.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue)](backend/requirements.txt)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-lightgrey)](LICENSE)

> An end-to-end pipeline that detects DNS-based threats — **DGA domains, DNS
> tunneling, and data exfiltration** — from network tap to analyst dashboard.
> A Zeek sensor and a Chrome extension feed a FastAPI + scikit-learn service
> that scores each query, streams alerts over SSE, and drives SOAR-style
> containment with a human in the loop.

**Live demo:** [dns-sentinel.vercel.app](https://dns-sentinel.vercel.app) ·
**Model metrics:** [MODEL_CARD.md](MODEL_CARD.md) ·
**Reproduce them:** [`python -m backend.evaluate`](#reproducible-evaluation)

---

## Overview

DNSentinel classifies DNS traffic in real time to surface threats like DGA
(Domain Generation Algorithm) activity, DNS tunneling, and exfiltration. It is
built as three integrated tiers plus a network sensor:

| Component | Technology | Purpose |
| --- | --- | --- |
| **Zeek sensor** | Zeek scripting *(third-party, attributed)* | Line-rate DNS-exfiltration signals from network taps |
| **Backend API** | Python · FastAPI · scikit-learn | Feature extraction, ML inference, SSE streaming, SOAR, PDF reports |
| **SOC dashboard** | Vite · React · Recharts | Analyst triage, topology, threat hunting, containment audit |
| **Chrome extension** | Manifest V3 | Browser-level DNS telemetry capture |

> **Attribution:** the Zeek `exfil_detect` sensor is a reused open-source
> package (BSD-3, (c) saiiman), vendored unmodified under
> `vendor/zeek-exfil-detect/` and integrated as the tap tier — see
> [THIRD_PARTY.md](THIRD_PARTY.md). Everything outside `vendor/` is original.

---

## Key Features

**Detection**
- 22-feature vector per query: Shannon entropy, English-bigram likelihood,
  character-run statistics, label depth, digit/consonant ratios, and derived
  complexity terms (`backend/features.py`).
- Ensemble of a supervised **Random Forest**, an unsupervised **Isolation
  Forest** anomaly detector, and an **optional** character-level DL DGA scorer
  that is skipped gracefully when `torch` isn't installed.
- Adaptive risk engine with `mean + k·σ` statistical baselining, tunable via
  YAML weights without code changes.

**SOC dashboard**
- Live triage feed (risk index, threat tier, origin IP), force-directed
  topology map, behavioral threat hunter, and a containment-audit view of
  active SOAR rules.
- SSE live streaming with automatic reconnect; `/` focuses the search bar.

**Response (SOAR)**
- Generates firewall/sinkhole rules with **24-hour auto-expiry** to prevent
  network disruption, plus a human-in-the-loop false-positive feedback loop.

**Forensics**
- Per-alert PDF incident reports with SHAP feature attribution; full audit
  ledger exportable to CSV for SIEM ingestion.

---

## Model Performance (measured, reproducible)

All numbers below are produced by `backend/evaluate.py` — **not** hand-typed —
and never evaluate on the training set. Full methodology in
[MODEL_CARD.md](MODEL_CARD.md).

**In-distribution (stratified 80/20 hold-out & 5-fold CV):**

| Dataset | Accuracy | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| Exfiltration (n=700) | 1.000 | 1.000 | 1.000 | 1.000 |
| DGA (n=1,000) | 0.997 | 0.994 | 1.000 | 0.997 |

> **Read these honestly.** The bundled datasets are small and near-linearly
> separable — an *entropy-only depth-1 stump* already scores F1 ≈ 0.99. So
> ~100% here reflects **dataset simplicity, not production accuracy.** The
> number that actually matters is generalization:

**Cross-dataset generalization (train on one set, test on the other):**

| Train → Test | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | --- | --- | --- | --- | --- |
| Exfil → DGA | 0.593 | **0.551** | 1.000 | 0.711 | 0.988 |
| DGA → Exfil | 0.924 | 1.000 | 0.849 | 0.918 | 1.000 |

Under distribution shift precision drops to **0.55** (407 false positives) —
and in a SOC, false-positive rate, not accuracy, governs analyst alert fatigue.
Closing that gap (public benchmarks, per-DGA-family recall, threshold
calibration) is the documented roadmap.

**Family-stratified benchmark (12,000 domains, 4 DGA families — see [BENCHMARK.md](BENCHMARK.md)):**

| View | Precision | Recall | F1 | ROC-AUC |
| --- | --- | --- | --- | --- |
| Cross-domain (bundled → benchmark) | 0.70 | 0.92 | 0.79 | 0.92 |
| In-benchmark (80/20 split) | 0.96 | 0.83 | 0.89 | 0.94 |

Per-family recall exposes the honest frontier: **random / arithmetic / hex DGAs = 1.00**,
but **dictionary DGAs = 0.67** and benign false-positives are high when trained only on the
small bundled set — a training-data coverage gap (precision recovers to 0.96 once trained on
representative data). Reproduce and read the full analysis in [BENCHMARK.md](BENCHMARK.md).

**Operating point (threshold calibration).**

A 0.5 decision threshold is a library default, not an operating point. Selecting
it against an explicit false-positive budget instead (`backend/calibrate.py`)
changes the picture in both directions:

| Direction | Threshold | FPR | Recall | Precision | False positives |
| --- | --- | --- | --- | --- | --- |
| Exfil → DGA, default | 0.503 | 0.814 | 1.000 | 0.551 | 407 |
| Exfil → DGA, 5% budget | 0.873 | 0.042 | 1.000 | 0.960 | **21** |
| DGA → Exfil, default | 0.501 | 0.000 | 0.849 | 1.000 | 0 |
| DGA → Exfil, 1% budget | 0.096 | 0.000 | **1.000** | 1.000 | 0 |

The same detection rate for 21 false positives instead of 407, and in the other
direction 53 recovered detections that the default threshold was discarding. The
default was wrong in both directions, in opposite ways, which is what an
uncalibrated cut point usually is.

A 1% budget is *not* reachable in the exfil → DGA direction: the tightest
achievable FPR is 0.020. The calibrator reports that rather than widening the
budget to produce a number, because a threshold that cannot meet a constraint is
a data problem, not a tuning problem.

```bash
python -m backend.calibrate --dataset data/dns_exfiltration_dataset.csv \
    --cross backend/dga_dataset.csv --max-fpr 0.05 --write
```

**What these numbers do not show.** Every figure above is measured on curated or
synthetic corpora, scored by the same feature extractor that was designed
against them. They demonstrate that the pipeline is reproducible, that its
failure modes are located, and that its operating point is chosen rather than
inherited. They are not evidence of performance on live enterprise traffic,
where DGA families absent from these sets and encrypted transports (DoH/DoT,
which defeat query-string features entirely) would both appear.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  SENSOR TIER                                                   │
│  Zeek exfil_detect  ─┐        Chrome Extension (MV3)           │
│  (network tap)       │        (browser DNS telemetry)          │
└──────────────────────┼───────────────┬───────────────────────┘
        ingest_zeek.py │               │ HTTP / SSE
┌──────────────────────▼───────────────▼───────────────────────┐
│  FASTAPI BACKEND  (localhost:8001)                            │
│  ┌────────────┐  ┌────────────┐  ┌────────────────┐           │
│  │ Feature +  │  │ RiskEngine │  │ SOAR           │           │
│  │ ML Ensemble│  │ (adaptive) │  │ (block/sinkhole)│          │
│  └─────┬──────┘  └─────┬──────┘  └────────────────┘           │
│  ┌─────▼───────────────▼──────────────────────────┐          │
│  │   SQLite: dns_logs · security_rules · cases      │          │
│  └──────────────────────────────────────────────────┘         │
└──────────────────────────────┬───────────────────────────────┘
                               │ SSE
                    React SOC Dashboard (Vite, :5173)
```

---

## Quick Start

**Prerequisites:** Python 3.10+, Node.js 18+, Google Chrome (for the extension).

```bash
git clone https://github.com/rahulpaul-07/DNS_SENTINEL.git
cd DNS_SENTINEL

# 1) Backend
cd backend
pip install -r requirements.txt          # add: -r requirements-ml.txt for the DL DGA model
python -m uvicorn main:app --host 127.0.0.1 --port 8001

# 2) Frontend (new terminal)
cd frontend && npm install && npm run dev # http://localhost:5173

# 3) Chrome extension
# chrome://extensions → Developer Mode → Load Unpacked → select extension/
```

---

## Reproducible Training

Models are **generated, not committed** — regenerate them deterministically
(seed=42) along with a `metrics.json` provenance manifest (dataset SHA-256,
library versions, hyperparameters, held-out metrics):

```bash
python -m backend.train                                 # bundled exfil dataset
python -m backend.train --dataset backend/dga_dataset.csv
```

Artifacts land in `backend/models/` (see [`backend/models/README.md`](backend/models/README.md)).
The backend also auto-trains on first request if the directory is empty.

## Reproducible Evaluation

```bash
# Honest hold-out + 5-fold CV + cross-dataset generalization
python -m backend.evaluate --dataset data/dns_exfiltration_dataset.csv --cross backend/dga_dataset.csv
python -m backend.evaluate --dataset backend/dga_dataset.csv         --cross data/dns_exfiltration_dataset.csv --plot
```

## Tests & CI

```bash
cd backend && pip install pytest && pytest -q     # feature, risk-engine, ML-contract tests
cd frontend && npm run build                       # verifies the dashboard build
```

Both suites run on every push and PR — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## API Reference

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Liveness probe (returns 503 when the DB is degraded) |
| `GET` | `/version` | App name and version |
| `POST` | `/analyze` | Analyze a single DNS query |
| `GET` | `/stream` | SSE live telemetry stream |
| `GET` | `/alerts` | Paginated alert history |
| `GET` | `/traffic` | Recent traffic log |
| `GET` | `/stats` | Dashboard statistics |
| `POST` | `/upload` | Ingest a CSV dataset (bulk analysis) |
| `POST` | `/train` | Retrain the model on uploaded data |
| `POST` | `/archive` | Clear the active forensic ledger (new case) |
| `GET` | `/export` · `/export/pdf` | Export the audit log as CSV / PDF |
| `GET` | `/alerts/{id}/pdf` | Per-alert PDF report |
| `POST` | `/alerts/{id}/block` · `/alerts/{id}/feedback` | SOAR block · mark false positive |
| `GET` | `/blocked` | List active SOAR blocks |

---

## Threat Coverage (MITRE ATT&CK)

| Threat class | Detection approach | ATT&CK |
| --- | --- | --- |
| DGA domains | Entropy + bigram likelihood + n-gram ML | T1568.002 |
| DNS tunneling | Label-depth + query-rate + throughput | T1071.004 |
| Data exfiltration | Encoded-payload estimation + Zeek baselining | T1048 |
| C2 beaconing | Interval-regularity analysis | T1071.004 |

---

## Tech Stack

**Backend** Python · FastAPI · Uvicorn · SQLAlchemy · SQLite ·
**ML** scikit-learn (Random Forest, Isolation Forest) · NumPy · Pandas · SHAP ·
**Frontend** React 18 · Vite · Recharts ·
**Extension** Chrome Manifest V3 ·
**Sensor** Zeek *(attributed, BSD-3)* ·
**Streaming** Server-Sent Events ·
**Reports** fpdf2

---

## Repository Layout

```
backend/     FastAPI service, feature extractor, ML ensemble, risk engine, SOAR
             evaluate.py   reproducible hold-out / cross-dataset metrics
             calibrate.py  threshold selection against an FPR budget
             benchmarks/   family-stratified DGA benchmark harness
frontend/    React + Vite SOC dashboard
extension/   Chrome MV3 DNS telemetry capture + native-messaging host
data/        Bundled datasets and sample captures
tools/       Standalone scripts (public-corpus benchmark, service demos)
docs/        Generated figures
vendor/      Third-party components, unmodified — see THIRD_PARTY.md
             zeek-exfil-detect/  Zeek DNS-exfiltration sensor (BSD-3, (c) saiiman)
```

---

## License & Attribution

BSD 3-Clause — see [LICENSE](LICENSE). Third-party components are credited in
[THIRD_PARTY.md](THIRD_PARTY.md).

---

*DNSentinel — detection, response, and forensics for the DNS layer.*
