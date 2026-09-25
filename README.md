# DNSentinel: DNS Threat Detection & Response

[![CI](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/rahulpaul-07/dns-sentinel/actions/workflows/codeql.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue)](backend/requirements.txt)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-lightgrey)](LICENSE)

> An end-to-end pipeline that detects DNS-based threats (**DGA domains, DNS
> tunnelling and data exfiltration**) from sensor to analyst. Zeek logs, a
> browser extension or a live sniffer feed a FastAPI + scikit-learn service
> that scores every query, streams results to a React dashboard over SSE, and
> drives SOAR-style containment with automatic expiry and a human in the loop.

**Live demo:** [dns-sentinel.vercel.app](https://dns-sentinel.vercel.app) ·
**Design:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
**Model metrics:** [MODEL_CARD.md](MODEL_CARD.md) ·
**Benchmark:** [BENCHMARK.md](BENCHMARK.md)

---

## Highlights

- **22-feature lexical model.** Shannon entropy, English-bigram likelihood,
  character-run statistics and label structure (`backend/features.py`) feed a
  Random Forest, with an Isolation Forest for outliers and SHAP attribution
  for every flagged query.
- **Calibrated operating point.** The decision threshold is chosen against an
  explicit false-positive budget (`backend/calibrate.py`) and loaded by the
  API. On the cross-dataset shift it cuts false positives **from 407 to 21 at
  the same recall**. `GET /model` reports the threshold in use.
- **Risk engine with sound semantics.** ML, behaviour and intel blend into a
  0-100 score. Absolute tiers always hold, and per-host `mean + 2σ`
  baselining can escalate a tier but never suppress one.
- **Safe-by-default SOAR.** Block and sinkhole rules auto-expire after 24 h,
  infrastructure is whitelisted, enforcement is dry-run unless enabled, and
  targets are validated before they reach `iptables`/`netsh`.
- **Real ingestion paths.** Header-driven Zeek `dns.log` parsing (upload or
  CLI replay), a Manifest V3 browser extension, and an opt-in scapy sniffer.
- **Analyst workflow.** Live triage feed, topology map, intel-driven hunting
  view, containment ledger, Markdown/PDF incident reports, and a CSV export
  hardened against formula injection.
- **Tested and reproducible.** 69 backend tests (API, SOAR lifecycle,
  calibration, metric drift against this README), seeded training with a
  provenance manifest, and CI covering lint, tests, calibration and all three
  builds.

---

## Architecture

```
┌────────────────────────── SENSORS ──────────────────────────┐
│  Zeek dns.log        Browser extension (MV3)   scapy sniffer │
│  (upload / replay)   (per-domain scoring)      (opt-in)      │
└──────────┬──────────────────────┬─────────────────┬──────────┘
           │ POST /upload         │ POST /analyze   │
┌──────────▼──────────────────────▼─────────────────▼──────────┐
│ FASTAPI  validate ─► features ─► RF + IsoForest (+DL) ─► risk │
│          ─► MITRE / PIE ─► SQLite ledger ─► SOAR (24h expiry) │
└──────────────────────────────┬────────────────────────────────┘
                               │ Server-Sent Events
                    React SOC dashboard (Vite)
```

The request lifecycle and the reasoning behind each design choice are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

> **Attribution:** the Zeek `exfil_detect` sensor is a reused open-source
> package (BSD-3, (c) saiiman), vendored unmodified under
> `vendor/zeek-exfil-detect/`. See [THIRD_PARTY.md](THIRD_PARTY.md).
> Everything outside `vendor/` is original to this project.

---

## Quick start

**Prerequisites:** Python 3.10+, Node.js 20.19+ (or 22.12+).

```bash
git clone https://github.com/rahulpaul-07/dns-sentinel.git
cd dns-sentinel

# 1) Backend  ->  http://127.0.0.1:8001/docs
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn main:app --port 8001

# 2) Dashboard (new terminal)  ->  http://localhost:5173
cd frontend && npm install && npm run dev
```

Then click **Stream Ingest** and upload `data/samples/dns.log`, or type a
domain into **Analyze a Query**. Models are trained automatically on first
use; run `python -m backend.train` from the repo root to regenerate them
explicitly.

**Docker** (API and dashboard behind nginx, same origin):

```bash
docker compose up --build        # dashboard on http://localhost:8080
```

**Browser extension:** `cd extension && npm install && npm run build`, then
load `extension/dist/` via `chrome://extensions` → Developer mode → *Load
unpacked*. See [extension/INSTALL.md](extension/INSTALL.md).

**Replay a Zeek log against a running API:**

```bash
python backend/ingest_zeek.py data/samples/dns.log --delay 0.5
```

---

## Model performance (measured, reproducible)

Every number below is produced by `backend/evaluate.py` or
`backend/calibrate.py`, never on the training set, and
`backend/tests/test_metric_drift.py` fails CI if they stop reproducing.

**In-distribution (stratified 80/20 hold-out & 5-fold CV):**

| Dataset | Accuracy | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| Exfiltration (n=700) | 1.000 | 1.000 | 1.000 | 1.000 |
| DGA (n=1,000) | 0.997 | 0.994 | 1.000 | 0.997 |

> **Read these honestly.** The bundled datasets are small and near-linearly
> separable (an *entropy-only depth-1 stump* already scores F1 ≈ 0.99), so
> ~100% reflects dataset simplicity, not production accuracy. The number that
> matters is generalisation:

**Cross-dataset generalisation (train on one set, test on the other):**

| Train → Test | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | --- | --- | --- | --- | --- |
| Exfil → DGA | 0.593 | **0.551** | 1.000 | 0.711 | 0.988 |
| DGA → Exfil | 0.924 | 1.000 | 0.849 | 0.918 | 1.000 |

Ranking quality survives the shift (AUC ≥ 0.99), but at the default 0.5
threshold precision collapses to 0.55: **407 false positives**. In a SOC,
false-positive rate, not accuracy, drives alert fatigue.

**Operating point (threshold calibration):**

| Direction | Threshold | FPR | Recall | Precision | False positives |
| --- | --- | --- | --- | --- | --- |
| Exfil → DGA, default | 0.503 | 0.814 | 1.000 | 0.551 | 407 |
| Exfil → DGA, 5% budget | **0.873** | 0.042 | 1.000 | 0.960 | **21** |
| DGA → Exfil, default | 0.501 | 0.000 | 0.849 | 1.000 | 0 |
| DGA → Exfil, 1% budget | 0.096 | 0.000 | **1.000** | 1.000 | 0 |

The default threshold was wrong in both directions, in opposite ways. A 1%
budget is *not* reachable in the exfil → DGA direction (the tightest achievable
FPR is 0.020), and the calibrator reports that instead of widening the budget.
The API serves the 0.873 operating point.

```bash
python -m backend.calibrate --dataset data/dns_exfiltration_dataset.csv \
    --cross backend/dga_dataset.csv --max-fpr 0.05 --write
```

**Family-stratified benchmark** (12,000 domains, 4 DGA families; see
[BENCHMARK.md](BENCHMARK.md)):

| View | Precision | Recall | F1 | ROC-AUC |
| --- | --- | --- | --- | --- |
| Cross-domain (bundled → benchmark) | 0.70 | 0.92 | 0.79 | 0.92 |
| In-benchmark (80/20 split) | 0.96 | 0.83 | 0.89 | 0.94 |

Random, arithmetic and hex DGAs reach recall 1.00; **dictionary DGAs reach
0.67**, the honest frontier for purely lexical features.

**What these numbers do not show.** They come from curated or synthetic
corpora scored by a feature extractor designed against them. They show the
pipeline is reproducible, its failure modes are located, and its operating
point is chosen rather than inherited. They are not evidence of performance on
live enterprise traffic, where unseen DGA families and encrypted transports
(DoH/DoT, which defeat query-string features entirely) would both appear.

---

## API

Interactive docs at `/docs`. Endpoints marked 🔒 require `X-API-Key` when the
backend runs with `API_KEY` set.

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` · `/version` | Liveness (503 if the DB is down) and version |
| `GET` | `/model` | Threshold in use, DL-scorer status, training provenance |
| `POST` | `/analyze` | Score one query: `{"query", "source_ip", "qtype"}` |
| `GET` | `/stream` | Server-Sent Events feed of every scored query |
| `GET` | `/traffic` · `/alerts` · `/stats` | Recent queries, filtered alerts (`risk_level`, `limit`, `offset`), aggregates |
| `POST` 🔒 | `/upload` | Ingest a Zeek `dns.log` or CSV in the background |
| `POST` 🔒 | `/train` | Retrain on a labelled CSV (`query`/`domain`, `label`) |
| `POST` 🔒 | `/archive` | Start a new case (clear the ledger and rules) |
| `POST` 🔒 | `/alerts/{id}/block` · `/alerts/{id}/feedback` | Block the source IP · mark a false positive |
| `POST` 🔒 | `/unblock/{entity}` | Revoke an active rule |
| `GET` | `/blocked` | Active SOAR rules |
| `GET` | `/alerts/{id}/report` · `/alerts/{id}/pdf` | Incident report (Markdown / PDF) |
| `GET` | `/export/alerts.csv` · `/export/pdf` | Ledger as CSV (streamed) / PDF audit |

```bash
curl -s -X POST http://127.0.0.1:8001/analyze -H 'content-type: application/json' \
  -d '{"query":"a1b2c3d4e5f6.t.dnscat-tunnel.xyz","source_ip":"10.0.0.7"}'
```

---

## Configuration

Copy [.env.example](.env.example) to `backend/.env`. All settings have safe
defaults.

| Variable | Default | Purpose |
| --- | --- | --- |
| `API_KEY` | *(unset)* | Require `X-API-Key` on state-changing endpoints |
| `SOAR_DRY_RUN` | `true` | Record rules without touching the OS firewall / hosts file |
| `CORS_ORIGINS` | `*` | Allowed dashboard origins |
| `ENABLE_LIVE_CAPTURE` | `false` | Start the scapy sniffer (needs root / Npcap) |
| `MAX_UPLOAD_MB` | `10` | Upload size limit |
| `DNSENTINEL_DB_PATH` | `backend/dnsentinel.db` | SQLite location |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | *(unset)* | Optional intel enrichment |

---

## Threat coverage (MITRE ATT&CK)

| Threat class | Detection approach | ATT&CK |
| --- | --- | --- |
| DGA domains | Entropy, bigram likelihood, character-run features | T1568 |
| DNS tunnelling | Label length/depth, high-entropy subdomains, burst diversity | T1071.004 |
| Exfiltration over DNS | Per-source query velocity with high entropy; Zeek baselining | T1041 |

---

## Security

Input is validated at the boundary (RFC 1035 lengths, printable ASCII,
`ipaddress` parsing). SOAR commands are argv lists, never shell strings.
Exports neutralise spreadsheet formulas, errors never echo internals, and
every per-source structure is LRU-bounded. The full table is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#security-notes). An API key
embedded in a browser bundle is not a secret: it deters drive-by scripts on a
public demo, and a multi-user deployment belongs behind SSO.

---

## Tests & CI

```bash
cd backend && pip install pytest ruff && ruff check . && pytest -q   # 69 tests
cd frontend && npm run lint && npm run build
cd extension && npm run build
```

CI ([ci.yml](.github/workflows/ci.yml)) runs all of the above on every push
and PR (Python 3.10 and 3.11), plus a seeded retrain and the calibration step.
CodeQL scans Python and JavaScript.

---

## Tech stack

**Backend** Python · FastAPI · SQLAlchemy · SQLite · Server-Sent Events ·
**ML** scikit-learn (Random Forest, Isolation Forest) · SHAP · NumPy · pandas ·
optional PyTorch CNN-BiLSTM ·
**Dashboard** React 19 · Vite · Tailwind CSS · Recharts · Framer Motion ·
**Extension** Chrome Manifest V3 · **Sensor** Zeek *(attributed, BSD-3)* ·
**Reports** fpdf2 · **Ops** Docker · nginx · GitHub Actions · Render · Vercel

---

## Repository layout

```
backend/     FastAPI service
  routers/     endpoint groups           services/  detection pipeline
  features.py  22-feature extractor      model.py   cached inference + calibration
  risk_engine.py  scoring and tiers      actions.py SOAR orchestrator
  train.py / evaluate.py / calibrate.py  reproducible metrics
  benchmarks/  family-stratified DGA benchmark     tests/  69 tests
frontend/    React SOC dashboard
extension/   MV3 browser extension (+ optional native-messaging host)
data/        bundled datasets and a sample Zeek dns.log
docs/        architecture notes and figures
tools/       public-corpus benchmark runner, SOAR/intel demos
vendor/      third-party components, unmodified (see THIRD_PARTY.md)
```

## License

BSD 3-Clause. See [LICENSE](LICENSE). Third-party components are credited in
[THIRD_PARTY.md](THIRD_PARTY.md).
