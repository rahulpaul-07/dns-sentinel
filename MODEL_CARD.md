# Model Card — DNSentinel DNS Threat Classifier

A concise, honest description of the model behind DNSentinel's `/analyze`
endpoint. Every metric here is produced by `backend/evaluate.py` (no
hand-typed numbers) and can be reproduced in under a minute.

## Overview

| | |
|---|---|
| **Task** | Binary classification of DNS queries: benign (0) vs. malicious (1), targeting DGA domains and DNS-based data exfiltration. |
| **Model** | `RandomForestClassifier` (300 trees, `max_depth=30`, `min_samples_split=10`, `random_state=42`) as the primary classifier, plus an `IsolationForest` anomaly detector and an **optional** character-level CNN-BiLSTM DGA scorer (`backend/dga_model.py`). The DL scorer is used only when `torch` is installed **and** trained weights exist; an untrained network is never averaged in. |
| **Input** | A single DNS query string → a **22-dimensional feature vector** (`backend/features.py`). |
| **Output** | `(label, malicious_probability ∈ [0,1], anomaly_flag, SHAP explanation)`. Decision threshold = **0.873**, loaded from `backend/models/calibration.json` (see *Operating point*). `GET /model` reports the threshold actually in use. |
| **Intended use** | Portfolio / research demonstrator for DNS threat detection and SOC workflow tooling. **Not** production-hardened for enterprise deployment as-is. |

## Features (22)

Shannon entropy, query length, subdomain length, English-bigram likelihood,
consonant/digit/unique-character ratios, vowel:consonant ratio, four
max-continuous-run features (numeric, alphabetic, consonant, same-char), upper/
lower/special counts, label count/max/average, entropy-to-length ratio, a
high-entropy flag, and a derived domain-complexity term. Full definitions in
`backend/features.py`; ordering is contract-tested in
`backend/tests/test_model_contract.py`.

## Training data

| Dataset | Rows | Balance | Notes |
|---|---|---|---|
| `data/dns_exfiltration_dataset.csv` | 700 | 350/350 | Exfil-style vs. benign domains. |
| `backend/dga_dataset.csv` | 1,000 | 500/500 | Algorithmically-generated vs. benign domains. |

**Limitation — separability.** These bundled sets are small and near-linearly
separable: an **entropy-only, depth-1 decision stump reaches F1 ≈ 0.99** on the
exfil set. Near-100% in-distribution scores therefore reflect *dataset
simplicity*, not model superiority, and should not be read as production
accuracy.

## Evaluation

Reproduce (train writes a `metrics.json` provenance manifest; evaluate prints
honest hold-out + cross-dataset numbers):

```bash
pip install -r backend/requirements.txt
python -m backend.train                                                # regenerate models + metrics.json
python -m backend.evaluate --dataset data/dns_exfiltration_dataset.csv --cross backend/dga_dataset.csv
python -m backend.evaluate --dataset backend/dga_dataset.csv         --cross data/dns_exfiltration_dataset.csv
```

**In-distribution (stratified 80/20 hold-out and 5-fold CV):**

| Dataset | Split | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|---|
| exfil (700) | hold-out | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| exfil (700) | 5-fold CV | 1.000 | 1.000 | 1.000 | 1.000 | — |
| dga (1,000) | hold-out | 0.995 | 0.990 | 1.000 | 0.995 | 1.000 |
| dga (1,000) | 5-fold CV | 0.997 | 0.994 | 1.000 | 0.997 | — |

**Cross-dataset generalization (train on one, test on the other — the honest signal):**

| Train → Test | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| exfil → dga | 0.593 | 0.551 | 1.000 | 0.711 | 0.988 |
| dga → exfil | 0.924 | 1.000 | 0.849 | 0.918 | 1.000 |

Under distribution shift, precision falls as low as **0.55** (407 false
positives in the exfil→dga direction). In a SOC, that false-positive rate — not
in-distribution accuracy — is the metric that governs analyst alert fatigue.

## Known limitations & ethical considerations

- **Domain shift** is the dominant failure mode (see above). Deploying on live
  traffic requires retraining on representative, diverse data.
- **Synthetic/curated data** inflates in-distribution scores; treat them as a
  functional smoke test, not a capability claim.
- **No adversarial robustness** evaluation. Dictionary-based DGAs (e.g.
  suppobox, matsnu) that mimic natural language are expected to be much harder
  than the random-looking DGAs in the bundled set.
- **Thin benign class in the exfil set.** Its benign rows are a handful of
  bare apex domains (`microsoft.com`, `apple.com`, ...), so the model gives
  ordinary subdomains such as `mail.google.com` raw probabilities of 0.4-0.6.
  The calibrated threshold classifies these correctly, and the risk engine
  receives the *calibrated* score (threshold mapped to 0.5) rather than the raw
  probability, so they land in the Low tier. A regression test pins this. The
  real fix is more representative benign training data.
- **`upper_count` is constant.** Queries are lower-cased at the API boundary
  (DNS is case-insensitive), so this feature is always 0. It is kept only to
  preserve the 22-feature contract of the trained artifacts.
- **`frequency` is constant in training.** Offline datasets have no timing, so
  training uses 1; the live per-source rate feeds the behavioural risk terms
  instead.

## Operating point

The decision threshold is chosen by `backend/calibrate.py` to maximise recall
under an explicit false-positive budget, on cross-dataset scores (in-distribution
scores are too separable to carry information):

| Budget | Threshold | FPR | Recall | Precision | False positives |
|---|---|---|---|---|---|
| default 0.5 | 0.503 | 0.814 | 1.000 | 0.551 | 407 |
| FPR <= 5% | **0.873** | 0.042 | 1.000 | 0.960 | 21 |

A 1% budget is unreachable in this direction; the calibrator reports that
instead of silently widening the budget. `backend/tests/test_metric_drift.py`
fails the build if any of these published figures stop reproducing.

## What has been done vs. what remains

Done: family-stratified benchmark with per-family recall ([BENCHMARK.md](BENCHMARK.md)),
a public-corpus runner (Netlab360 / chrmor, 25 families), FPR-budget threshold
calibration wired into the live API, and metric-drift tests in CI.

Remaining: training (not just testing) on public corpora such as
CIC-Bell-DNS-EXF-2021 and Tranco, adversarial evaluation against dictionary
DGAs, and encrypted-transport coverage (DoH/DoT defeat query-string features
entirely).

## Family-stratified benchmark

A larger (12,000-domain) DGA benchmark with per-family recall lives in [BENCHMARK.md](BENCHMARK.md) and `backend/benchmarks/`. Headline: cross-domain F1 0.79 (AUC 0.92); dictionary-DGA recall 0.67 is the hard case; benign false-positive rate falls from 39.6% to ~3.8% once the model is trained on representative data. The harness also accepts real public CSVs (CIC-Bell-DNS-EXF-2021 / Tranco / Bambenek).
