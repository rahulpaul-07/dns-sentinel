"""Deterministic, reproducible trainer for the DNSentinel detection models.

This is the *canonical* way to (re)generate the model artifacts. It is fully
seeded, so the same dataset always produces byte-comparable models, and it
writes a `metrics.json` provenance manifest next to the models (dataset hash,
library versions, hyperparameters, timestamp, held-out metrics) so a reviewer
can trust — and reproduce — every number without rerunning anything.

Usage
-----
    python -m backend.train                                  # uses the bundled exfil dataset
    python -m backend.train --dataset data/dns_exfiltration_dataset.csv
    python -m backend.train --dataset backend/dga_dataset.csv --domain-col domain

Outputs (git-ignored except metrics.json):
    backend/models/dns_rf_model.joblib      # RandomForest classifier
    backend/models/dns_iso_model.joblib     # IsolationForest anomaly detector
    backend/models/metrics.json             # provenance + held-out metrics
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    StratifiedKFold,
    cross_val_predict,
    train_test_split,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_ORDER, vectorize  # noqa: E402

SEED = 42
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BACKEND_DIR, "models")
DEFAULT_DATASET = os.path.join(BACKEND_DIR, "..", "data", "dns_exfiltration_dataset.csv")


from evaluate import RF_PARAMS  # noqa: E402  (one definition, shared with the evaluator)
ISO_PARAMS = dict(contamination=0.15, random_state=SEED)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path: str, domain_col: str, label_col: str):
    X, y = [], []
    with open(path, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            domain = (row.get(domain_col) or "").strip()
            if not domain:
                continue
            X.append(vectorize(domain))
            y.append(int(row[label_col]))
    return np.array(X, dtype=float), np.array(y, dtype=int)


def fit_production_models(X, y):
    """Fit the shipped RandomForest + IsolationForest on all of (X, y)."""
    rf = RandomForestClassifier(**RF_PARAMS).fit(X, y)
    iso = IsolationForest(**ISO_PARAMS).fit(X)
    return rf, iso


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    ap.add_argument("--domain-col", default="domain")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--out", default=MODELS_DIR, help="output directory for artifacts")
    a = ap.parse_args()

    dataset = os.path.abspath(a.dataset)
    os.makedirs(a.out, exist_ok=True)
    X, y = load(dataset, a.domain_col, a.label_col)
    classes, counts = np.unique(y, return_counts=True)
    print(f"[*] Loaded {len(y)} samples from {os.path.basename(dataset)} "
          f"(balance={dict(zip(classes.tolist(), counts.tolist()))})")

    # --- Held-out metrics (never trained on the test split) ---------------
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=SEED
    )
    holdout_clf = RandomForestClassifier(**RF_PARAMS).fit(X_tr, y_tr)
    pred = holdout_clf.predict(X_te)
    prob = holdout_clf.predict_proba(X_te)[:, 1]
    holdout = {
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "precision": round(float(precision_score(y_te, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_te, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_te, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_te, prob)), 4) if len(classes) == 2 else None,
    }
    cv_pred = cross_val_predict(
        RandomForestClassifier(**RF_PARAMS), X, y,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED),
    )
    cv = {
        "accuracy": round(float(accuracy_score(y, cv_pred)), 4),
        "precision": round(float(precision_score(y, cv_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, cv_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, cv_pred, zero_division=0)), 4),
    }

    # --- Fit the production models on ALL data, then persist ---------------
    rf, iso = fit_production_models(X, y)
    rf_path = os.path.join(a.out, "dns_rf_model.joblib")
    iso_path = os.path.join(a.out, "dns_iso_model.joblib")
    joblib.dump(rf, rf_path)
    joblib.dump(iso, iso_path)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "trainer": "backend/train.py",
        "seed": SEED,
        "dataset": {
            "path": os.path.relpath(dataset, os.path.join(BACKEND_DIR, "..")),
            "sha256": _sha256(dataset),
            "n_samples": int(len(y)),
            "class_balance": {int(k): int(v) for k, v in zip(classes, counts)},
        },
        "features": {"count": len(FEATURE_ORDER), "order": FEATURE_ORDER},
        "models": {
            "random_forest": {"params": RF_PARAMS, "artifact": "dns_rf_model.joblib"},
            "isolation_forest": {"params": ISO_PARAMS, "artifact": "dns_iso_model.joblib"},
        },
        "metrics": {"holdout_20pct": holdout, "stratified_5fold_cv": cv},
        "environment": {
            "python": sys.version.split()[0],
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
        },
        "note": (
            "In-distribution metrics are near-perfect because the bundled dataset is "
            "near-linearly separable (an entropy-only depth-1 stump scores ~0.99 F1). "
            "See MODEL_CARD.md for honest cross-dataset generalization results and "
            "reproduce with: python -m backend.evaluate"
        ),
    }
    with open(os.path.join(a.out, "metrics.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")

    print(f"[+] Wrote {rf_path}")
    print(f"[+] Wrote {iso_path}")
    print(f"[+] Wrote {os.path.join(a.out, 'metrics.json')}")
    print(f"[=] Held-out 20%: {holdout}")
    print(f"[=] 5-fold CV:    {cv}")


if __name__ == "__main__":
    main()
