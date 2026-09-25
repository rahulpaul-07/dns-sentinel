"""Reproducible, honest evaluation harness for the DNSentinel detection model.

This is deliberately the *source of truth* for every accuracy number quoted in
the README and MODEL_CARD. It never evaluates on the training set: it reports a
stratified hold-out split, stratified k-fold cross-validation, and (optionally)
cross-dataset generalization -- the honest, harder signal.

Usage
-----
    python -m backend.evaluate --dataset data/dns_exfiltration_dataset.csv
    python -m backend.evaluate --dataset backend/dga_dataset.csv \
        --cross data/dns_exfiltration_dataset.csv

Run from the repo root. Produces a metrics table on stdout and, with
--plot, writes confusion_matrix.png.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys

import numpy as np

# Allow "python backend/evaluate.py" as well as "-m backend.evaluate".
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_ORDER, vectorize  # noqa: E402,F401  (re-exported)

from sklearn.ensemble import RandomForestClassifier  # noqa: E402

RF_PARAMS = dict(n_estimators=300, max_depth=30, min_samples_split=10, random_state=42)
from sklearn.model_selection import (  # noqa: E402
    StratifiedKFold,
    cross_val_predict,
    train_test_split,
)
from sklearn.metrics import (  # noqa: E402
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)



def load(path: str, domain_col: str, label_col: str):
    """Vectorize a labelled domain CSV with the project's own feature extractor."""
    X, y = [], []
    with open(path, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            domain = (row.get(domain_col) or "").strip()
            if not domain:
                continue
            X.append(vectorize(domain))
            y.append(int(row[label_col]))
    return np.array(X, dtype=float), np.array(y, dtype=int)


def _rf() -> RandomForestClassifier:
    # Identical hyperparameters to the production model in train.py.
    return RandomForestClassifier(**RF_PARAMS)


def _line(tag: str, y_true, y_pred, y_prob=None) -> str:
    auc = ""
    if y_prob is not None and len(set(y_true)) == 2:
        auc = f" auc={roc_auc_score(y_true, y_prob):.3f}"
    return (
        f"{tag:<22} acc={accuracy_score(y_true, y_pred):.3f} "
        f"prec={precision_score(y_true, y_pred, zero_division=0):.3f} "
        f"rec={recall_score(y_true, y_pred, zero_division=0):.3f} "
        f"f1={f1_score(y_true, y_pred, zero_division=0):.3f}{auc}"
    )


def evaluate(dataset, domain_col, label_col, cross=None, plot=False):
    X, y = load(dataset, domain_col, label_col)
    classes, counts = np.unique(y, return_counts=True)
    print(f"\n=== {os.path.basename(dataset)} (n={len(y)}, "
          f"balance={dict(zip(classes.tolist(), counts.tolist()))}) ===")

    # 1) Honest stratified hold-out.
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    clf = _rf().fit(X_tr, y_tr)
    pred = clf.predict(X_te)
    prob = clf.predict_proba(X_te)[:, 1]
    print(_line("hold-out(20%)", y_te, pred, prob))
    cm = confusion_matrix(y_te, pred)
    print(f"{'':<22} confusion [[TN,FP],[FN,TP]] = {cm.tolist()}")

    # 2) Stratified 5-fold CV (more robust point estimate).
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_pred = cross_val_predict(_rf(), X, y, cv=skf)
    print(_line("5-fold CV", y, cv_pred))

    # 3) Cross-dataset generalization (the number worth bragging about honestly).
    if cross:
        Xc, yc = load(cross, domain_col, label_col)
        gen = _rf().fit(X, y)
        gp = gen.predict(Xc)
        gpr = gen.predict_proba(Xc)[:, 1]
        print(_line(f"-> {os.path.basename(cross)}", yc, gp, gpr))
        print(f"{'':<22} confusion [[TN,FP],[FN,TP]] = "
              f"{confusion_matrix(yc, gp).tolist()}")

    if plot:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            fig, ax = plt.subplots(figsize=(4, 4))
            ax.imshow(cm, cmap="Blues")
            ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
            ax.set_xticklabels(["benign", "malicious"])
            ax.set_yticklabels(["benign", "malicious"])
            ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
            for (i, j), v in np.ndenumerate(cm):
                ax.text(j, i, str(v), ha="center", va="center")
            ax.set_title("Hold-out confusion matrix")
            fig.tight_layout()
            fig.savefig("confusion_matrix.png", dpi=120)
            print("wrote confusion_matrix.png")
        except ImportError:
            print("matplotlib not installed; skipping --plot")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True, help="labelled domain CSV")
    ap.add_argument("--domain-col", default="domain")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--cross", help="second CSV for cross-dataset generalization")
    ap.add_argument("--plot", action="store_true", help="write confusion_matrix.png")
    a = ap.parse_args()
    evaluate(a.dataset, a.domain_col, a.label_col, a.cross, a.plot)


if __name__ == "__main__":
    main()
