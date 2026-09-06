"""Select a decision threshold against an explicit false-positive budget.

The model ships with a 0.5 threshold, which is an arbitrary default rather than
an operating point. In a SOC the quantity that governs analyst workload is the
false-positive rate on benign traffic, not accuracy: at 10,000 benign queries a
day, a 5% FPR is 500 alerts nobody will read. This module picks the threshold
that maximises recall subject to a stated FPR ceiling, and reports what that
choice costs.

Calibration runs on *cross-dataset* predictions by default. Calibrating on
in-distribution scores would be worthless here: the bundled datasets are close
to linearly separable (see MODEL_CARD.md), so nearly every threshold in
(0, 1) scores perfectly and the choice carries no information. Under
distribution shift the score distribution actually overlaps, so the threshold
has to be paid for -- which is the regime a deployed sensor is in.

Usage
-----
    python -m backend.calibrate \
        --dataset data/dns_exfiltration_dataset.csv \
        --cross backend/dga_dataset.csv \
        --max-fpr 0.01

    python -m backend.calibrate --dataset backend/dga_dataset.csv \
        --cross data/dns_exfiltration_dataset.csv --max-fpr 0.05 --write

Run from the repo root. With --write, records the chosen operating point in
backend/models/calibration.json for the API to load.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import FEATURE_ORDER, load, _rf  # noqa: E402

from sklearn.metrics import (  # noqa: E402
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict  # noqa: E402

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
CALIBRATION_PATH = os.path.join(BACKEND_DIR, "models", "calibration.json")
DEFAULT_THRESHOLD = 0.5


def operating_points(y_true: np.ndarray, y_prob: np.ndarray) -> list[dict]:
    """Every distinct threshold the scores actually produce, with its metrics.

    Built from the unique predicted probabilities rather than a fixed grid, so
    no achievable operating point is missed and none is duplicated.
    """
    points = []
    for threshold in np.unique(np.concatenate([y_prob, [0.0, 1.0]])):
        pred = (y_prob >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        negatives = tn + fp
        positives = tp + fn
        points.append(
            {
                "threshold": float(threshold),
                "fpr": float(fp / negatives) if negatives else 0.0,
                "recall": float(tp / positives) if positives else 0.0,
                "precision": float(tp / (tp + fp)) if (tp + fp) else 0.0,
                "false_positives": int(fp),
                "false_negatives": int(fn),
            }
        )
    return points


def choose(points: list[dict], max_fpr: float) -> dict | None:
    """Highest-recall operating point whose FPR stays inside the budget.

    Ties on recall are broken by the lower FPR, so the returned point is the
    cheapest way to buy that level of detection. Returns None when no threshold
    satisfies the budget -- an honest outcome, not an error: it means the model
    cannot separate the classes tightly enough to meet the constraint at all.

    Zero-recall points are excluded. A threshold above every score trivially
    achieves an FPR of zero by detecting nothing, and returning it would let any
    budget look satisfiable. A detector that fires on nothing has not met the
    constraint; it has stopped being a detector.
    """
    feasible = [p for p in points if p["fpr"] <= max_fpr and p["recall"] > 0.0]
    if not feasible:
        return None
    return max(feasible, key=lambda p: (p["recall"], -p["fpr"]))


def _fmt(p: dict) -> str:
    return (
        f"threshold={p['threshold']:.4f}  fpr={p['fpr']:.4f}  "
        f"recall={p['recall']:.3f}  precision={p['precision']:.3f}  "
        f"fp={p['false_positives']}  fn={p['false_negatives']}"
    )


def calibrate(dataset, cross, domain_col, label_col, max_fpr, in_distribution, write):
    X, y = load(dataset, domain_col, label_col)

    if in_distribution:
        source = f"{os.path.basename(dataset)} (5-fold CV, in-distribution)"
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        y_prob = cross_val_predict(
            _rf(), X, y, cv=skf, method="predict_proba"
        )[:, 1]
        y_eval = y
    else:
        if not cross:
            raise SystemExit(
                "--cross is required unless --in-distribution is passed. "
                "Calibrating on a near-separable in-distribution split picks a "
                "threshold that means nothing off-distribution."
            )
        source = f"{os.path.basename(dataset)} -> {os.path.basename(cross)} (cross-dataset)"
        Xc, y_eval = load(cross, domain_col, label_col)
        y_prob = _rf().fit(X, y).predict_proba(Xc)[:, 1]

    print(f"\n=== calibration on {source} ===")
    print(f"evaluated on n={len(y_eval)}  auc={roc_auc_score(y_eval, y_prob):.3f}")

    points = operating_points(y_eval, y_prob)
    default = min(points, key=lambda p: abs(p["threshold"] - DEFAULT_THRESHOLD))
    chosen = choose(points, max_fpr)

    print(f"\ndefault (0.5)          {_fmt(default)}")
    if chosen is None:
        print(
            f"\nNo threshold reaches fpr <= {max_fpr:.3f}. The tightest available "
            f"is {min(p['fpr'] for p in points):.4f}. Meeting this budget needs a "
            "better feature set or representative training data, not a different "
            "cut point."
        )
        return None

    print(f"budget fpr <= {max_fpr:<9.3f} {_fmt(chosen)}")

    d_recall = chosen["recall"] - default["recall"]
    d_fp = chosen["false_positives"] - default["false_positives"]
    print(
        f"\ncost of the budget: {d_recall:+.3f} recall, {d_fp:+d} false positives "
        f"against the default cut."
    )
    print(
        "Recall lost here is the honest price of the alert-fatigue ceiling. "
        "Report both numbers or neither."
    )

    if write:
        os.makedirs(os.path.dirname(CALIBRATION_PATH), exist_ok=True)
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "calibrator": "backend/calibrate.py",
            "source": source,
            "in_distribution": bool(in_distribution),
            "max_fpr_budget": max_fpr,
            "chosen": chosen,
            "default_threshold_point": default,
            "note": (
                "Threshold selected to maximise recall subject to the stated FPR "
                "budget. Reproduce with python -m backend.calibrate."
            ),
        }
        with open(CALIBRATION_PATH, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {os.path.relpath(CALIBRATION_PATH)}")

    return chosen


def load_threshold(default: float = DEFAULT_THRESHOLD) -> float:
    """Threshold for the API to use. Falls back to the default when uncalibrated.

    Kept deliberately quiet: an uncalibrated deployment is a valid state, and
    the caller should not have to handle an exception for it.
    """
    try:
        with open(CALIBRATION_PATH, encoding="utf-8") as fh:
            return float(json.load(fh)["chosen"]["threshold"])
    except (OSError, KeyError, ValueError, TypeError):
        return default


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True, help="labelled domain CSV to train on")
    ap.add_argument("--cross", help="second CSV to calibrate against (recommended)")
    ap.add_argument("--domain-col", default="domain")
    ap.add_argument("--label-col", default="label")
    ap.add_argument(
        "--max-fpr",
        type=float,
        default=0.01,
        help="false-positive budget on benign traffic (default 0.01)",
    )
    ap.add_argument(
        "--in-distribution",
        action="store_true",
        help="calibrate on 5-fold CV of --dataset instead of a cross-dataset split",
    )
    ap.add_argument(
        "--write",
        action="store_true",
        help="record the chosen point in backend/models/calibration.json",
    )
    a = ap.parse_args()
    calibrate(
        a.dataset, a.cross, a.domain_col, a.label_col,
        a.max_fpr, a.in_distribution, a.write,
    )


if __name__ == "__main__":
    main()
