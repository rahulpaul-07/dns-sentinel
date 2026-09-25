"""Inference layer for the DNSentinel detection ensemble.

Models are loaded once and cached in memory; `reload_models()` swaps them
atomically after a retrain. The decision threshold comes from
models/calibration.json (written by calibrate.py) rather than a hard-coded 0.5,
so the operating point the README documents is the one the API actually uses.
"""
import logging
import os
import threading

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from calibrate import DEFAULT_THRESHOLD, load_threshold
from explainability import get_shap_explanation, reset_explainer
from features import FEATURE_ORDER

logger = logging.getLogger("DNSentinel.Model")

# The character-level DL scorer needs torch, which is an optional extra.
try:
    import dga_model
except ImportError:  # torch not installed: the DL score is skipped entirely
    dga_model = None

# Artifacts live in backend/models/ and are generated reproducibly by
# `python -m backend.train` (they are git-ignored). They are auto-trained on
# first use when missing.
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
RF_MODEL_PATH = os.path.join(MODELS_DIR, "dns_rf_model.joblib")
ISO_MODEL_PATH = os.path.join(MODELS_DIR, "dns_iso_model.joblib")
DEFAULT_DATASET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "dns_exfiltration_dataset.csv")

_lock = threading.Lock()
_models = None          # (rf, iso) once loaded
_threshold = None       # calibrated decision threshold


def _train_base_models():
    """Fit the default models on the bundled dataset (same recipe as train.py)."""
    from train import fit_production_models, load

    logger.info("No model artifacts found; training baseline models from %s", DEFAULT_DATASET)
    X, y = load(DEFAULT_DATASET, "domain", "label")
    rf, iso = fit_production_models(X, y)
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(rf, RF_MODEL_PATH)
    joblib.dump(iso, ISO_MODEL_PATH)
    return rf, iso


def load_models():
    """Return the cached (rf, iso) pair, loading or training it on first use."""
    global _models
    if _models is None:
        with _lock:
            if _models is None:
                if os.path.exists(RF_MODEL_PATH) and os.path.exists(ISO_MODEL_PATH):
                    _models = (joblib.load(RF_MODEL_PATH), joblib.load(ISO_MODEL_PATH))
                else:
                    _models = _train_base_models()
    return _models


def reload_models():
    """Drop cached models and explainer so the next request picks up new artifacts."""
    global _models, _threshold
    with _lock:
        _models = None
        _threshold = None
    reset_explainer()


def decision_threshold() -> float:
    global _threshold
    if _threshold is None:
        _threshold = load_threshold(DEFAULT_THRESHOLD)
    return _threshold


def calibrated_score(probability: float) -> float:
    """Rescale P(malicious) so the calibrated threshold maps to 0.5.

    The risk engine blends the ML signal with behaviour and intel, so it must
    see the model's *operating point*, not its raw output. With a threshold of
    0.87, a raw 0.6 is a confident "benign" and should contribute like 0.34,
    not like 0.6. Piecewise-linear and monotonic, so ranking is unchanged.
    """
    t = decision_threshold()
    if probability < t:
        return 0.5 * probability / t
    return 0.5 + 0.5 * (probability - t) / (1.0 - t) if t < 1.0 else 1.0


def dga_model_ready() -> bool:
    return dga_model is not None and dga_model.is_ready()


def train_custom_model(df: pd.DataFrame) -> dict:
    """Retrain the ensemble on an uploaded, labelled dataset and hot-swap it in.

    Expects the FEATURE_ORDER columns plus 'label' (1 malicious, 0 benign).
    """
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column for supervised training.")
    counts = df["label"].value_counts()
    if len(counts) < 2 or counts.min() < 2:
        raise ValueError("Dataset needs at least two examples of each class (0 and 1).")

    X = df[FEATURE_ORDER].to_numpy(dtype=float)
    y = df["label"].astype(int).to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf_clf = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
    rf_clf.fit(X_train, y_train)
    y_pred = rf_clf.predict(X_test)
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "feature_importances": dict(zip(FEATURE_ORDER, map(float, rf_clf.feature_importances_))),
        "note": "Held-out 20% split. A custom model resets the operating point to the 0.5 default; "
                "re-run calibrate.py to choose one for this data.",
    }

    iso_clf = IsolationForest(contamination=0.15, random_state=42).fit(X)
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(rf_clf, RF_MODEL_PATH)
    joblib.dump(iso_clf, ISO_MODEL_PATH)
    reload_models()
    # The shipped calibration was chosen for the bundled model, not this one.
    global _threshold
    _threshold = DEFAULT_THRESHOLD
    return metrics


def predict(features_array, domain: str = ""):
    """Score one feature vector with the ensemble.

    Returns (label, malicious_probability, isolation_prediction, shap_text):
      - label: 1 when malicious_probability exceeds the calibrated threshold
      - malicious_probability: RF P(malicious), averaged with the DL DGA score
        only when trained DL weights are available
      - isolation_prediction: -1 outlier / 1 inlier (IsolationForest)
      - shap_text: human-readable top contributing features, or ""
    """
    rf, iso = load_models()
    # Models are fitted on plain arrays (train.py), so predict on one too.
    X = np.asarray([features_array], dtype=float)

    rf_prob_malicious = float(rf.predict_proba(X)[0][1])
    iso_prediction = int(iso.predict(X)[0])

    malicious_probability = rf_prob_malicious
    if domain and dga_model_ready():
        try:
            malicious_probability = (rf_prob_malicious + dga_model.predict(domain)) / 2.0
        except Exception as e:  # never let the optional scorer break a request
            logger.warning("DGA model prediction failed: %s", e)

    final_label = 1 if malicious_probability >= decision_threshold() else 0

    shap_text = ""
    # SHAP is comparatively expensive; only explain what we are going to flag.
    if final_label == 1 or iso_prediction == -1:
        shap_text = get_shap_explanation(rf, X[0], FEATURE_ORDER)

    return int(final_label), float(malicious_probability), iso_prediction, shap_text
