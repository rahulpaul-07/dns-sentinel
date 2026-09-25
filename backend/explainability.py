"""SHAP attribution text for a single prediction."""
import logging

import numpy as np
import shap

logger = logging.getLogger("DNSentinel.XAI")

# TreeExplainer construction walks every tree, so cache it -- keyed on the model
# object so a retrained model never gets explained with a stale explainer.
_explainer = None
_explained_model_id = None


def reset_explainer():
    global _explainer, _explained_model_id
    _explainer = None
    _explained_model_id = None


def _get_explainer(rf_model):
    global _explainer, _explained_model_id
    if _explainer is None or _explained_model_id != id(rf_model):
        _explainer = shap.TreeExplainer(rf_model)
        _explained_model_id = id(rf_model)
    return _explainer


def _malicious_class_values(shap_values):
    """Normalise SHAP output shapes across versions to a 1-D class-1 vector."""
    if isinstance(shap_values, list):          # older SHAP: one array per class
        return np.asarray(shap_values[1][0])
    vals = np.asarray(shap_values)[0]
    if vals.ndim > 1:                          # newer SHAP: (features, classes)
        vals = vals[:, 1]
    return vals


def get_shap_explanation(rf_model, feature_array, feature_names, top_k: int = 3) -> str:
    """Top features pushing this sample towards 'malicious', as one line of text."""
    try:
        explainer = _get_explainer(rf_model)
        vals = _malicious_class_values(explainer.shap_values(np.asarray([feature_array], dtype=float)))
    except Exception as e:  # attribution is best-effort; never fail the request
        logger.warning("SHAP explanation failed: %s", e)
        return ""

    impacts = sorted(zip(feature_names, vals), key=lambda x: x[1], reverse=True)
    top = [f"{name} (+{val * 100:.1f}%)" for name, val in impacts[:top_k] if val > 0.01]
    if not top:
        return ""
    return f"[XAI: SHAP] {' | '.join(top)} contributed most to the malicious score."
