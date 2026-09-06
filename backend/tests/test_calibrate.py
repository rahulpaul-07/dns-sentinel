"""Unit tests for the threshold calibrator (backend/calibrate.py).

These use synthetic score arrays rather than the trained model, so they assert
the selection logic itself and stay fast enough to run on every push.
"""
import json

import numpy as np
import pytest

from calibrate import (
    DEFAULT_THRESHOLD,
    choose,
    load_threshold,
    operating_points,
)


@pytest.fixture()
def separable():
    """Perfectly separable scores: benign low, malicious high."""
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    prob = np.array([0.01, 0.05, 0.10, 0.12, 0.88, 0.90, 0.95, 0.99])
    return y, prob


@pytest.fixture()
def overlapping():
    """Overlapping scores: no threshold separates the classes cleanly."""
    y = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    prob = np.array([0.1, 0.2, 0.6, 0.7, 0.8, 0.3, 0.4, 0.75, 0.9, 0.95])
    return y, prob


def test_operating_points_cover_every_distinct_score(overlapping):
    y, prob = overlapping
    points = operating_points(y, prob)
    # One point per unique score, plus the 0.0 and 1.0 endpoints.
    assert len(points) == len(set(prob.tolist()) | {0.0, 1.0})
    assert {p["threshold"] for p in points} >= {0.0, 1.0}


def test_threshold_zero_flags_everything(overlapping):
    y, prob = overlapping
    zero = next(p for p in operating_points(y, prob) if p["threshold"] == 0.0)
    assert zero["recall"] == 1.0
    assert zero["fpr"] == 1.0


def test_metrics_are_bounded(overlapping):
    y, prob = overlapping
    for p in operating_points(y, prob):
        assert 0.0 <= p["fpr"] <= 1.0
        assert 0.0 <= p["recall"] <= 1.0
        assert 0.0 <= p["precision"] <= 1.0
        assert p["false_positives"] >= 0
        assert p["false_negatives"] >= 0


def test_recall_is_monotonic_in_threshold(overlapping):
    """Raising the threshold can never increase recall."""
    y, prob = overlapping
    points = sorted(operating_points(y, prob), key=lambda p: p["threshold"])
    recalls = [p["recall"] for p in points]
    assert all(a >= b for a, b in zip(recalls, recalls[1:]))


def test_choose_respects_the_budget(overlapping):
    y, prob = overlapping
    points = operating_points(y, prob)
    for budget in (0.0, 0.2, 0.4, 0.6, 1.0):
        chosen = choose(points, budget)
        if chosen is not None:
            assert chosen["fpr"] <= budget


def test_choose_maximises_recall_within_the_budget(overlapping):
    y, prob = overlapping
    points = operating_points(y, prob)
    chosen = choose(points, 0.4)
    best = max(p["recall"] for p in points if p["fpr"] <= 0.4)
    assert chosen["recall"] == best


def test_choose_breaks_recall_ties_on_lower_fpr(separable):
    """Where several points detect everything, take the cheapest."""
    y, prob = separable
    chosen = choose(operating_points(y, prob), 1.0)
    assert chosen["recall"] == 1.0
    assert chosen["fpr"] == 0.0


def test_choose_returns_none_when_the_budget_is_unreachable():
    """An impossible budget is reported, not silently widened."""
    y = np.array([0, 0, 1, 1])
    prob = np.array([0.9, 0.9, 0.9, 0.9])  # no separation at all
    assert choose(operating_points(y, prob), 0.0) is None


def test_load_threshold_falls_back_when_uncalibrated(monkeypatch, tmp_path):
    monkeypatch.setattr("calibrate.CALIBRATION_PATH", str(tmp_path / "missing.json"))
    assert load_threshold() == DEFAULT_THRESHOLD


def test_load_threshold_reads_a_written_calibration(monkeypatch, tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps({"chosen": {"threshold": 0.8733}}), encoding="utf-8")
    monkeypatch.setattr("calibrate.CALIBRATION_PATH", str(path))
    assert load_threshold() == pytest.approx(0.8733)


def test_load_threshold_falls_back_on_malformed_calibration(monkeypatch, tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr("calibrate.CALIBRATION_PATH", str(path))
    assert load_threshold() == DEFAULT_THRESHOLD
