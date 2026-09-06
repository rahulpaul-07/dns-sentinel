"""Guard the numbers published in README.md and MODEL_CARD.md against drift.

A README figure that nobody re-checks becomes wrong the first time a feature is
added or a dependency bumps a default. These tests retrain on the bundled
datasets and assert the published claims still hold, so a regression fails the
build instead of quietly changing what the documentation says.

Bounds are deliberately loose. The purpose is to catch a real regression -- a
broken feature, a shuffled vector, a dependency that changes an estimator's
behaviour -- not to pin an exact float that a scikit-learn point release may
legitimately move.
"""
import os

import numpy as np
import pytest
from sklearn.metrics import roc_auc_score

from calibrate import choose, operating_points
from evaluate import _rf, load

REPO_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
EXFIL = os.path.join(REPO_ROOT, "data", "dns_exfiltration_dataset.csv")
DGA = os.path.join(REPO_ROOT, "backend", "dga_dataset.csv")

pytestmark = pytest.mark.skipif(
    not (os.path.exists(EXFIL) and os.path.exists(DGA)),
    reason="bundled datasets not present",
)


def _cross(train_path, test_path):
    X, y = load(train_path, "domain", "label")
    Xt, yt = load(test_path, "domain", "label")
    prob = _rf().fit(X, y).predict_proba(Xt)[:, 1]
    return yt, prob


@pytest.fixture(scope="module")
def exfil_to_dga():
    return _cross(EXFIL, DGA)


@pytest.fixture(scope="module")
def dga_to_exfil():
    return _cross(DGA, EXFIL)


def test_datasets_have_the_documented_shape():
    """MODEL_CARD quotes 700 exfil rows and 1,000 DGA rows, both balanced."""
    _, y_exfil = load(EXFIL, "domain", "label")
    _, y_dga = load(DGA, "domain", "label")
    assert len(y_exfil) == 700
    assert len(y_dga) == 1000
    assert set(np.unique(y_exfil).tolist()) == {0, 1}
    assert set(np.unique(y_dga).tolist()) == {0, 1}


def test_cross_dataset_auc_holds(exfil_to_dga, dga_to_exfil):
    """Ranking quality survives distribution shift, as MODEL_CARD reports."""
    y, prob = exfil_to_dga
    assert roc_auc_score(y, prob) >= 0.95
    y, prob = dga_to_exfil
    assert roc_auc_score(y, prob) >= 0.95


def test_default_threshold_is_still_the_expensive_choice(exfil_to_dga):
    """The README claims 0.5 costs ~407 false positives. Keep that honest.

    If this ever drops sharply the README's argument for calibration has gone
    stale and the numbers there need rewriting -- which is exactly what this
    test is for.
    """
    y, prob = exfil_to_dga
    default = min(
        operating_points(y, prob), key=lambda p: abs(p["threshold"] - 0.5)
    )
    assert default["false_positives"] > 300
    assert default["recall"] == pytest.approx(1.0, abs=0.05)


def test_calibrated_point_meets_the_published_budget(exfil_to_dga):
    """README: 5% budget keeps recall at 1.00 for roughly 21 false positives."""
    y, prob = exfil_to_dga
    chosen = choose(operating_points(y, prob), 0.05)
    assert chosen is not None
    assert chosen["fpr"] <= 0.05
    assert chosen["recall"] >= 0.95
    assert chosen["false_positives"] <= 40


def test_one_percent_budget_remains_unreachable(exfil_to_dga):
    """README states a 1% budget cannot be met in this direction.

    If a future feature makes it reachable that is good news, but the README
    says otherwise and must be updated -- so this fails rather than passing
    silently on a claim that is no longer true.
    """
    y, prob = exfil_to_dga
    assert choose(operating_points(y, prob), 0.01) is None


def test_calibration_recovers_detections_in_the_reverse_direction(dga_to_exfil):
    """README: the default discards ~53 detections that calibration recovers."""
    y, prob = dga_to_exfil
    points = operating_points(y, prob)
    default = min(points, key=lambda p: abs(p["threshold"] - 0.5))
    chosen = choose(points, 0.01)
    assert chosen is not None
    assert chosen["recall"] > default["recall"]
    assert chosen["fpr"] <= 0.01
