"""Unit tests for the adaptive RiskEngine (backend/risk_engine.py)."""
import asyncio

import pytest

from risk_engine import RiskEngine, RiskTier


def _run(coro):
    """Drive a coroutine to completion from a synchronous test.

    asyncio.get_event_loop() no longer creates a loop implicitly on the main
    thread -- deprecated since 3.10 and removed in 3.12 -- so it raises
    RuntimeError on newer interpreters. asyncio.run() owns the loop for the
    call and closes it afterwards, which works on every supported version.
    """
    return asyncio.run(coro)


@pytest.fixture()
def engine(tmp_path):
    cfg = tmp_path / "risk_baseline.yaml"
    return RiskEngine(config_path=str(cfg))


def test_default_config_is_written_when_missing(tmp_path):
    cfg = tmp_path / "risk_baseline.yaml"
    RiskEngine(config_path=str(cfg))
    assert cfg.exists()


def test_weights_load_from_defaults(engine):
    assert engine.w_ml == pytest.approx(0.5)
    assert engine.w_behavior == pytest.approx(0.3)
    assert engine.w_intel == pytest.approx(0.2)


def test_score_returns_bounded_value_and_valid_tier(engine):
    score, level = _run(engine.score("10.0.0.1", "example.com", ml_score=0.1))
    assert 0.0 <= score <= 100.0
    assert level in {t.value for t in RiskTier}


def test_high_ml_score_yields_higher_risk_than_low(engine):
    low, _ = _run(engine.score("10.0.0.2", "safe.com", ml_score=0.0))
    high, _ = _run(engine.score("10.0.0.3", "evil.com", ml_score=1.0))
    assert high > low


def test_profile_created_and_tracks_query_count(engine):
    _run(engine.score("10.0.0.9", "a.com", ml_score=0.2))
    _run(engine.score("10.0.0.9", "b.com", ml_score=0.2))
    assert engine.profiles["10.0.0.9"].total_queries == 2


def test_critical_tier_for_maxed_out_signals(engine):
    score, level = _run(
        engine.score("10.0.0.5", "exfil.attacker.net", ml_score=1.0, intel_score=1.0)
    )
    assert score > 80
    assert level == RiskTier.CRITICAL.value
