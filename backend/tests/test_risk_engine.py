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


def test_missing_config_uses_defaults_without_writing(tmp_path):
    cfg = tmp_path / "risk_baseline.yaml"
    engine = RiskEngine(config_path=str(cfg))
    assert not cfg.exists()  # never litter the working directory
    assert engine.w_ml == 0.5 and engine.k_factor == 2.0


def test_profiles_are_bounded(tmp_path):
    engine = RiskEngine(config_path=str(tmp_path / "none.yaml"))
    engine.MAX_PROFILES = 3
    for i in range(10):
        _run(engine.score(f"10.0.0.{i}", "example.com", ml_score=0.1))
    assert len(engine.profiles) == 3
    assert "10.0.0.9" in engine.profiles and "10.0.0.0" not in engine.profiles


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


def test_single_query_caps_at_high_without_behavioural_evidence(engine):
    """One query cannot show burst behaviour, so maxed ML + intel tops out at High."""
    score, level = _run(
        engine.score("10.0.0.5", "exfil.attacker.net", ml_score=1.0, intel_score=1.0)
    )
    assert score == 70.0
    assert level == RiskTier.BLOCK.value


def test_critical_tier_needs_a_diverse_burst(engine):
    """A burst of distinct maxed-out queries adds the behaviour term and goes Critical."""
    level = None
    for i in range(20):
        score, level = _run(
            engine.score("10.0.0.6", f"chunk{i}.exfil.attacker.net", ml_score=1.0, intel_score=1.0)
        )
    assert score > 80
    assert level == RiskTier.CRITICAL.value


def test_quiet_host_small_blip_is_not_escalated(engine):
    """Deviation below the absolute floor is noise: a 5 -> 11 blip stays Low."""
    for _ in range(20):
        _run(engine.score("10.0.0.7", "same.example.com", ml_score=0.1))
    _, level = _run(engine.score("10.0.0.7", "same.example.com", ml_score=0.22))
    assert level == RiskTier.MONITOR.value


def test_deviation_from_own_baseline_escalates_one_tier(engine):
    for _ in range(20):
        _run(engine.score("10.0.0.8", "same.example.com", ml_score=0.1))
    score, level = _run(engine.score("10.0.0.8", "odd.example.com", ml_score=0.6))
    assert 25 < score <= 50                   # static tier would be Medium ...
    assert level == RiskTier.BLOCK.value      # ... but it is unusual for this host
