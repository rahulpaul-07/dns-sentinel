import time
import yaml
import numpy as np
import asyncio
import os
import logging
from typing import Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict, deque
from datetime import datetime

logger = logging.getLogger("DNSentinel.RiskEngine")

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "risk_baseline.yaml")

class RiskTier(Enum):
    MONITOR = "Low"
    ALERT = "Medium"
    BLOCK = "High"
    CRITICAL = "Critical"

_TIER_ORDER = [RiskTier.MONITOR, RiskTier.ALERT, RiskTier.BLOCK, RiskTier.CRITICAL]


@dataclass
class RiskProfile:
    source_ip: str
    current_score: float = 0.0
    score_history: deque = field(default_factory=lambda: deque(maxlen=100))
    query_history: deque = field(default_factory=lambda: deque(maxlen=500))
    tier: RiskTier = RiskTier.MONITOR
    last_seen: datetime = field(default_factory=datetime.now)
    total_queries: int = 0

class RiskEngine:
    # Bound per-source state so a spray of spoofed source IPs cannot grow
    # memory without limit; the least-recently-seen profile is evicted.
    MAX_PROFILES = 10_000
    MIN_DIVERSITY_SAMPLE = 5
    MIN_BASELINE_SAMPLES = 15   # history needed before a baseline is trusted
    ESCALATION_FLOOR = 15.0     # below this, deviation is noise, not signal

    @staticmethod
    def _static_tier(score: float) -> "RiskTier":
        if score > 80:
            return RiskTier.CRITICAL
        if score > 50:
            return RiskTier.BLOCK
        if score > 25:
            return RiskTier.ALERT
        return RiskTier.MONITOR

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.profiles: "OrderedDict[str, RiskProfile]" = OrderedDict()
        self.lock = asyncio.Lock()
        
        # Default config in case file is missing
        self.config = {
            'weights': {'ml': 0.5, 'behavior': 0.3, 'intel': 0.2},
            'sensitivity': {'k_factor': 2.0}
        }
        
        # Read-only: a missing file means "use defaults", never "write one to CWD".
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or self.config

        self.w_ml = self.config['weights']['ml']
        self.w_behavior = self.config['weights']['behavior']
        self.w_intel = self.config['weights']['intel']
        self.k_factor = self.config['sensitivity']['k_factor']

    def _compute_behavior_score(self, profile: RiskProfile) -> float:
        now = time.time()
        five_min_ago = now - 300
        recent = [q for q in profile.query_history if q[0] > five_min_ago]
        
        if not recent: return 0.0
        
        # Velocity score (queries per minute)
        velocity = len(recent) / 5.0
        v_score = min(velocity / 120.0, 1.0) # Normalized to 120 qpm
        
        # Domain diversity only means something once there is a burst to
        # measure; one query is trivially "100% unique".
        if len(recent) < self.MIN_DIVERSITY_SAMPLE:
            u_score = 0.0
        else:
            u_score = len(set(q[1] for q in recent)) / len(recent)
        
        return (v_score * 0.6) + (u_score * 0.4)

    async def score(self, source_ip: str, domain: str, ml_score: float, intel_score: float = 0.0) -> Tuple[float, str]:
        """
        Adaptive Scoring Logic
        Returns: (final_score 0-100, risk_level string)
        """
        async with self.lock:
            if source_ip not in self.profiles:
                self.profiles[source_ip] = RiskProfile(source_ip=source_ip)
                if len(self.profiles) > self.MAX_PROFILES:
                    self.profiles.popitem(last=False)
            self.profiles.move_to_end(source_ip)

            p = self.profiles[source_ip]
            p.last_seen = datetime.now()
            p.total_queries += 1
            p.query_history.append((time.time(), domain))
            
            behavior_score = self._compute_behavior_score(p)
            
            # Weighted Combine (0-1 range)
            combined_base = (self.w_ml * ml_score) + \
                           (self.w_behavior * behavior_score) + \
                           (self.w_intel * intel_score)
            
            final_score_raw = combined_base * 100
            
            # Absolute tiers always apply. Per-source baselining can only
            # *escalate*: a score more than k standard deviations above this
            # source's own history is unusual for that host and moves up one
            # tier. It can never suppress -- otherwise a persistently
            # malicious source would become its own "normal".
            tier = self._static_tier(final_score_raw)
            if len(p.score_history) > self.MIN_BASELINE_SAMPLES and final_score_raw >= self.ESCALATION_FLOOR:
                history = np.asarray(p.score_history)
                if final_score_raw > history.mean() + self.k_factor * history.std():
                    tier = _TIER_ORDER[min(_TIER_ORDER.index(tier) + 1, len(_TIER_ORDER) - 1)]

            p.current_score = final_score_raw
            p.score_history.append(final_score_raw)
            p.tier = tier
            
            return round(final_score_raw, 1), tier.value

# Singleton
risk_engine = RiskEngine()
