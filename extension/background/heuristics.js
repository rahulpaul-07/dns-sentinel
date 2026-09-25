// Lightweight, deterministic port of the backend's structural features and
// PIE weighting, used for an instant in-browser score before (or without) the
// API's full ML verdict. Every input here is computed from observed data --
// nothing is randomised -- so the same browsing produces the same scores.

// Mirrors backend/intel_service.py check_local_heuristics().
const RISKY_TLDS = ['.xyz', '.top', '.pw', '.bid', '.monster', '.icu', '.cloud'];
const TUNNEL_KEYWORDS = ['tunnel', 'exfil', 'c2', 'dns-tunnel', 'iodine', 'dnscat'];

// Per-registrable-domain lookup timestamps for a 30 s burst window (mirrors
// backend/behavioral.py). Bounded so a long browsing session can't grow it.
const BURST_WINDOW_MS = 30_000;
const MAX_TRACKED = 2_000;
const recentLookups = new Map();

export function extractFeatures(domain) {
    const queryLower = domain.toLowerCase();
    const parts = queryLower.split('.');
    const subdomain = parts.length > 2 ? parts[0] : '';
    const length = queryLower.length;
    const consonants = queryLower.match(/[^aeiou0-9.-]/g) || [];
    const digits = queryLower.match(/[0-9]/g) || [];

    return {
        entropy: calculateEntropy(queryLower),
        length,
        subdomain_length: subdomain.length,
        consonant_ratio: consonants.length / (length || 1),
        digit_ratio: digits.length / (length || 1),
        labels: parts.length,
        labels_max: Math.max(...parts.map(p => p.length), 0),
    };
}

function calculateEntropy(str) {
    if (!str) return 0;
    const counts = {};
    for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
    return Object.values(counts).reduce((sum, n) => {
        const p = n / str.length;
        return sum - p * Math.log2(p);
    }, 0);
}

export function localIntelScore(domain) {
    const d = domain.toLowerCase();
    let score = 0;
    const tags = [];
    const tld = RISKY_TLDS.find(t => d.endsWith(t));
    if (tld) { score += 20; tags.push(`RiskTLD:${tld}`); }
    for (const kw of TUNNEL_KEYWORDS) {
        if (d.includes(kw)) { score += 25; tags.push(`SuspiciousKW:${kw}`); }
    }
    return { score: Math.min(score, 100), tags };
}

// Distinct subdomains of the same parent inside the window: many unique
// labels under one zone is the signature of tunnelling/exfiltration.
function behaviorScore(domain, now = Date.now()) {
    const parent = domain.split('.').slice(-2).join('.');
    const entries = (recentLookups.get(parent) || []).filter(e => now - e.t < BURST_WINDOW_MS);
    entries.push({ t: now, name: domain });
    recentLookups.delete(parent);            // re-insert = most recently used
    recentLookups.set(parent, entries);
    if (recentLookups.size > MAX_TRACKED) recentLookups.delete(recentLookups.keys().next().value);

    const unique = new Set(entries.map(e => e.name)).size;
    if (entries.length > 10 && unique >= entries.length * 0.8) return 30; // structured burst
    if (entries.length > 10) return 15;                                   // high velocity
    return 0;
}

export function calculateFallbackScore(features, domain) {
    // Structural risk from the lexical features.
    let risk_score = (features.entropy || 0) * 12;
    risk_score += Math.min(features.length || 0, 20);
    risk_score += (features.digit_ratio || 0) * 35;
    risk_score = Math.min(risk_score, 100);

    const intel = localIntelScore(domain);
    const behavior_score = behaviorScore(domain);
    const asset_value = 60; // a standard workstation

    const attack_weight = ((features.entropy || 0) > 4.2 || (features.length || 0) > 25) ? 40 : 0;

    // Same weights as backend/pie_engine.py.
    const weights = { risk_score: 0.35, intel_score: 0.25, asset_value: 0.20, behavior_score: 0.10, attack_weight: 0.10 };
    const pie_score = Math.min(Math.max(
        weights.risk_score * risk_score +
        weights.intel_score * intel.score +
        weights.asset_value * asset_value +
        weights.behavior_score * behavior_score +
        weights.attack_weight * attack_weight,
    0), 100);

    let priority = "MONITOR";
    if (pie_score >= 85) priority = "CRITICAL";
    else if (pie_score >= 70) priority = "BLOCK";
    else if (pie_score >= 50) priority = "ALERT";

    const tagText = intel.tags.length ? `, Tags: ${intel.tags.join(' ')}` : '';
    return {
        ml_score: pie_score / 100,
        isolation_score: 1,
        final_score: pie_score,
        shap_reason: `[Local heuristics] PIE ${pie_score.toFixed(1)} (${priority}). Structural: ${risk_score.toFixed(1)}, Intel: ${intel.score}, Burst: ${behavior_score}${tagText}`,
    };
}
