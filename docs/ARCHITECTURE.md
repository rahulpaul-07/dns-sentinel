# Architecture and design decisions

This document explains how a DNS query becomes an alert, and why the system is
built the way it is. Model accuracy and its limits are covered separately in
[MODEL_CARD.md](../MODEL_CARD.md) and [BENCHMARK.md](../BENCHMARK.md).

## Components

```
 Zeek dns.log ──► POST /upload ─┐
 Browser ext. ──► POST /analyze ├─► services/analysis.analyze_dns ──► SQLite (audit_logs)
 scapy sniffer ─(opt-in)────────┘            │                       │
                                             ├─► SOAR orchestrator ──► security_rules (24h expiry)
                                             └─► SSE broadcast ─────► React dashboard
```

| Module | Responsibility |
|---|---|
| `backend/main.py` | App assembly only: config, CORS, lifespan tasks, routers, error handler |
| `backend/routers/` | One file per endpoint group; thin, no business logic |
| `backend/services/analysis.py` | The detection pipeline and the bulk-ingest worker |
| `backend/features.py` | 22 lexical features and `FEATURE_ORDER`, the single definition of the model input |
| `backend/model.py` | Cached model loading, calibrated threshold, optional DL scorer, hot-reload after retrain |
| `backend/risk_engine.py` | Blends ML, behaviour and intel into a 0-100 score and a tier |
| `backend/actions.py` | SOAR: validated block/sinkhole rules with auto-expiry, dry-run by default |
| `backend/zeek.py` | Header-driven Zeek `dns.log` parser shared by the upload endpoint and CLI |
| `backend/security.py` | Optional `X-API-Key` guard for state-changing routes |
| `backend/reports.py` | PDF rendering (Latin-1-safe) |

## Lifecycle of one query

1. **Validate.** `schemas.DNSLog` rejects empty or over-long names (RFC 1035:
   253 chars), anything that isn't printable ASCII without whitespace, and
   source IPs that don't parse. This matters beyond tidiness: the query text
   later reaches log files, PDFs and, for sinkholes, the hosts file.
2. **Temporal context.** `state.record_query` returns the source's queries in
   the last 60 s from a bounded, LRU-evicted history.
3. **Features.** `extract_features` computes entropy, English-bigram
   likelihood, character-run statistics and label structure;
   `feature_vector` orders them by `FEATURE_ORDER`.
4. **Model.** `model.predict` returns P(malicious) from the Random Forest (plus
   the DL DGA score when trained weights exist), the Isolation Forest verdict,
   and a SHAP explanation for anything flagged. Models are loaded once and
   cached in memory.
5. **Intel.** VirusTotal, AbuseIPDB and OTX run concurrently when keys are
   configured (cached in Redis if available); otherwise local heuristics are
   used (risky TLDs, tunnelling-tool keywords).
6. **Risk.** `risk_engine.score` computes
   `100 × (0.5·ml + 0.3·behaviour + 0.2·intel)`, where `ml` is the
   *calibrated* probability (see below).
7. **Tier.** Absolute cut points (25 / 50 / 80) always apply. Once a source
   has 15 scored queries, a score more than 2σ above its own history
   escalates one tier.
8. **Context.** Rule-based MITRE ATT&CK mapping (T1071.004, T1568, T1041), a
   plain-language explanation, and a PIE priority for triage ordering.
9. **Persist, respond, broadcast.** The row is written to SQLite. Scores above
   80 auto-create a 24 h IP block (dry-run by default). The result is pushed
   to every SSE subscriber.

## Decisions and trade-offs

**The threshold is calibrated, not defaulted.** 0.5 is a library default. The
threshold is chosen offline to maximise recall under a 5% false-positive
budget on cross-dataset scores, written to `models/calibration.json`, and
loaded by the API. On the exfil → DGA shift this cuts false positives from
407 to 21 at the same recall.

**The risk engine sees the calibrated score.** A threshold only changes the
label; the risk score blends the probability directly. With a threshold of
0.87, a raw 0.6 is a confident "benign", so `calibrated_score` maps the
threshold to 0.5 (piecewise-linear and monotonic, so ranking is unchanged)
before blending. Without this, ordinary names like `www.wikipedia.org` scored
Medium.

**Per-host baselining can escalate but never suppress.** An earlier version
tiered each source purely relative to its own history, so a persistently
malicious host became its own "normal" and its alerts were downgraded. It also
made a quiet host's harmless 5 → 11 blip "Critical" (11 > 1.5 × 7). Now
absolute tiers always hold, deviation adds at most one tier, and deviation
below a score of 15 is ignored as noise.

**Behavioural diversity needs a sample.** "Share of unique domains" is
meaningless for one query (trivially 100%), so it only counts once a source
has 5 queries in the window. A single query can therefore reach High but not
Critical; Critical requires behavioural evidence.

**SOAR is safe by default.** Every rule expires after 24 h, a background task
revokes expired rules each minute, infrastructure addresses are protected
(resolvers, gateway, loopback, `0.0.0.0`), and `SOAR_DRY_RUN=true` records
rules without touching the OS. When enforcement is enabled, targets are
validated with `ipaddress` / an RFC 1123 regex and commands are argument
lists, never shell strings. The sinkhole removes only the exact tagged line
it added.

**SSE instead of WebSockets for the feed.** The feed is one-way, SSE
reconnects natively, and it passes through proxies as plain HTTP. Each client
gets a bounded queue; a slow tab drops its oldest events rather than stalling
ingestion. The stream sends an opening frame immediately, because uvicorn
holds response headers until the first body chunk and `EventSource.onopen`
would otherwise wait for the first event.

**In-process state, deliberately.** Per-IP histories, risk profiles and SSE
queues live in memory and are bounded (LRU, 10k sources). This is correct for
a single worker. Horizontal scaling would move them to Redis and the ledger
to Postgres; the module boundaries (`state.py`, `database.py`) are where
that change would go.

**Optional auth, stated honestly.** Setting `API_KEY` protects mutating
endpoints with a constant-time `X-API-Key` check. A key compiled into a
browser bundle is not a secret, so this deters drive-by scripts on a public
demo; real multi-analyst use belongs behind SSO at a reverse proxy.

## Security notes

| Risk | Mitigation |
|---|---|
| Command injection via source IP | IP parsed with `ipaddress`; argv lists, no `shell=True` |
| Hosts-file injection via query | Printable-ASCII/no-whitespace validation, RFC 1123 check before sinkholing |
| CSV formula injection in exports | Cells starting with `= + - @` are prefixed with `'` |
| Error-detail leakage | Global handler logs server-side and returns a generic 500 |
| Unbounded memory from spoofed sources | LRU caps on every per-source map; bounded SSE queues |
| Oversized uploads | `MAX_UPLOAD_MB` (default 10) returns 413 |
| CORS misconfiguration | Credentials are disabled whenever the origin list is `*` |

## Testing

`backend/tests/` has 69 tests: feature extraction, risk-engine tiering
semantics, the model contract, calibration maths, metric drift against the
published README numbers, the Zeek parser, and HTTP-level API tests (input
validation, block → unblock → re-block lifecycle, whitelist refusal, PDF and
CSV exports, upload limits, auth, error redaction, SSE handshake). CI runs
them on Python 3.10 and 3.11, alongside ruff, the calibration step, a
frontend lint/build and an extension build.
