# Changelog

## 1.1.0: correctness and hardening audit

### Detection correctness
- The API now uses the calibrated decision threshold (0.873) from
  `models/calibration.json`; it previously hard-coded 0.5, despite the README
  documenting the calibrated operating point.
- The risk engine receives the calibrated ML score, so common benign names
  (`www.wikipedia.org`, `mail.google.com`) are no longer rated Medium.
- Per-host baselining can escalate a tier but no longer suppresses one, so a
  persistently malicious host no longer becomes its own baseline. Small
  deviations on quiet hosts are no longer promoted to Critical.
- Domain-diversity scoring needs at least 5 queries; one query no longer counts
  as a "100% unique" burst.
- The optional DL DGA scorer is only ensembled when trained weights load;
  previously an untrained network's output was averaged into every score when
  `torch` was installed.
- PIE attack-type weighting now works; it was always 0 because it looked up
  `"malicious"` in a table keyed by attack class.
- The extension's local scorer no longer uses random intel and behaviour
  inputs, and the LLM second opinion no longer adds random noise.

### Security
- SOAR: targets validated (`ipaddress` / RFC 1123) before any OS command;
  argv lists instead of `shell=True`; dry-run honoured for sinkholes;
  unspecified addresses protected; configurable via `SOAR_DRY_RUN`.
- Input validation for source IPs, control characters and whitespace in queries.
- Optional `X-API-Key` guard (constant-time) on state-changing endpoints.
- Upload size limit, CSV formula-injection protection, generic 500 responses,
  CORS credentials disabled for wildcard origins.
- Dependency upgrades clearing all known advisories (starlette, python-multipart,
  python-dotenv, scapy; unused aiohttp removed; frontend build tooling).
- Removed the unused native-messaging host and its `nativeMessaging` permission;
  the extension privacy statement now describes the actual data flow.

### Reliability and performance
- Models are cached in memory instead of loaded from disk on every request, and
  hot-swapped after `/train` (which now runs off the event loop).
- Re-blocking a previously unblocked target no longer violates a UNIQUE constraint.
- SOAR uses per-call DB sessions instead of one shared long-lived session.
- The SSE stream flushes headers immediately (the dashboard showed "reconnecting"
  until the first event) and sends heartbeats; slow clients drop old events
  instead of stalling ingestion.
- All per-source state is LRU-bounded.
- The Zeek parser reads the `#fields` header instead of assuming column indices;
  bulk ingest no longer crashes with a NameError at the end of Zeek uploads.
- PDF exports are Latin-1 safe.

### Dashboard and extension
- Every API call goes through one client (several calls bypassed it and broke on
  the deployed site); errors are surfaced to the analyst.
- Timestamps are UTC with `Z` and rendered in local time; the modal no longer
  crashes on records without an explanation, and MITRE IDs no longer render as
  "TT1071.004".
- Removed unsupported claims from the UI (hard-coded "F1 0.99", "AI model
  updated", "kernel modules"); the intro is shorter and skippable.
- The extension devtools page works under the MV3 CSP, and the popup no longer
  loads a remote script.

### Project
- 33 new tests (36 → 69): HTTP API, SOAR lifecycle, auth, exports, SSE, Zeek
  parsing, calibration mapping, tier semantics.
- CI: ruff lint gate, Node 22, extension build job.
- Docker: non-root backend image with baked models and a healthcheck; nginx
  frontend with an SSE-safe `/api` proxy; `docker compose up` runs the stack.
- Removed dead or fabricated code: a threat-hunt engine that returned random
  results, an unmounted CTGAN router, orphaned dashboard pages, a duplicate
  intel module, committed runtime files, and a broken ML pipeline script.
- New [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); README, MODEL_CARD,
  PIE_SCORE and contributor docs corrected to match the code.
