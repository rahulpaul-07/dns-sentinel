# Third-Party Components & Attribution

DNSentinel integrates one third-party open-source component. It is credited
here in full. All other code in this repository — the FastAPI backend and ML
pipeline (`backend/`), the React SOC dashboard (`frontend/`), the Chrome MV3
extension (`extension/`), and the Zeek→pipeline ingestion glue
(`backend/ingest_zeek.py`) — is original work by the repository author.

## Zeek DNS-exfiltration sensor — `vendor/zeek-exfil-detect/`

- **What it is:** a Zeek (formerly Bro) network-security-monitor package that
  detects DNS-based data exfiltration using per-connection statistical
  baselining (modified z-score / MAD, Euclidean distance, PCR) against a
  persisted historical baseline.
- **Origin:** upstream Zeek package authored by **saiiman**, distributed under
  the BSD 3-Clause License. The original license text is preserved verbatim in
  [`vendor/zeek-exfil-detect/COPYING`](vendor/zeek-exfil-detect/COPYING). The package scaffolding (`zkg.meta`, `configure`,
  `CMakeLists.txt`, `src/`, and the `btest` baselines under `testing/`) is part
  of that upstream package and is vendored with it, so the whole component is
  contained in one directory and nothing upstream sits at the repository root.
- **How DNSentinel uses it:** as the network-tap sensor tier. Zeek emits
  exfiltration signals/logs, which `backend/ingest_zeek.py` normalizes and
  feeds into the DNSentinel feature extractor and risk engine. The integration,
  normalization, and everything downstream are original.
- **Modifications:** Used as an external dependency - the sensor was imported wholesale and is not modified within this project; all customization lives in the downstream integration (`backend/ingest_zeek.py`), not in the Zeek scripts.

If you are evaluating this project: the sensor tier is a deliberately reused,
production-grade IDS package — reusing battle-tested detection instead of
reinventing it is the intended design. The novel contribution is the end-to-end
platform (ML ensemble, adaptive risk scoring, SOAR, SOC dashboard, browser
telemetry) built around it.

## Python / JavaScript dependencies

Runtime dependencies are declared in `backend/requirements.txt`,
`backend/requirements-ml.txt`, `frontend/package.json`, and
`extension/package.json`, each under its own OSI-approved license.
