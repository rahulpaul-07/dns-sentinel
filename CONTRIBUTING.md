# Contributing to DNSentinel

Thanks for your interest in improving DNSentinel! This guide covers how to get
a local environment running, the project layout, and the conventions we follow.

## Project layout

| Path | What lives here |
|------|-----------------|
| `backend/` | FastAPI service — ML inference, SSE streaming, SOAR actions, PDF reports |
| `frontend/` | Vite + React SOC dashboard |
| `extension/` | Manifest V3 browser extension (build with `npm run build`, load `dist/`) |
| `data/` | Training / evaluation datasets and sample captures |
| `tools/` | Standalone scripts: `run_real_benchmark.py`, `demo_soar.py`, `demo_intel.py` |
| `docs/` | [ARCHITECTURE.md](docs/ARCHITECTURE.md) and generated figures |
| `vendor/` | Third-party components, unmodified — see [THIRD_PARTY.md](THIRD_PARTY.md) |

Inside `backend/`, three modules are the source of truth for every number the
documentation quotes: `train.py` regenerates the models and their provenance
manifest, `evaluate.py` produces the hold-out and cross-dataset metrics, and
`calibrate.py` selects the decision threshold against a false-positive budget.
None of them should be edited without rerunning the others.

## Local development

### Backend (Python 3.10+)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example .env        # optional: fill in API keys
uvicorn main:app --reload --port 8001
```

The API is then available at http://127.0.0.1:8001 (interactive docs at
`/docs`, health probe at `/health`, serving model details at `/model`).

### Frontend (Node 20.19+ or 22.12+)

```bash
cd frontend
npm install
npm run dev
```

The dev server proxies `/api` to `http://127.0.0.1:8001`; set `BACKEND_URL`
to point it elsewhere. Production builds call `VITE_API_URL` directly (see
`frontend/.env.example`).

## Running the tests

```bash
cd backend
pip install pytest ruff
ruff check .
pytest -q
```

Tests use a throwaway SQLite file and force `SOAR_DRY_RUN=true` (see
`tests/conftest.py`), so they never touch your data or firewall. The suite
covers features, risk tiering, the model contract, calibration, metric drift
against the README, the Zeek parser and the HTTP API. CI runs it on every push.

## Coding conventions

- **Commits** use [Conventional Commits](https://www.conventionalcommits.org/)
  prefixes: `feat:`, `fix:`, `test:`, `docs:`, `ci:`, `refactor:`, `chore:`.
- Keep pull requests focused; one logical change per PR.
- Add or update tests for any behavioural change to the backend.
- Run `ruff check . && pytest -q` (backend) and `npm run lint && npm run build`
  (frontend) before opening a PR. CI enforces both.
- If a change moves a published metric, update README/MODEL_CARD in the same PR;
  `test_metric_drift.py` will fail until you do.

## Reporting issues

Open a GitHub issue with steps to reproduce, expected vs. actual behaviour, and
your environment (OS, Python/Node versions). Security-sensitive reports should
be raised privately with the maintainers rather than in a public issue.
