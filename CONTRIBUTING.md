# Contributing to DNSentinel

Thanks for your interest in improving DNSentinel! This guide covers how to get
a local environment running, the project layout, and the conventions we follow.

## Project layout

| Path | What lives here |
|------|-----------------|
| `backend/` | FastAPI service — ML inference, SSE streaming, SOAR actions, PDF reports |
| `frontend/` | Vite + React SOC dashboard |
| `extension/` | Manifest V3 Chrome extension for browser-level DNS telemetry |
| `data/` | Training / evaluation datasets and sample captures |
| `tools/` | Standalone scripts — `ml_pipeline.py`, `run_real_benchmark.py`, service demos |
| `docs/` | Generated figures |
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
uvicorn main:app --reload --port 8000
```

The API is then available at http://localhost:8000 (interactive docs at
`/docs`, health probe at `/health`, version at `/version`).

### Frontend (Node 20+)

```bash
cd frontend
npm install
npm run dev
```

Point the dashboard at your backend by setting `VITE_API_URL` in
`frontend/.env` if it isn't running on the default port.

## Running the tests

```bash
cd backend
pip install pytest
pytest -q
```

The fast feature/risk-engine tests run with no heavy dependencies; the ML
contract tests run automatically once `scikit-learn` and `shap` are installed
(they are part of `requirements.txt`). CI runs the full suite on every push.

## Coding conventions

- **Commits** use [Conventional Commits](https://www.conventionalcommits.org/)
  prefixes: `feat:`, `fix:`, `test:`, `docs:`, `ci:`, `refactor:`, `chore:`.
- Keep pull requests focused; one logical change per PR.
- Add or update tests for any behavioural change to the backend.
- Run `pytest -q` (backend) and `npm run build` (frontend) before opening a PR —
  both must pass, which CI enforces.

## Reporting issues

Open a GitHub issue with steps to reproduce, expected vs. actual behaviour, and
your environment (OS, Python/Node versions). Security-sensitive reports should
be raised privately with the maintainers rather than in a public issue.
