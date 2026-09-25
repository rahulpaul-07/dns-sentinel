# DNSentinel dashboard

React 19 + Vite SOC dashboard for the DNSentinel API: live triage feed over
Server-Sent Events, topology map, intel-driven hunting view, containment
ledger, and per-alert reports.

```bash
npm install
npm run dev        # http://localhost:5173, proxies /api to http://127.0.0.1:8001
npm run lint
npm run build      # static output in dist/
```

| Variable | When | Purpose |
|---|---|---|
| `BACKEND_URL` | dev server | Proxy target for `/api` (default `http://127.0.0.1:8001`) |
| `VITE_API_URL` | production build | Deployed API base URL; calls go there directly |
| `VITE_API_KEY` | optional | Sent as `X-API-Key` if the API sets `API_KEY` |

All HTTP access goes through [`src/services/api.js`](src/services/api.js), so
one build works behind the dev proxy, the Docker nginx proxy, or a separately
hosted API. See the [root README](../README.md) for the full system.
