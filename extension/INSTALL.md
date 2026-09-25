# DNSentinel browser extension

A Manifest V3 extension that scores every domain the browser resolves. It
computes a local heuristic score instantly and, when the DNSentinel API is
reachable, replaces it with the API's ML verdict.

## Build

Requires Node.js 20.19+ (or 22.12+).

```bash
cd extension
npm install
npm run build        # outputs a loadable extension in extension/dist/
```

## Load in Chrome / Edge / Brave

1. Open `chrome://extensions` and enable **Developer mode**.
2. Click **Load unpacked** and select `extension/dist/`.

Load `dist/`, not the source folder: the DevTools panel is written in JSX and
only runs after the build.

## Connect it to the API

1. Start the backend (`python -m uvicorn main:app --port 8001` in `backend/`).
2. Open the extension popup → settings (gear icon). The backend URL defaults
   to `http://127.0.0.1:8001`.
3. Browse normally. Each new domain appears in the popup and in DevTools →
   **DNSentinel**, and is also written to the API's ledger, so it shows up on
   the dashboard.

Without the API the extension still works, using the local heuristics in
`background/heuristics.js`.

## Optional: LLM second opinion

Entering a Groq API key in settings adds an LLM assessment that is averaged
with the structural score (temperature 0, deterministic). Domain names are
then sent to Groq, so leave it empty if that is not acceptable.
