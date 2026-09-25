# DNSentinel: DNS Threat Detection in the Browser

## Description

DNSentinel scores every domain your browser resolves for signs of
algorithmically generated domains (DGA), DNS tunnelling and exfiltration.

- **Instant local scoring.** Entropy, character-mix and label-structure
  heuristics run in the service worker, together with a short-window burst
  detector that notices many unique subdomains under one zone.
- **ML verdicts from your own API.** Each domain is sent to a DNSentinel
  backend you run (default `http://127.0.0.1:8001`), which applies the Random
  Forest + Isolation Forest ensemble, the calibrated threshold and SHAP
  attribution.
- **Tiered response.** Monitor, Alert, Block or Critical. High-risk domains
  can be blocked with `declarativeNetRequest` rules that expire
  automatically.
- **DevTools panel.** A SOC-style view of every scored domain in the
  current session.

## Privacy and data flow

- **Heuristics run locally.** No data leaves the browser for the local score.
- **Domain names are sent to the backend URL you configure.** By default that
  is `127.0.0.1` (your own machine). If you point it at a remote server, that
  server receives every domain you visit.
- **Optional LLM second opinion.** If you enter a Groq API key in settings,
  domain names are also sent to Groq's API. It is off unless a key is set.
- **No telemetry.** The extension collects no analytics or usage data.

## Permission justifications

- `webRequest`: read the hostname of each outgoing request to score it.
- `declarativeNetRequest`: block domains rated Block/Critical, with auto-expiry.
- `storage`: settings, the domain whitelist and a 24-hour event cache (IndexedDB).
- `alarms`: expire block rules and prune the event cache.
- `notifications`: tell the user when a domain has been blocked.
- `tabs` / `activeTab`: attribute requests to a tab and show in-page warnings.
- `host_permissions` (`<all_urls>`): required to observe every hostname.
