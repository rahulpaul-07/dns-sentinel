"""Replay a Zeek dns.log into a running DNSentinel API, one query at a time.

    python backend/ingest_zeek.py                          # bundled sample
    python backend/ingest_zeek.py /path/to/dns.log --api http://127.0.0.1:8001 --delay 0.5

For bulk loads prefer the dashboard's upload button (POST /upload), which
parses the same format server-side.
"""
import argparse
import os
import sys
import time

import httpx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from zeek import iter_zeek_dns  # noqa: E402

DEFAULT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "samples", "dns.log")


def replay(path: str, api: str, delay: float, api_key: str = "") -> int:
    headers = {"X-API-Key": api_key} if api_key else {}
    sent = 0
    with open(path, encoding="utf-8") as fh, httpx.Client(base_url=api, timeout=30, headers=headers) as client:
        for rec in iter_zeek_dns(fh):
            payload = {"query": rec["query"], "source_ip": rec["source_ip"], "qtype": rec["qtype"]}
            try:
                resp = client.post("/analyze", json=payload, params={"skip_intel": True})
                resp.raise_for_status()
                result = resp.json()
                print(f"[>] {rec['source_ip']:<15} {rec['query']:<50} -> "
                      f"{result.get('risk_level')} ({result.get('risk_score')})")
                sent += 1
            except httpx.HTTPError as e:
                print(f"[!] {rec['query']}: {e}", file=sys.stderr)
            time.sleep(delay)
    return sent


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="?", default=DEFAULT_LOG)
    ap.add_argument("--api", default=os.getenv("DNSENTINEL_API", "http://127.0.0.1:8001"))
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between queries")
    a = ap.parse_args()
    if not os.path.exists(a.log):
        sys.exit(f"Error: file not found: {a.log}")
    n = replay(a.log, a.api, a.delay, os.getenv("API_KEY", ""))
    print(f"[=] Replayed {n} queries from {a.log}")
