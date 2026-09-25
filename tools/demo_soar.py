"""End-to-end SOAR walkthrough against a running API: analyze -> block -> list -> unblock.

    python tools/demo_soar.py [--api http://127.0.0.1:8001]

Uses a documentation-range IP (RFC 5737) so nothing real is ever targeted, and
the API's default SOAR_DRY_RUN=true means no firewall rule is actually applied.
"""
import argparse
import json
import os
import sys

import httpx

TEST_IP = "203.0.113.42"


def main(api: str) -> int:
    headers = {"X-API-Key": os.environ["API_KEY"]} if os.getenv("API_KEY") else {}
    with httpx.Client(base_url=api, timeout=30, headers=headers) as client:
        print("[1] Analyzing a suspicious query ...")
        res = client.post("/analyze", params={"skip_intel": True},
                          json={"query": "soar-test.exfil.xyz", "source_ip": TEST_IP}).json()
        print(f"    risk={res['risk_level']} ({res['risk_score']})  db_id={res.get('db_id')}")

        print("[2] Blocking the source ...")
        block = client.post(f"/alerts/{res['db_id']}/block").json()
        print("    " + json.dumps(block))

        print("[3] Active rules:")
        for rule in client.get("/blocked").json():
            print(f"    {rule['target']:<16} {rule['rule_type']:<16} expires {rule['expires_at']}")

        print("[4] Lifting the block ...")
        print("    " + json.dumps(client.post(f"/unblock/{TEST_IP}").json()))
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default=os.getenv("DNSENTINEL_API", "http://127.0.0.1:8001"))
    args = ap.parse_args()
    try:
        sys.exit(main(args.api))
    except httpx.HTTPError as e:
        sys.exit(f"Request failed: {e}. Is the API running on {args.api}?")
