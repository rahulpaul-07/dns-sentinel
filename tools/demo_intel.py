"""Run the threat-intel enrichment layer on one domain/IP and print the result.

    python tools/demo_intel.py [domain] [ip]

With no VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY set, only the
local heuristics (risky TLDs, tunnelling-tool keywords) contribute.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
from intel_service import intel_service  # noqa: E402


async def main(domain: str, ip: str):
    result = await intel_service.enrich_query(domain, ip)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "dnscat-tunnel.top"
    ip = sys.argv[2] if len(sys.argv) > 2 else "203.0.113.7"
    asyncio.run(main(domain, ip))
