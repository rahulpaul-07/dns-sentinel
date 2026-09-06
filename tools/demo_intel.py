import asyncio
import logging
import json
from intel_service import intel_service

# Mock Log Input
TEST_DOMAIN = "malicious-phishing.top" # High risk TLD + keyword
TEST_IP = "192.168.1.150"

async def test_intel_pipeline():
    print(f"\n[] INITIALIZING THREAT INTEL TEST FOR: {TEST_DOMAIN} from {TEST_IP}")
    print("-" * 50)

    try:
        # Run enrichment
        results = await intel_service.enrich_query(TEST_DOMAIN, TEST_IP)

        # Output Results
        print(f"\n[] NORMALIZED RESULT:")
        print(json.dumps(results, indent=4))

        # Validation Logic
        if results['reputation_score'] > 20:
            print(f"\n[] TEST PASSED: Risk Detected (Score: {results['reputation_score']})")
        else:
            print(f"\n[] TEST WARNING: No risks detected for mock domain.")

    except Exception as e:
        print(f"\n[] TEST FAILED: Pipeline Exception - {e}")

if __name__ == "__main__":
    asyncio.run(test_intel_pipeline())
