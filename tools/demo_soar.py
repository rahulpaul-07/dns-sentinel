import requests
import json
import time

API_BASE = "http://localhost:8000"

def test_soar_pipeline():
    print("\n--- DNSentinel SOAR Upgrade Test ---")

    # 1. Test Manual Blocking
    print("\n[STEP 1] Testing Manual IP Block...")
    # Trigger a real-time analysis first to get a log ID
    test_log = {"query": "soar-test.exfil.xyz", "source_ip": "1.2.3.4"}
    res = requests.post(f"{API_BASE}/analyze", json=test_log).json()
    log_id = res.get('db_id')

    if log_id:
        block_res = requests.post(f"{API_BASE}/alerts/{log_id}/block").json()
        print(f"Block Output: {json.dumps(block_res, indent=2)}")

        # 2. Verify List
        print("\n[STEP 2] Verifying Active Blocks List...")
        active = requests.get(f"{API_BASE}/blocked").json()
        print(f"Active Rules Count: {len(active)}")

        # 3. Test Unblock
        print("\n[STEP 3] Testing Manual Unblock...")
        unblock_res = requests.post(f"{API_BASE}/unblock/1.2.3.4").json()
        print(f"Unblock Output: {unblock_res}")

if __name__ == "__main__":
    try:
        test_soar_pipeline()
    except Exception as e:
        print(f"Test failed: {e}. Is the server running on {API_BASE}?")
