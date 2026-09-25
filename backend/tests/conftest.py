"""Test isolation: point the app at a throwaway SQLite file before it is imported.

database.py reads DNSENTINEL_DB_PATH at import time, so this must run before
any test module imports the app. Pytest loads conftest.py first.
"""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="dnsentinel-test-")
os.environ["DNSENTINEL_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["SOAR_DRY_RUN"] = "true"     # never touch a real firewall from tests
os.environ.pop("API_KEY", None)         # auth is exercised explicitly in test_api
os.environ["REDIS_HOST"] = "127.0.0.1"  # fail fast if Redis is absent
