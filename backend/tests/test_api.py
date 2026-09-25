"""HTTP-level tests for the FastAPI app: contracts, validation, SOAR lifecycle, exports.

Runs against an isolated temp database (see conftest.py) with SOAR in dry-run.
"""
import pytest

pytest.importorskip("sklearn", reason="scikit-learn not installed")
pytest.importorskip("shap", reason="shap not installed")

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from config import settings  # noqa: E402

SAMPLE_ZEEK = """#separator \\x09
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name
1696951800.1\tC1\t10.0.0.5\t5353\t8.8.8.8\t53\tudp\t1\t0.01\twww.example.com\t1\tC_INTERNET\t1\tA
1696951801.1\tC2\t10.0.0.6\t5353\t8.8.8.8\t53\tudp\t2\t0.01\t-\t1\tC_INTERNET\t1\tA
"""


@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:
        c.post("/archive")
        yield c


def analyze(client, query, ip="10.1.2.3"):
    r = client.post("/analyze", params={"skip_intel": True, "skip_broadcast": True},
                    json={"query": query, "source_ip": ip})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- liveness
def test_health_and_version(client):
    h = client.get("/health")
    assert h.status_code == 200 and h.json()["database"] == "up"
    assert client.get("/version").json()["version"] == settings.VERSION


def test_model_endpoint_reports_calibrated_threshold(client):
    info = client.get("/model").json()
    assert 0.0 < info["decision_threshold"] <= 1.0
    assert info["dl_dga_model"] in ("loaded", "disabled")
    assert info["soar_dry_run"] is True


# ---------------------------------------------------------------- analysis
def test_analyze_contract(client):
    res = analyze(client, "www.google.com")
    for key in ("risk_score", "risk_level", "prediction", "priority", "priority_score",
                "features", "explanation", "db_id", "timestamp"):
        assert key in res
    assert res["risk_level"] in ("Low", "Medium", "High", "Critical")
    assert res["timestamp"].endswith("Z")


def test_random_label_scores_higher_than_dictionary_word(client):
    benign = analyze(client, "mail.google.com", ip="10.9.9.1")
    dga = analyze(client, "xk2j9qpz7vbm4n8rt5wq1y.com", ip="10.9.9.2")
    assert dga["risk_score"] > benign["risk_score"]


@pytest.mark.parametrize("payload", [
    {"query": ""},
    {"query": "a" * 300},
    {"query": "evil.com\n127.0.0.1 bank.com"},       # hosts-file injection attempt
    {"query": "ok.com", "source_ip": "not-an-ip"},
    {"query": "ok.com", "source_ip": "1.2.3.4; rm -rf /"},
])
def test_analyze_rejects_invalid_input(client, payload):
    assert client.post("/analyze", json=payload).status_code == 422


# ---------------------------------------------------------------- alerts
def test_alerts_filtering_and_bounds(client):
    assert client.get("/alerts", params={"risk_level": "bogus"}).status_code == 400
    assert client.get("/alerts", params={"limit": 0}).status_code == 422
    rows = client.get("/alerts", params={"limit": 5}).json()
    assert isinstance(rows, list) and len(rows) <= 5
    assert all(r["risk_level"] != "Low" for r in rows)


def test_stats_totals_are_consistent(client):
    s = client.get("/stats").json()
    assert s["total_requests"] == sum(s["risk_distribution"].values())


# ---------------------------------------------------------------- SOAR
def test_block_unblock_reblock_lifecycle(client):
    """Re-blocking a previously unblocked target used to hit a UNIQUE constraint."""
    log_id = analyze(client, "c2-beacon.example.net", ip="203.0.113.10")["db_id"]
    first = client.post(f"/alerts/{log_id}/block").json()
    assert first["status"] == "SUCCESS" and first["dry_run"] is True
    assert client.post(f"/alerts/{log_id}/block").json()["status"] == "SKIPPED"
    assert any(r["target"] == "203.0.113.10" for r in client.get("/blocked").json())

    assert client.post("/unblock/203.0.113.10").json()["status"] == "REMOVED"
    assert client.post("/unblock/203.0.113.10").status_code == 404
    assert client.post(f"/alerts/{log_id}/block").json()["status"] == "SUCCESS"


def test_whitelisted_and_invalid_targets_are_refused(client):
    log_id = analyze(client, "whatever.example.org", ip="8.8.8.8")["db_id"]
    assert client.post(f"/alerts/{log_id}/block").json()["status"] == "DENIED"
    assert client.post("/unblock/not a target").status_code == 400


def test_false_positive_feedback(client):
    log_id = analyze(client, "fp-check.example.com", ip="203.0.113.20")["db_id"]
    assert client.post(f"/alerts/{log_id}/feedback").json()["status"] == "FEEDBACK_RECORDED"
    report = client.get(f"/alerts/{log_id}/report").json()["markdown"]
    assert "False positive" in report
    assert client.post("/alerts/999999/feedback").status_code == 404


# ---------------------------------------------------------------- exports
def test_pdf_reports_render(client):
    log_id = analyze(client, "pdf-render.example.com")["db_id"]
    one = client.get(f"/alerts/{log_id}/pdf")
    assert one.status_code == 200 and one.content.startswith(b"%PDF")
    full = client.get("/export/pdf")
    assert full.status_code == 200 and full.content.startswith(b"%PDF")
    assert client.get("/alerts/999999/pdf").status_code == 404


def test_csv_export_neutralises_formula_injection(client):
    analyze(client, "=cmd.example.com")
    body = client.get("/export/alerts.csv").text
    assert body.splitlines()[0].startswith("timestamp,source_ip,query")
    assert "'=cmd.example.com" in body


# ---------------------------------------------------------------- ingest
def test_zeek_upload_is_parsed_by_header(client):
    before = client.get("/stats").json()["total_requests"]
    r = client.post("/upload", files={"file": ("dns.log", SAMPLE_ZEEK, "text/plain")})
    assert r.status_code == 200
    # BackgroundTasks run before TestClient returns; the '-' query row is skipped.
    assert client.get("/stats").json()["total_requests"] == before + 1


def test_upload_size_limit(client, monkeypatch):
    monkeypatch.setattr(settings, "MAX_UPLOAD_MB", 0)
    r = client.post("/upload", files={"file": ("big.csv", "query\nexample.com\n", "text/csv")})
    assert r.status_code == 413


def test_train_rejects_single_class(client):
    csv_body = "query,label\n" + "".join(f"site{i}.com,0\n" for i in range(10))
    r = client.post("/train", files={"file": ("t.csv", csv_body, "text/csv")})
    assert r.status_code == 400


# ---------------------------------------------------------------- auth
def test_api_key_guards_mutating_endpoints(client, monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "s3cret")
    assert client.post("/archive").status_code == 401
    assert client.post("/archive", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/unblock/203.0.113.99").status_code == 401
    # Read-only endpoints stay open.
    assert client.get("/stats").status_code == 200
    assert client.post("/archive", headers={"X-API-Key": "s3cret"}).status_code == 200


def test_errors_do_not_leak_internals(client, monkeypatch):
    import routers.traffic as traffic

    def boom(*a, **k):
        raise RuntimeError("secret path /etc/shadow")

    monkeypatch.setattr(traffic, "SessionLocal", boom)
    with TestClient(main.app, raise_server_exceptions=False) as c:
        r = c.get("/stats")
    assert r.status_code == 500 and "shadow" not in r.text


# ---------------------------------------------------------------- calibration
def test_calibrated_score_maps_threshold_to_midpoint():
    from model import calibrated_score, decision_threshold

    t = decision_threshold()
    assert calibrated_score(t) == pytest.approx(0.5)
    assert calibrated_score(0.0) == 0.0 and calibrated_score(1.0) == pytest.approx(1.0)
    probs = [i / 20 for i in range(21)]
    assert [calibrated_score(p) for p in probs] == sorted(calibrated_score(p) for p in probs)


@pytest.mark.parametrize("domain", ["www.wikipedia.org", "mail.google.com", "secure.microsoft.com"])
def test_common_benign_names_are_not_alerts(client, domain):
    """Regression: raw (uncalibrated) probabilities used to push these to Medium."""
    res = analyze(client, domain, ip="198.51.100.50")
    assert res["risk_level"] == "Low" and res["prediction"] == "Normal"


def test_sse_stream_opens_immediately():
    """The first frame must arrive before any event so EventSource.onopen fires."""
    import asyncio

    from routers.core import stream

    class _Req:
        async def is_disconnected(self):
            return True

    async def first_chunk():
        resp = await stream(_Req())
        return await resp.body_iterator.__anext__()

    assert asyncio.run(first_chunk()).startswith("retry:")
