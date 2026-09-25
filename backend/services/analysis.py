"""Core detection pipeline and background workers.

analyze_dns is the heart of the service:
feature extraction -> ML ensemble -> adaptive risk scoring -> MITRE mapping ->
PIE prioritisation -> persistence -> SOAR auto-response -> live broadcast.
"""
import asyncio
import csv
import io
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import ValidationError

from actions import orchestrator
from behavioral import analyzer as behavioral_analyzer
from database import DNSAuditLog, SessionLocal, iso_utc
from features import extract_features, feature_vector
from intel_service import intel_service
from mitre import generate_explanation, map_threat
from model import calibrated_score, predict
from pie_engine import pie_engine
from risk_engine import risk_engine
from schemas import DNSLog
from state import alert_groups, alerts, manager, record_query, traffic_history
from zeek import iter_zeek_dns

logger = logging.getLogger("DNSentinel")

ALERT_LEVELS = ("Critical", "High", "Medium")
AUTO_BLOCK_SCORE = 80
ALERT_GROUP_WINDOW_S = 600
# Internal zones treated as high-value assets for prioritisation.
HIGH_VALUE_SUFFIXES = (".domain.local", ".corp.local")

# MITRE technique -> PIE attack class (most severe wins).
_ATTACK_BY_TECHNIQUE = [("T1041", "exfiltration"), ("T1071.004", "tunneling"), ("T1568", "DGA")]


def _attack_type(mitre_tags: Optional[dict]) -> str:
    for technique, attack in _ATTACK_BY_TECHNIQUE:
        if mitre_tags and technique in mitre_tags:
            return attack
    return "normal"


def _to_utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def _correlate(log: DNSLog, risk_level: str, result: dict):
    """Group alerts per source IP over a 10-minute window to cut duplicate noise."""
    if risk_level not in ALERT_LEVELS:
        return
    now = time.time()
    group = alert_groups.get(log.source_ip)
    if group is None or now - group["last_seen"] > ALERT_GROUP_WINDOW_S:
        if len(alert_groups) > 10_000:  # bound memory: drop stale groups
            for ip in [ip for ip, g in alert_groups.items() if now - g["last_seen"] > ALERT_GROUP_WINDOW_S]:
                del alert_groups[ip]
        alert_groups[log.source_ip] = {
            "id": f"ALERT-{int(now)}", "source_ip": log.source_ip, "severity": risk_level,
            "first_seen": now, "last_seen": now, "count": 1, "domains": [log.query],
        }
        alerts.append(result)
        return
    group["last_seen"] = now
    group["count"] += 1
    if log.query not in group["domains"] and len(group["domains"]) < 100:
        group["domains"].append(log.query)
    if risk_level == "Critical":
        alerts.append(result)


async def process_capture_packet(event: dict):
    """Bridge from the live packet sniffer into the analysis pipeline."""
    try:
        log_data = DNSLog(
            query=event.get("query_name") or "unknown",
            source_ip=event.get("src_ip") or "0.0.0.0",
            qtype=event.get("query_type") or "A",
        )
        await analyze_dns(log_data)
    except ValidationError:
        pass  # malformed/empty query names are common on the wire; skip them
    except Exception as e:
        logger.error("Live analysis bridge error: %s", e)


async def analyze_dns(log: DNSLog, skip_intel: bool = False, skip_broadcast: bool = False, db: Any = None):
    if not log.timestamp:
        log.timestamp = time.time()

    # 1. Temporal context: queries from this source in the last minute.
    frequency = record_query(log.source_ip, log.timestamp)

    # 2. Structural features -> model input vector.
    features = extract_features(log.model_dump())
    features["frequency"] = frequency
    vector = feature_vector(features)

    # 3. Behavioural burst analysis (velocity + domain diversity).
    behavior = behavioral_analyzer.analyze(log.source_ip, log.query)
    features["behavioral_metrics"] = behavior

    # 4. ML ensemble (RandomForest + IsolationForest [+ optional DL DGA scorer]).
    pred_label, mal_prob, iso_pred, shap_explanation = predict(vector, log.query)

    # 5. Threat intel: external providers, or local heuristics when skipped.
    if not skip_intel:
        intel_data = await intel_service.enrich_query(log.query, log.source_ip)
        intel_reputation = intel_data.get("reputation_score", 0)
        intel_hit = intel_data.get("is_malicious", False)
    else:
        local_intel = intel_service.check_local_heuristics(log.query)
        intel_reputation = local_intel["score"]
        intel_data = {"sources": ["Local Heuristics"], "threat_tags": local_intel["tags"],
                      "reputation_score": intel_reputation}
        intel_hit = intel_reputation > 30
    features["intel_data"] = intel_data

    # 6. Adaptive risk scoring (ML probability + per-source behaviour + intel).
    risk_score, risk_level = await risk_engine.score(
        source_ip=log.source_ip, domain=log.query,
        ml_score=calibrated_score(mal_prob), intel_score=intel_reputation / 100.0,
    )

    # 7. MITRE mapping and analyst-facing explanation.
    mitre_tags = map_threat(features, pred_label, iso_pred)
    explanation = generate_explanation(features, pred_label, iso_pred, risk_score)
    if shap_explanation:
        explanation = f"{explanation} | {shap_explanation}"

    is_malicious = pred_label == 1 or risk_level in ALERT_LEVELS
    result = {
        "timestamp": iso_utc(_to_utc(log.timestamp)),
        "query": log.query,
        "qtype": log.qtype,
        "source_ip": log.source_ip,
        "features": features,
        "prediction": "Malicious" if is_malicious else "Normal",
        "ml_probability": round(mal_prob, 3),
        "confidence": round(mal_prob if pred_label == 1 else 1 - mal_prob, 3),
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "isolation_outlier": iso_pred == -1,
        "behavioral_flags": {"burst": behavior["burst_detected"], "structured": behavior["structured_burst"]},
        "intel_hit": intel_hit,
        "mitre": mitre_tags,
    }

    _correlate(log, risk_level, result)
    traffic_history.append(result)

    # 8. PIE prioritisation (what should an analyst look at first?).
    pie_result = pie_engine.calculate_priority(
        risk_score=risk_score,
        intel_score=intel_reputation,
        asset_value=85 if log.query.endswith(HIGH_VALUE_SUFFIXES) else 50,
        behavior_score=behavior["behavior_score"],
        attack_type=_attack_type(mitre_tags),
    )
    pie_explanation = pie_result.pop("explanation", "")
    result.update(pie_result)
    result["explanation"] = " | ".join(p for p in (explanation, pie_explanation) if p)

    # 9. Persist, auto-respond, broadcast.
    active_db = db or SessionLocal()
    try:
        record = DNSAuditLog(
            source_ip=log.source_ip,
            query=log.query,
            qtype=log.qtype,
            risk_score=result["risk_score"],
            risk_level=risk_level,
            prediction=result["prediction"],
            priority=pie_result["priority"],
            priority_score=pie_result["priority_score"],
            mitre_data=mitre_tags,
            features=features,
            explanation=result["explanation"],
            timestamp=_to_utc(log.timestamp),
        )
        active_db.add(record)
        active_db.commit()
        active_db.refresh(record)
        result["db_id"] = record.id

        if risk_score > AUTO_BLOCK_SCORE:
            result["soar_action"] = orchestrator.trigger_block(
                entity=log.source_ip,
                reason=f"Auto-response: risk {risk_score} for {log.query}",
                risk_score=risk_score,
            )
    except Exception as e:
        logger.error("Persistence error: %s", e)
    finally:
        if not db:
            active_db.close()

    if not skip_broadcast:
        await manager.broadcast(result)
    return result


def _iter_csv_logs(content: str):
    """Yield DNSLog records from a CSV with a recognisable query column."""
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        q = next((row[c] for c in ("query", "domain", "dns_domain_name", "hostname", "url") if row.get(c)), None)
        if not q:
            continue
        src = row.get("source_ip") or row.get("src_ip") or row.get("client_ip") or "0.0.0.0"
        qt = row.get("qtype") or row.get("type") or "A"
        yield {"query": q, "source_ip": src, "qtype": qt}


async def process_csv_background(content: str, delay: float = 0.02) -> dict:
    """Stream an uploaded Zeek dns.log or CSV through the pipeline.

    The small per-row delay paces the live dashboard feed; rows that fail
    validation are counted and skipped rather than aborting the whole file.
    """
    is_zeek = content.lstrip().startswith("#separator")
    rows = iter_zeek_dns(content) if is_zeek else _iter_csv_logs(content)
    processed = skipped = 0
    logger.info("Ingest started (%s format, %d bytes)", "Zeek" if is_zeek else "CSV", len(content))
    try:
        with SessionLocal() as db_session:
            for row in rows:
                try:
                    log = DNSLog(**{**row, "timestamp": None})
                except ValidationError:
                    skipped += 1
                    continue
                await analyze_dns(log, skip_intel=True, db=db_session)
                processed += 1
                if delay:
                    await asyncio.sleep(delay)
    except Exception as e:
        logger.exception("Ingest aborted after %d rows: %s", processed, e)
    logger.info("Ingest finished: %d processed, %d skipped", processed, skipped)
    return {"processed": processed, "skipped": skipped}


async def soar_maintenance(interval_s: int = 60):
    """Background task: revoke expired SOAR rules."""
    while True:
        try:
            orchestrator.cleanup_expired_rules()
        except Exception as e:
            logger.error("SOAR maintenance error: %s", e)
        await asyncio.sleep(interval_s)
