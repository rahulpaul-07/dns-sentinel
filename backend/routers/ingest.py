"""Bulk ingest, model retraining, and forensic archive endpoints."""
import csv
import io
import logging

import pandas as pd
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy import delete
from starlette.concurrency import run_in_threadpool

from config import settings
from database import DNSAuditLog, SecurityRule, SessionLocal
from features import FEATURE_ORDER, vectorize
from model import train_custom_model
from security import require_api_key
from services.analysis import process_csv_background
from state import alert_groups, alerts, ip_query_history, traffic_history

logger = logging.getLogger("DNSentinel")
router = APIRouter(tags=["ingest"], dependencies=[Depends(require_api_key)])

_LABELS = {"malicious": 1, "benign": 0, "1": 1, "0": 0, "true": 1, "false": 0}


async def _read_upload(file: UploadFile) -> str:
    limit = settings.MAX_UPLOAD_MB * 1024 * 1024
    contents = await file.read(limit + 1)
    if len(contents) > limit:
        raise HTTPException(413, f"file exceeds the {settings.MAX_UPLOAD_MB} MB upload limit")
    return contents.decode("utf-8", errors="replace")


@router.post("/upload")
async def upload_csv(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Accept a Zeek dns.log or CSV and stream it through the pipeline in the background."""
    decoded = await _read_upload(file)
    if not decoded.strip():
        raise HTTPException(400, "file is empty")
    background_tasks.add_task(process_csv_background, decoded)
    return {"status": "success", "message": "Ingest started. Results stream to the live feed."}


@router.post("/train")
async def train_model_endpoint(file: UploadFile = File(...)):
    """Retrain the ensemble on a labelled CSV (columns: query|domain and label)."""
    decoded = await _read_upload(file)
    rows = []
    for row in csv.DictReader(io.StringIO(decoded)):
        q = (row.get("query") or row.get("domain") or "").strip()
        raw = row.get("label", row.get("is_dga", row.get("malicious")))
        label = _LABELS.get(str(raw).strip().lower()) if raw is not None else None
        if not q or label is None:
            continue
        rows.append(vectorize(q) + [label])

    if not rows:
        raise HTTPException(400, "No valid rows found. The CSV needs 'query' (or 'domain') and 'label' columns.")

    df = pd.DataFrame(rows, columns=FEATURE_ORDER + ["label"])
    try:
        # CPU-bound: keep the event loop (and the live stream) responsive.
        metrics = await run_in_threadpool(train_custom_model, df)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"status": "success", "metrics": metrics, "rows_processed": len(rows)}


@router.post("/archive")
async def archive_and_clear():
    """Start a new case: wipe the audit ledger, SOAR rules and in-memory telemetry."""
    with SessionLocal() as db:
        db.execute(delete(DNSAuditLog))
        db.execute(delete(SecurityRule))
        db.commit()
    for buf in (traffic_history, alerts, ip_query_history, alert_groups):
        buf.clear()
    return {"status": "SUCCESS", "message": "Ledger cleared. New case started."}
