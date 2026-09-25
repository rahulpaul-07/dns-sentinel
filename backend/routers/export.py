"""CSV and PDF forensic export endpoints."""
import csv
import io
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Response
from fastapi.responses import StreamingResponse

from database import DNSAuditLog, SessionLocal
from reports import ledger_pdf
from routers.alerts import parse_risk_level

router = APIRouter(tags=["export"])

CSV_COLUMNS = ["timestamp", "source_ip", "query", "qtype", "risk_score",
               "risk_level", "prediction", "priority", "is_false_positive", "mitre_ids"]


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (CWE-1236).

    A query like `=HYPERLINK(...)` is attacker-controlled input; prefixing a
    quote stops Excel/Sheets from evaluating it when an analyst opens the file.
    """
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _row(log: DNSAuditLog) -> list:
    return [_csv_safe(v) for v in (
        log.timestamp.isoformat() if log.timestamp else "",
        log.source_ip, log.query, log.qtype, log.risk_score, log.risk_level,
        log.prediction, log.priority, bool(log.is_false_positive),
        ", ".join(log.mitre_data.keys()) if log.mitre_data else "",
    )]


@router.get("/export")
async def export_logs():
    """Full ledger as CSV text wrapped in JSON (used by the dashboard's download button)."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_COLUMNS)
    with SessionLocal() as db:
        for log in db.query(DNSAuditLog).order_by(DNSAuditLog.id).yield_per(500):
            writer.writerow(_row(log))
    return {"csv": output.getvalue()}


@router.get("/export/alerts.csv")
async def export_alerts_csv(risk_level: Optional[str] = None):
    """Stream the ledger as a real text/csv attachment, optionally filtered by tier."""
    level = parse_risk_level(risk_level)

    def row_iter():
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CSV_COLUMNS)
        with SessionLocal() as db:
            q = db.query(DNSAuditLog)
            if level:
                q = q.filter(DNSAuditLog.risk_level == level)
            for log in q.order_by(DNSAuditLog.id.desc()).yield_per(500):
                writer.writerow(_row(log))
                if buffer.tell() > 64_000:
                    yield buffer.getvalue()
                    buffer.seek(0)
                    buffer.truncate(0)
        yield buffer.getvalue()

    filename = f"dnsentinel_alerts_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.csv"
    return StreamingResponse(
        row_iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/pdf")
async def export_pdf_report():
    """Audit report PDF over the whole ledger."""
    with SessionLocal() as db:
        logs = db.query(DNSAuditLog).order_by(DNSAuditLog.id.desc()).all()
        content = ledger_pdf(logs)
    filename = f"DNSentinel_Audit_{datetime.now(timezone.utc):%Y%m%d}.pdf"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
