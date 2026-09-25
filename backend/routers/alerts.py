"""Alert ledger, per-alert reports/PDFs, and SOAR block/feedback actions."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from actions import orchestrator
from database import DNSAuditLog, SessionLocal
from reports import alert_pdf
from security import require_api_key
from state import VALID_RISK_LEVELS

router = APIRouter(tags=["alerts"])


def parse_risk_level(risk_level: Optional[str]) -> Optional[str]:
    """Normalise a risk_level query param, or 400 on an unknown tier."""
    if not risk_level:
        return None
    level = risk_level.strip().capitalize()
    if level not in VALID_RISK_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"invalid risk_level '{risk_level}'; expected one of {sorted(VALID_RISK_LEVELS)}",
        )
    return level


@router.get("/alerts")
async def get_alerts(
    response: Response,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    risk_level: Optional[str] = None,
):
    """Alerts from the ledger, newest first. Without a filter, Low-risk noise is excluded."""
    response.headers["Cache-Control"] = "no-store"
    level = parse_risk_level(risk_level)
    with SessionLocal() as db:
        query = db.query(DNSAuditLog)
        if level:
            query = query.filter(DNSAuditLog.risk_level == level)
        else:
            query = query.filter(DNSAuditLog.risk_level != "Low")
        logs = query.order_by(DNSAuditLog.id.desc()).offset(offset).limit(limit).all()
        return [log.to_dict() for log in logs]


@router.post("/alerts/{log_id}/block", dependencies=[Depends(require_api_key)])
async def block_host(log_id: int):
    """SOAR action: block the source IP behind an alert (24h auto-expiry)."""
    with SessionLocal() as db:
        log = db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
        if not log:
            raise HTTPException(404, "Alert not found")
        result = orchestrator.trigger_block(
            entity=log.source_ip,
            reason=f"Manual block from alert SOC-{log.id}",
            rule_type="IP_BLOCK",
            risk_score=log.risk_score,
        )
        if result["status"] in ("SUCCESS", "SKIPPED"):
            log.is_blocked = True
            db.commit()
        return result


@router.post("/alerts/{log_id}/feedback", dependencies=[Depends(require_api_key)])
async def log_feedback(log_id: int):
    """Analyst verdict: mark an alert as a false positive (and lift any block)."""
    result = orchestrator.mark_false_positive(log_id)
    if result["status"] == "NOT_FOUND":
        raise HTTPException(404, "Alert not found")
    return result


@router.get("/alerts/{log_id}/report")
async def generate_report(log_id: int):
    """Markdown incident report for one alert."""
    report = orchestrator.generate_incident_report(log_id)
    if not report:
        raise HTTPException(404, "Alert not found")
    return {"markdown": report}


@router.get("/alerts/{log_id}/pdf")
async def generate_pdf_report(log_id: int):
    """PDF incident report for one alert."""
    with SessionLocal() as db:
        log = db.query(DNSAuditLog).filter(DNSAuditLog.id == log_id).first()
        if not log:
            raise HTTPException(404, "Alert not found")
        content = alert_pdf(log)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="SOC_Incident_{log_id}.pdf"'},
    )
