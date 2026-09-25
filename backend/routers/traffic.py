"""Recent-traffic feed and aggregate SOC statistics."""
from fastapi import APIRouter, Query, Response
from sqlalchemy import func

from database import DNSAuditLog, SessionLocal

router = APIRouter(tags=["traffic"])


@router.get("/traffic")
async def get_traffic(response: Response, limit: int = Query(100, ge=1, le=1000)):
    """Most recent analysed queries, newest first."""
    response.headers["Cache-Control"] = "no-store"
    with SessionLocal() as db:
        logs = db.query(DNSAuditLog).order_by(DNSAuditLog.id.desc()).limit(limit).all()
        return [log.to_dict() for log in logs]


@router.get("/stats")
async def get_stats():
    """Aggregate counts for the dashboard header (one GROUP BY, not four scans)."""
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    with SessionLocal() as db:
        rows = db.query(DNSAuditLog.risk_level, func.count(DNSAuditLog.id)) \
            .group_by(DNSAuditLog.risk_level).all()
    for level, count in rows:
        if level in distribution:
            distribution[level] = count
    total = sum(count for _, count in rows)
    return {
        "total_requests": total,
        "total_alerts": distribution["Critical"] + distribution["High"] + distribution["Medium"],
        "risk_distribution": distribution,
    }
