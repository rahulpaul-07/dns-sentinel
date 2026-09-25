"""Single-query analysis endpoint (thin wrapper over services.analysis)."""
from fastapi import APIRouter

from schemas import DNSLog
from services.analysis import analyze_dns

router = APIRouter(tags=["analysis"])


@router.post("/analyze")
async def analyze_dns_endpoint(log: DNSLog, skip_intel: bool = False, skip_broadcast: bool = False):
    """Score one DNS query through the full pipeline and persist the result."""
    return await analyze_dns(log, skip_intel, skip_broadcast)
