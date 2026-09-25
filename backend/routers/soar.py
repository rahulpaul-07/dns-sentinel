"""SOAR containment: list active blocks and manual unblock override."""
from fastapi import APIRouter, Depends, HTTPException

from actions import orchestrator
from security import require_api_key

router = APIRouter(tags=["soar"])


@router.post("/unblock/{entity}", dependencies=[Depends(require_api_key)])
async def unblock_entity(entity: str):
    """Analyst override: lift an active block on an IP or domain."""
    result = orchestrator.trigger_unblock(entity)
    if result["status"] == "INVALID":
        raise HTTPException(400, result["message"])
    if result["status"] == "NOT_FOUND":
        raise HTTPException(404, result["message"])
    return result


@router.get("/blocked")
async def list_blocked_entities():
    """All currently active SOAR rules."""
    return orchestrator.list_active()
