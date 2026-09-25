"""Liveness, version, model info, SSE stream and WebSocket endpoints."""
import asyncio
import json
import logging
import os

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import text

from config import settings
from database import SessionLocal
from model import MODELS_DIR, decision_threshold, dga_model_ready
from state import manager

logger = logging.getLogger("DNSentinel")
router = APIRouter(tags=["core"])

SSE_HEARTBEAT_S = 15


@router.get("/")
async def root():
    return {"status": "DNSentinel backend online", "docs": "/docs", "version": settings.VERSION}


@router.get("/health")
async def health():
    """Liveness probe: 200 when the database answers, 503 otherwise."""
    db_ok = True
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Health check DB probe failed: %s", exc)
        db_ok = False
    return JSONResponse(
        status_code=200 if db_ok else 503,
        content={
            "status": "healthy" if db_ok else "degraded",
            "database": "up" if db_ok else "down",
            "version": settings.VERSION,
        },
    )


@router.get("/version")
async def version():
    return {"app": settings.APP_NAME, "version": settings.VERSION}


@router.get("/model")
async def model_info():
    """What is actually serving: threshold, DL scorer status, training provenance."""
    manifest = {}
    try:
        with open(os.path.join(MODELS_DIR, "metrics.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        pass
    return {
        "decision_threshold": decision_threshold(),
        "dl_dga_model": "loaded" if dga_model_ready() else "disabled",
        "soar_dry_run": settings.SOAR_DRY_RUN,
        "trained_on": manifest.get("dataset", {}).get("path"),
        "dataset_sha256": manifest.get("dataset", {}).get("sha256"),
        "holdout_metrics": manifest.get("metrics", {}).get("holdout_20pct"),
    }


@router.get("/stream")
async def stream(request: Request):
    """Server-Sent Events feed of every analysed query.

    Sends a comment heartbeat when idle so proxies keep the connection open
    and disconnected clients are noticed and cleaned up.
    """
    queue = manager.new_sse_queue()

    async def event_generator():
        # Flush headers immediately: uvicorn holds them until the first body
        # chunk, so without this the browser's `onopen` would not fire until
        # the first event or heartbeat. `retry` sets the reconnect delay.
        yield "retry: 3000\n: connected\n\n"
        try:
            while not await request.is_disconnected():
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=SSE_HEARTBEAT_S)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"data: {json.dumps(data, default=str)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            manager.drop_sse_queue(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep-alive; clients don't send commands
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)
