"""DNSentinel backend: application assembly.

This module only wires configuration, middleware, background tasks and
routers. Business logic lives in `services/` and endpoint groups in
`routers/`. The ASGI entrypoint is `main:app`.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from database import init_db

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("DNSentinel")

# Create tables before importing modules that query them.
init_db()

from routers import alerts, analysis, core, export, ingest, soar, traffic  # noqa: E402
from services.analysis import process_capture_packet, soar_maintenance  # noqa: E402


def _start_live_capture():
    """Opt-in scapy sniffer (ENABLE_LIVE_CAPTURE=true; needs root/admin)."""
    try:
        import capture
        capture.start_capture(None, asyncio.get_running_loop(), process_capture_packet)
        logger.info("Live DNS capture enabled")
        return capture
    except Exception as e:  # missing scapy/Npcap or no privileges
        logger.warning("Live capture requested but unavailable: %s", e)
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    maintenance_task = asyncio.create_task(soar_maintenance())
    sniffer = _start_live_capture() if settings.ENABLE_LIVE_CAPTURE else None
    logger.info("DNSentinel %s started (SOAR dry-run=%s, API key %s)",
                settings.VERSION, settings.SOAR_DRY_RUN, "required" if settings.API_KEY else "not set")
    yield
    maintenance_task.cancel()
    if sniffer:
        sniffer.stop_capture()


app = FastAPI(
    title="DNSentinel API",
    description="DNS threat detection (DGA, tunneling, exfiltration) with SOAR-style response.",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Browsers reject credentialed requests to a wildcard origin, and the API uses
# header auth (not cookies), so credentials are only enabled for explicit origins.
_wildcard = "*" in settings.CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _wildcard else settings.CORS_ORIGINS,
    allow_credentials=not _wildcard,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)

for _module in (core, analysis, ingest, alerts, soar, traffic, export):
    app.include_router(_module.router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Log the detail server-side; never echo internals (paths, SQL) to clients.
    logger.error("Unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
