"""
ThreatVision AI — Backend Entry Point
Run with:  uvicorn main:app --reload
"""

from contextlib import asynccontextmanager

import structlog
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.investigations import router as investigation_router
from backend.app.api.websocket import ws_manager
from backend.app.config.settings import settings
from backend.app.database.session import create_tables
from backend.app.utils.logging import configure_logging

# ── Logging (must be first) ───────────────────────────────────────────────────
configure_logging()
log = structlog.get_logger(__name__)


# ── Application lifespan ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Runs on startup and shutdown.
    Startup:  initialise DB tables, log config summary.
    Shutdown: close DB connections, log goodbye.
    """
    log.info(
        "threatvision.starting",
        version=settings.app_version,
        environment=settings.app_env,
        database=settings.database_url.split("///")[0],  # don't log credentials
        ai_provider=settings.ai_provider,
        ti_provider=settings.ti_provider,
    )

    # Create DB tables (dev mode only — use Alembic in production)
    if settings.is_development:
        await create_tables()
        log.info("database.ready")

    yield  # application runs here

    log.info("threatvision.shutting_down")


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatVision AI",
    description=(
        "DFIR investigation platform. "
        "Upload evidence, extract IOCs, map MITRE ATT&CK, "
        "generate AI-powered Root Cause Analysis."
    ),
    version=settings.app_version,
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    lifespan=lifespan,
)


# ── CORS ──────────────────────────────────────────────────────────────────────

if settings.cors_allow_all:
    allow_origins = ["*"]
else:
    allow_origins = settings.cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(health_router)
app.include_router(investigation_router)


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws/{investigation_id}")
async def websocket_endpoint(websocket: WebSocket, investigation_id: str):
    """
    Real-time pipeline progress for a specific investigation.
    Frontend connects here immediately after starting an investigation.

    Messages sent by server:
        {"event": "pipeline_update", "investigation_id": "...", "stages": [...]}
        {"event": "pong"}
        {"event": "error", "message": "..."}

    Messages accepted from client:
        "ping"
    """
    await ws_manager.connect(websocket, investigation_id)
    log.info("ws.connection_opened", investigation_id=investigation_id)
    try:
        await ws_manager.listen(websocket, investigation_id)
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(websocket, investigation_id)
        log.info("ws.connection_closed", investigation_id=investigation_id)


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc: Exception):
    log.error(
        "unhandled_exception",
        path=str(request.url),
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.is_development else "An unexpected error occurred.",
        },
    )


# ── Root redirect ─────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "ThreatVision AI Backend",
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/api/health",
    }


# ── Dev runner ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        workers=1 if settings.reload else settings.workers,
        log_config=None,    # structlog handles logging
    )
