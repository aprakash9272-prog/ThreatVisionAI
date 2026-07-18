"""
ThreatVision AI — Health Check
GET /api/health
"""

from datetime import datetime, timezone

from fastapi import APIRouter

from backend.app.config.settings import settings
from backend.app.database.session import check_connection
from backend.app.schemas.investigation import HealthCheck

router = APIRouter(tags=["health"])


@router.get(
    "/api/health",
    response_model=HealthCheck,
    summary="Health check",
    description="Returns service health, version, environment, and DB status.",
)
async def health_check():
    db_ok = await check_connection()
    return HealthCheck(
        status="ok" if db_ok else "degraded",
        version=settings.app_version,
        environment=settings.app_env,
        database="connected" if db_ok else "unreachable",
        timestamp=datetime.now(timezone.utc),
    )
