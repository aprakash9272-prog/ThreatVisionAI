"""
ThreatVision AI — Database Session
Async SQLAlchemy engine + session factory.
Works with SQLite (dev) and PostgreSQL (prod) via DATABASE_URL.
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.app.config.settings import settings
from backend.app.models.investigation import Base

import structlog

log = structlog.get_logger(__name__)

# ── Engine ────────────────────────────────────────────────────────────────────

def _build_engine() -> AsyncEngine:
    connect_args = {}
    if "sqlite" in settings.database_url:
        # SQLite requires check_same_thread=False for async use
        connect_args["check_same_thread"] = False

    return create_async_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_pre_ping=True,
        connect_args=connect_args,
    )


engine: AsyncEngine = _build_engine()

# ── Session factory ───────────────────────────────────────────────────────────

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ── Dependency for FastAPI routes ─────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an async database session.
    Rolls back on exception; always closes the session.

    Usage:
        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Lifecycle helpers ─────────────────────────────────────────────────────────

async def create_tables() -> None:
    """
    Create all tables defined in ORM models.
    Called once on application startup.
    In production, use Alembic migrations instead.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("database.tables_created")


async def drop_tables() -> None:
    """Drop all tables. Only used in tests."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    log.info("database.tables_dropped")


async def check_connection() -> bool:
    """Ping the database. Used by the health check endpoint."""
    try:
        async with engine.connect() as conn:
            from sqlalchemy import text
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        log.error("database.connection_failed", error=str(exc))
        return False
