"""
ThreatVision AI — Application Settings
Loaded from environment variables / .env file via Pydantic Settings.
"""

from functools import lru_cache
from pathlib import Path
from typing import List, Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    All application configuration.
    Values are read from environment variables (case-insensitive).
    .env file is loaded automatically if present.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "ThreatVision AI"
    app_version: str = "1.0.0"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = True
    secret_key: str = "dev-secret-change-in-production"

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    reload: bool = True

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./threatvision.db"
    database_echo: bool = False

    # ── File Storage ──────────────────────────────────────────────────────────
    upload_dir: Path = Path("./backend/app/uploads")
    investigation_dir: Path = Path("./backend/app/investigations")
    max_upload_size_mb: int = 100
    max_files_per_investigation: int = 20

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8080", "file://"]
    cors_allow_all: bool = True

    # ── WebSocket ─────────────────────────────────────────────────────────────
    ws_heartbeat_interval: int = 30

    # ── AI Provider ───────────────────────────────────────────────────────────
    ai_provider: Literal["mock", "anthropic", "openai"] = "mock"
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    ai_model: str = "claude-sonnet-4-6"
    ai_max_tokens: int = 4096
    ai_timeout_seconds: int = 60

    # ── Threat Intelligence ───────────────────────────────────────────────────
    ti_provider: Literal["mock", "virustotal", "misp", "opencti"] = "mock"
    virustotal_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    greynoise_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    mitre_stix_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    mitre_cache_ttl_hours: int = 24

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "console"
    log_file: str = "./logs/threatvision.log"

    # ── Redis / Celery ────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    use_celery: bool = False

    # ── Computed properties ───────────────────────────────────────────────────
    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @field_validator("upload_dir", "investigation_dir", mode="before")
    @classmethod
    def ensure_path(cls, v) -> Path:
        return Path(v)

    @model_validator(mode="after")
    def create_directories(self) -> "Settings":
        """Ensure storage directories exist on startup."""
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.investigation_dir.mkdir(parents=True, exist_ok=True)
        Path("./logs").mkdir(parents=True, exist_ok=True)
        return self

    # Allowed file extensions → MIME types
    ALLOWED_EXTENSIONS: dict = {
        ".eml":   "message/rfc822",
        ".msg":   "application/vnd.ms-outlook",
        ".evtx":  "application/octet-stream",
        ".json":  "application/json",
        ".csv":   "text/csv",
        ".pdf":   "application/pdf",
        ".txt":   "text/plain",
        ".log":   "text/plain",
        ".zip":   "application/zip",
        ".png":   "image/png",
        ".jpg":   "image/jpeg",
        ".jpeg":  "image/jpeg",
        ".docx":  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pcap":  "application/vnd.tcpdump.pcap",
        ".pcapng": "application/octet-stream",
    }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return cached Settings instance.
    Using lru_cache ensures Settings is only instantiated once per process.
    """
    return Settings()


# Module-level singleton for convenience
settings = get_settings()
