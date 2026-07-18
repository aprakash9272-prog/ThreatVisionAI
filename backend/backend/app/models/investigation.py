"""
ThreatVision AI — Database Models
SQLAlchemy 2.0 ORM with async support.
Designed for SQLite (dev) and PostgreSQL (prod) without changes.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Enum,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ── Enums ─────────────────────────────────────────────────────────────────────

class InvestigationStatus(str, PyEnum):
    PENDING    = "pending"
    UPLOADING  = "uploading"
    PARSING    = "parsing"
    EXTRACTING = "extracting"
    MAPPING    = "mapping"
    ANALYZING  = "analyzing"
    COMPLETED  = "completed"
    FAILED     = "failed"


class EvidenceType(str, PyEnum):
    EMAIL      = "email"
    LOG        = "log"
    EVTX       = "evtx"
    JSON       = "json"
    CSV        = "csv"
    PDF        = "pdf"
    DOCX       = "docx"
    XLSX       = "xlsx"
    PCAP       = "pcap"
    IMAGE      = "image"
    ZIP        = "zip"
    UNKNOWN    = "unknown"


class IOCType(str, PyEnum):
    IPV4        = "ipv4"
    IPV6        = "ipv6"
    DOMAIN      = "domain"
    URL         = "url"
    MD5         = "md5"
    SHA1        = "sha1"
    SHA256      = "sha256"
    EMAIL_ADDR  = "email_address"
    USERNAME    = "username"
    HOSTNAME    = "hostname"
    PROCESS     = "process"
    SERVICE     = "service"
    REGISTRY    = "registry_key"
    MUTEX       = "mutex"
    POWERSHELL  = "powershell_command"
    SCHEDULED_TASK = "scheduled_task"
    CERTIFICATE = "certificate"
    CVE         = "cve"


class Confidence(str, PyEnum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ── Base ──────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Models ────────────────────────────────────────────────────────────────────

class Investigation(Base):
    """
    Root record for a single investigation session.
    One investigation can contain multiple evidence files.
    """
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus), default=InvestigationStatus.PENDING, index=True
    )
    severity: Mapped[Optional[Severity]] = mapped_column(Enum(Severity), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Pipeline stage tracking
    current_stage: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    stage_progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100

    # AI-generated outputs (stored as JSON strings)
    executive_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    attack_narrative: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    containment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recovery: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Error tracking
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    evidence_files: Mapped[list["EvidenceFile"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", lazy="selectin"
    )
    iocs: Mapped[list["IOC"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    timeline_events: Mapped[list["TimelineEvent"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    mitre_mappings: Mapped[list["MITREMapping"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Investigation id={self.id} status={self.status}>"


class EvidenceFile(Base):
    """
    A single uploaded file within an investigation.
    Stores file metadata and parser output.
    """
    __tablename__ = "evidence_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )

    # File metadata
    original_filename: Mapped[str] = mapped_column(String(512))
    storage_path: Mapped[str] = mapped_column(String(1024))
    file_size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    mime_type: Mapped[str] = mapped_column(String(128))
    evidence_type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType), default=EvidenceType.UNKNOWN
    )

    # Parser state
    parse_status: Mapped[str] = mapped_column(String(32), default="pending")
    parse_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parsed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Normalized output from parser (JSON)
    parsed_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Timestamps
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(back_populates="evidence_files")

    __table_args__ = (
        Index("idx_evidence_sha256_inv", "sha256", "investigation_id"),
    )

    def __repr__(self) -> str:
        return f"<EvidenceFile id={self.id} name={self.original_filename}>"


class IOC(Base):
    """
    An Indicator of Compromise extracted from evidence.
    Deduplicated per investigation by (type, value).
    """
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    evidence_file_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("evidence_files.id", ondelete="SET NULL"), nullable=True
    )

    ioc_type: Mapped[IOCType] = mapped_column(Enum(IOCType), index=True)
    value: Mapped[str] = mapped_column(Text, index=True)
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.MEDIUM)

    # Enrichment (populated by threat intel provider)
    is_malicious: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    threat_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    enrichment_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    enriched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Source context
    source_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(back_populates="iocs")

    __table_args__ = (
        UniqueConstraint("investigation_id", "ioc_type", "value", name="uq_ioc_per_investigation"),
    )

    def __repr__(self) -> str:
        return f"<IOC type={self.ioc_type} value={self.value[:40]}>"


class TimelineEvent(Base):
    """
    A single event in the attack timeline.
    Sourced from parsed evidence and ordered chronologically.
    """
    __tablename__ = "timeline_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    evidence_file_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("evidence_files.id", ondelete="SET NULL"), nullable=True
    )

    # Event data
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    timestamp_raw: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)  # original string
    event_type: Mapped[str] = mapped_column(String(64))          # e.g. "process_create"
    event_description: Mapped[str] = mapped_column(Text)
    event_source: Mapped[str] = mapped_column(String(256))        # file name or source

    # ATT&CK context
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    mitre_technique_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.MEDIUM)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)

    # Raw event data (JSON)
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(back_populates="timeline_events")

    def __repr__(self) -> str:
        return f"<TimelineEvent ts={self.timestamp} type={self.event_type}>"


class MITREMapping(Base):
    """
    A MITRE ATT&CK technique identified in an investigation.
    One record per unique technique per investigation.
    """
    __tablename__ = "mitre_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )

    technique_id: Mapped[str] = mapped_column(String(32), index=True)       # e.g. "T1059"
    sub_technique_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # e.g. "T1059.001"
    technique_name: Mapped[str] = mapped_column(String(256))
    tactic: Mapped[str] = mapped_column(String(64))                          # e.g. "execution"
    tactic_name: Mapped[str] = mapped_column(String(64))                     # e.g. "Execution"

    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.MEDIUM)

    # Evidence and reasoning
    evidence_summary: Mapped[str] = mapped_column(Text)
    reasoning: Mapped[str] = mapped_column(Text)
    matched_keywords: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    matched_ioc_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    matched_event_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # ATT&CK metadata
    in_cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    mitre_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(back_populates="mitre_mappings")

    __table_args__ = (
        UniqueConstraint("investigation_id", "technique_id", name="uq_technique_per_investigation"),
    )

    def __repr__(self) -> str:
        return f"<MITREMapping {self.technique_id} {self.technique_name}>"


class InvestigationReport(Base):
    """
    Generated reports for an investigation.
    Multiple formats can be stored per investigation.
    """
    __tablename__ = "investigation_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )

    report_format: Mapped[str] = mapped_column(String(16))   # pdf | markdown | html | docx | json
    storage_path: Mapped[str] = mapped_column(String(1024))
    file_size_bytes: Mapped[int] = mapped_column(Integer)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def __repr__(self) -> str:
        return f"<InvestigationReport format={self.report_format} investigation={self.investigation_id}>"
