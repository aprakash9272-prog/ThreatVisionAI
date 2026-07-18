"""
ThreatVision AI — Pydantic Schemas
Request/response models for the API layer.
Kept separate from ORM models (schemas vs models separation).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.investigation import (
    Confidence,
    EvidenceType,
    IOCType,
    InvestigationStatus,
    Severity,
)


# ── Shared base ───────────────────────────────────────────────────────────────

class ORMBase(BaseModel):
    """Base for all schemas that map from ORM models."""
    model_config = ConfigDict(from_attributes=True)


# ── Evidence File schemas ─────────────────────────────────────────────────────

class EvidenceFileOut(ORMBase):
    id: str
    original_filename: str
    file_size_bytes: int
    sha256: str
    mime_type: str
    evidence_type: EvidenceType
    parse_status: str
    parse_error: Optional[str] = None
    uploaded_at: datetime


class EvidenceFileDetail(EvidenceFileOut):
    """Extended evidence file info including parser output."""
    parsed_metadata: Optional[Dict[str, Any]] = None
    parsed_at: Optional[datetime] = None


# ── IOC schemas ───────────────────────────────────────────────────────────────

class IOCOut(ORMBase):
    id: str
    ioc_type: IOCType
    value: str
    confidence: Confidence
    is_malicious: Optional[bool] = None
    threat_score: Optional[float] = None
    tags: Optional[List[str]] = None
    source_line: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    occurrence_count: int
    evidence_file_id: Optional[str] = None


class IOCEnriched(IOCOut):
    """IOC with full threat intel enrichment data."""
    enrichment_data: Optional[Dict[str, Any]] = None
    enriched_at: Optional[datetime] = None


# ── Timeline schemas ──────────────────────────────────────────────────────────

class TimelineEventOut(ORMBase):
    id: str
    timestamp: Optional[datetime] = None
    timestamp_raw: Optional[str] = None
    event_type: str
    event_description: str
    event_source: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    confidence: Confidence
    severity: Severity
    evidence_file_id: Optional[str] = None


class TimelineEventDetail(TimelineEventOut):
    """Event with raw data."""
    raw_data: Optional[Dict[str, Any]] = None


# ── MITRE Mapping schemas ─────────────────────────────────────────────────────

class MITREMappingOut(ORMBase):
    id: str
    technique_id: str
    sub_technique_id: Optional[str] = None
    technique_name: str
    tactic: str
    tactic_name: str
    confidence: Confidence
    evidence_summary: str
    reasoning: str
    matched_keywords: Optional[List[str]] = None
    in_cisa_kev: bool
    mitre_url: Optional[str] = None


# ── Investigation schemas ─────────────────────────────────────────────────────

class InvestigationCreate(BaseModel):
    """Request body when creating a new investigation."""
    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)


class InvestigationOut(ORMBase):
    """Summary view — list endpoint."""
    id: str
    title: Optional[str] = None
    status: InvestigationStatus
    severity: Optional[Severity] = None
    risk_score: Optional[float] = None
    current_stage: Optional[str] = None
    stage_progress: int
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    file_count: int = 0         # computed field


class InvestigationDetail(InvestigationOut):
    """Full detail view — single investigation endpoint."""
    description: Optional[str] = None

    # AI-generated narrative
    executive_summary: Optional[str] = None
    root_cause: Optional[str] = None
    attack_narrative: Optional[str] = None
    business_impact: Optional[str] = None
    containment: Optional[str] = None
    recovery: Optional[str] = None
    lessons_learned: Optional[str] = None
    recommendations: Optional[str] = None

    # Related data
    evidence_files: List[EvidenceFileOut] = []
    iocs: List[IOCOut] = []
    timeline_events: List[TimelineEventOut] = []
    mitre_mappings: List[MITREMappingOut] = []


# ── Pipeline status (WebSocket payload) ──────────────────────────────────────

class PipelineStageStatus(BaseModel):
    """Status of a single pipeline stage."""
    stage_id: str
    stage_name: str
    status: str   # pending | running | done | error
    progress: int = 0
    message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class PipelineUpdate(BaseModel):
    """WebSocket message sent to the client during processing."""
    event: str = "pipeline_update"
    investigation_id: str
    overall_status: InvestigationStatus
    overall_progress: int
    current_stage: Optional[str] = None
    stages: List[PipelineStageStatus] = []
    partial_results: Optional[Dict[str, Any]] = None  # ioc_count, event_count, etc.


# ── Chat schemas ──────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str       # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    investigation_id: str
    message: str
    history: List[ChatMessage] = []


class ChatResponse(BaseModel):
    role: str = "assistant"
    content: str
    tokens_used: Optional[int] = None


# ── Report schemas ────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    investigation_id: str
    format: str = "markdown"     # markdown | html | pdf | docx | servicenow | json
    include_iocs: bool = True
    include_timeline: bool = True
    include_mitre: bool = True
    include_recommendations: bool = True


class ReportOut(BaseModel):
    id: str
    investigation_id: str
    report_format: str
    download_url: str
    file_size_bytes: int
    generated_at: datetime


# ── Generic responses ─────────────────────────────────────────────────────────

class HealthCheck(BaseModel):
    status: str = "ok"
    version: str
    environment: str
    database: str = "connected"
    timestamp: datetime


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None
