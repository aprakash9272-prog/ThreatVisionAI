"""
ThreatVision AI — Investigation API Routes

POST   /api/investigation/upload          Upload evidence files
POST   /api/investigation/start           Start investigation pipeline
GET    /api/investigation/{id}            Get investigation status + detail
GET    /api/investigation/{id}/timeline   Get attack timeline
GET    /api/investigation/{id}/iocs       Get extracted IOCs
GET    /api/investigation/{id}/mitre      Get MITRE ATT&CK mappings
GET    /api/investigation/{id}/rca        Get Root Cause Analysis
POST   /api/investigation/{id}/report     Generate and return report
GET    /api/investigations                List all investigations
"""

from typing import List, Optional

import structlog
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.models.investigation import (
    IOCType,
    InvestigationStatus,
)
from backend.app.schemas.investigation import (
    ChatRequest,
    ChatResponse,
    EvidenceFileOut,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationOut,
    IOCOut,
    MITREMappingOut,
    ReportOut,
    ReportRequest,
    TimelineEventOut,
)
from backend.app.services.investigation_service import (
    InvestigationService,
    InvestigationServiceError,
)

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/investigation", tags=["investigations"])


# ── Dependency ────────────────────────────────────────────────────────────────

def get_service(db: AsyncSession = Depends(get_db)) -> InvestigationService:
    return InvestigationService(db)


def _raise_service_error(exc: InvestigationServiceError) -> None:
    """Convert service layer errors to appropriate HTTP exceptions."""
    status_map = {
        "not_found":           status.HTTP_404_NOT_FOUND,
        "invalid_status":      status.HTTP_409_CONFLICT,
        "too_many_files":      status.HTTP_422_UNPROCESSABLE_ENTITY,
        "unsupported_file_type": status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        "file_too_large":      status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    }
    http_status = status_map.get(exc.code, status.HTTP_400_BAD_REQUEST)
    raise HTTPException(status_code=http_status, detail=exc.message)


# ── Upload evidence ───────────────────────────────────────────────────────────

@router.post(
    "/upload",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Upload evidence files",
    description=(
        "Creates a new investigation and uploads one or more evidence files. "
        "Returns the investigation ID and list of evidence records. "
        "Supported: .eml .msg .evtx .json .csv .pdf .txt .log .zip "
        ".png .jpg .docx .xlsx .pcap"
    ),
)
async def upload_evidence(
    files: List[UploadFile] = File(..., description="Evidence files to upload"),
    title: Optional[str] = Form(None, description="Investigation title"),
    description: Optional[str] = Form(None, description="Investigation description"),
    service: InvestigationService = Depends(get_service),
):
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one file must be provided.",
        )

    try:
        # Create investigation
        investigation = await service.create_investigation(
            InvestigationCreate(title=title, description=description)
        )

        # Upload files
        evidence_records = await service.upload_files(
            investigation_id=investigation.id,
            files=files,
        )

        return {
            "investigation_id": investigation.id,
            "status": investigation.status,
            "files_uploaded": len(evidence_records),
            "evidence": [
                {
                    "evidence_id": e.id,
                    "filename": e.original_filename,
                    "size_bytes": e.file_size_bytes,
                    "sha256": e.sha256,
                    "evidence_type": e.evidence_type,
                    "mime_type": e.mime_type,
                }
                for e in evidence_records
            ],
        }

    except InvestigationServiceError as exc:
        _raise_service_error(exc)


# ── Start investigation pipeline ──────────────────────────────────────────────

@router.post(
    "/start",
    response_model=dict,
    summary="Start investigation pipeline",
    description=(
        "Triggers the full investigation pipeline for an existing investigation. "
        "Processing runs asynchronously; use GET /{id} to poll status, "
        "or connect via WebSocket /ws/{id} for live updates."
    ),
)
async def start_investigation(
    investigation_id: str,
    background_tasks: BackgroundTasks,
    service: InvestigationService = Depends(get_service),
):
    try:
        investigation = await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    if investigation.status == InvestigationStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Investigation already completed. Create a new investigation to re-analyse.",
        )

    if investigation.status in (
        InvestigationStatus.PARSING,
        InvestigationStatus.EXTRACTING,
        InvestigationStatus.MAPPING,
        InvestigationStatus.ANALYZING,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Investigation is already running (status: {investigation.status}).",
        )

    evidence_files = await service.get_evidence_files(investigation_id)
    if not evidence_files:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No evidence files uploaded. Upload files before starting investigation.",
        )

    # TODO Phase 3+: background_tasks.add_task(run_pipeline, investigation_id)
    # Pipeline worker is implemented in Phase 3 (parsers) through Phase 7 (AI).
    # For now, acknowledge the request and return a queued status.

    log.info(
        "investigation.pipeline_queued",
        investigation_id=investigation_id,
        file_count=len(evidence_files),
    )

    return {
        "investigation_id": investigation_id,
        "status": "queued",
        "message": (
            "Investigation pipeline queued. "
            "Connect to ws://host/ws/{investigation_id} for live progress updates."
        ),
        "file_count": len(evidence_files),
    }


# ── Get investigation detail ──────────────────────────────────────────────────

@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetail,
    summary="Get investigation status and full detail",
)
async def get_investigation(
    investigation_id: str,
    service: InvestigationService = Depends(get_service),
):
    try:
        investigation = await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    # Build the detail response
    evidence_files = await service.get_evidence_files(investigation_id)

    detail = InvestigationDetail.model_validate(investigation)
    detail.evidence_files = [EvidenceFileOut.model_validate(e) for e in evidence_files]
    detail.file_count = len(evidence_files)
    return detail


# ── Timeline ──────────────────────────────────────────────────────────────────

@router.get(
    "/{investigation_id}/timeline",
    response_model=List[TimelineEventOut],
    summary="Get chronological attack timeline",
)
async def get_timeline(
    investigation_id: str,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: InvestigationService = Depends(get_service),
):
    try:
        await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    from sqlalchemy import select
    from backend.app.models.investigation import TimelineEvent
    db = service.db
    result = await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.investigation_id == investigation_id)
        .order_by(TimelineEvent.timestamp.asc().nullsfirst())
        .limit(limit)
        .offset(offset)
    )
    events = result.scalars().all()
    return [TimelineEventOut.model_validate(e) for e in events]


# ── IOCs ──────────────────────────────────────────────────────────────────────

@router.get(
    "/{investigation_id}/iocs",
    response_model=List[IOCOut],
    summary="Get all extracted IOCs",
)
async def get_iocs(
    investigation_id: str,
    ioc_type: Optional[IOCType] = Query(None, description="Filter by IOC type"),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    service: InvestigationService = Depends(get_service),
):
    try:
        await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    from sqlalchemy import select
    from backend.app.models.investigation import IOC
    db = service.db
    query = select(IOC).where(IOC.investigation_id == investigation_id)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    query = query.order_by(IOC.ioc_type, IOC.occurrence_count.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    iocs = result.scalars().all()
    return [IOCOut.model_validate(i) for i in iocs]


# ── MITRE Mappings ────────────────────────────────────────────────────────────

@router.get(
    "/{investigation_id}/mitre",
    response_model=List[MITREMappingOut],
    summary="Get MITRE ATT&CK technique mappings",
)
async def get_mitre(
    investigation_id: str,
    service: InvestigationService = Depends(get_service),
):
    try:
        await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    from sqlalchemy import select
    from backend.app.models.investigation import MITREMapping
    db = service.db
    result = await db.execute(
        select(MITREMapping)
        .where(MITREMapping.investigation_id == investigation_id)
        .order_by(MITREMapping.tactic, MITREMapping.technique_id)
    )
    mappings = result.scalars().all()
    return [MITREMappingOut.model_validate(m) for m in mappings]


# ── RCA ───────────────────────────────────────────────────────────────────────

@router.get(
    "/{investigation_id}/rca",
    response_model=dict,
    summary="Get Root Cause Analysis",
)
async def get_rca(
    investigation_id: str,
    service: InvestigationService = Depends(get_service),
):
    try:
        investigation = await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    if investigation.status != InvestigationStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail=f"RCA not available yet. Current status: {investigation.status}",
        )

    return {
        "investigation_id": investigation_id,
        "severity": investigation.severity,
        "risk_score": investigation.risk_score,
        "executive_summary":  investigation.executive_summary  or "Unable to determine from available evidence.",
        "root_cause":         investigation.root_cause         or "Unable to determine from available evidence.",
        "attack_narrative":   investigation.attack_narrative   or "Unable to determine from available evidence.",
        "business_impact":    investigation.business_impact    or "Unable to determine from available evidence.",
        "containment":        investigation.containment        or "Unable to determine from available evidence.",
        "recovery":           investigation.recovery           or "Unable to determine from available evidence.",
        "lessons_learned":    investigation.lessons_learned    or "Unable to determine from available evidence.",
        "recommendations":    investigation.recommendations    or "Unable to determine from available evidence.",
    }


# ── Report generation ─────────────────────────────────────────────────────────

@router.post(
    "/{investigation_id}/report",
    response_model=ReportOut,
    summary="Generate investigation report",
    description="Generate a downloadable report in the requested format.",
)
async def generate_report(
    investigation_id: str,
    request: ReportRequest,
    service: InvestigationService = Depends(get_service),
):
    try:
        investigation = await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    if investigation.status != InvestigationStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail="Report cannot be generated until the investigation is complete.",
        )

    # TODO Phase 8: report_service.generate(investigation_id, request.format)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Report generation will be implemented in Phase 8.",
    )


# ── AI Chat ───────────────────────────────────────────────────────────────────

@router.post(
    "/{investigation_id}/chat",
    response_model=ChatResponse,
    summary="Chat with AI about the investigation",
)
async def chat(
    investigation_id: str,
    request: ChatRequest,
    service: InvestigationService = Depends(get_service),
):
    try:
        investigation = await service.get_investigation(investigation_id)
    except InvestigationServiceError as exc:
        _raise_service_error(exc)

    if investigation.status != InvestigationStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail="Chat is available once the investigation is complete.",
        )

    # TODO Phase 7: ai_engine.chat(investigation_id, request)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="AI chat will be implemented in Phase 7.",
    )


# ── List all investigations ───────────────────────────────────────────────────

@router.get(
    "s",            # resolves to /api/investigations
    response_model=List[InvestigationOut],
    summary="List all investigations",
    tags=["investigations"],
)
async def list_investigations(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    service: InvestigationService = Depends(get_service),
):
    investigations = await service.list_investigations(limit=limit, offset=offset)
    results = []
    for inv in investigations:
        out = InvestigationOut.model_validate(inv)
        out.file_count = len(inv.evidence_files)
        results.append(out)
    return results
