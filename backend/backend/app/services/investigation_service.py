"""
ThreatVision AI — Investigation Service
Core business logic for creating and managing investigations.
The API layer calls this; the service layer owns all DB writes.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import aiofiles
import structlog
from fastapi import UploadFile
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.investigation import (
    EvidenceFile,
    Investigation,
    InvestigationStatus,
)
from backend.app.schemas.investigation import InvestigationCreate, InvestigationOut
from backend.app.utils.file_utils import (
    build_storage_path,
    compute_sha256,
    detect_mime_type,
    get_evidence_type,
    is_allowed_extension,
    safe_filename,
    validate_file_size,
)

log = structlog.get_logger(__name__)


class InvestigationServiceError(Exception):
    """Raised for expected business logic errors (400-level)."""
    def __init__(self, message: str, code: str = "investigation_error"):
        self.message = message
        self.code = code
        super().__init__(message)


class InvestigationService:
    """
    Encapsulates all investigation business logic.
    Instantiated per-request via FastAPI dependency injection.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ── Create ────────────────────────────────────────────────────────────────

    async def create_investigation(
        self, payload: InvestigationCreate
    ) -> Investigation:
        """Create a new empty investigation record."""
        investigation = Investigation(
            title=payload.title,
            description=payload.description,
            status=InvestigationStatus.PENDING,
        )
        self.db.add(investigation)
        await self.db.flush()   # get the generated id without committing

        log.info(
            "investigation.created",
            investigation_id=investigation.id,
            title=payload.title,
        )
        return investigation

    # ── Upload evidence files ─────────────────────────────────────────────────

    async def upload_files(
        self,
        investigation_id: str,
        files: List[UploadFile],
    ) -> List[EvidenceFile]:
        """
        Accept one or more uploaded files, validate, store, and create
        EvidenceFile records.  Raises InvestigationServiceError on validation
        failures so the API layer can return clean 400 responses.
        """
        investigation = await self._get_or_404(investigation_id)

        # Guard: investigation must not already be running
        if investigation.status not in (
            InvestigationStatus.PENDING,
            InvestigationStatus.UPLOADING,
        ):
            raise InvestigationServiceError(
                f"Investigation {investigation_id} is in status "
                f"'{investigation.status}' and cannot accept new files.",
                code="invalid_status",
            )

        # Guard: file count limit
        existing_count = await self._count_evidence_files(investigation_id)
        from backend.app.config.settings import settings
        if existing_count + len(files) > settings.max_files_per_investigation:
            raise InvestigationServiceError(
                f"Upload would exceed the maximum of "
                f"{settings.max_files_per_investigation} files per investigation.",
                code="too_many_files",
            )

        investigation.status = InvestigationStatus.UPLOADING
        evidence_records: List[EvidenceFile] = []

        for upload in files:
            evidence = await self._process_single_upload(investigation_id, upload)
            evidence_records.append(evidence)
            self.db.add(evidence)

        await self.db.flush()

        log.info(
            "investigation.files_uploaded",
            investigation_id=investigation_id,
            file_count=len(evidence_records),
        )
        return evidence_records

    async def _process_single_upload(
        self, investigation_id: str, upload: UploadFile
    ) -> EvidenceFile:
        """Validate, save, and create one EvidenceFile record."""
        filename = upload.filename or "unnamed_file"

        # Extension check
        if not is_allowed_extension(filename):
            raise InvestigationServiceError(
                f"File type not allowed: '{Path(filename).suffix}'",
                code="unsupported_file_type",
            )

        # Read file content into memory (streaming for large files in Phase 3)
        content = await upload.read()
        size = len(content)

        # Size check
        ok, err = validate_file_size(size)
        if not ok:
            raise InvestigationServiceError(err, code="file_too_large")

        # Generate a unique evidence ID for path isolation
        import uuid
        evidence_id = str(uuid.uuid4())

        # Write to disk
        storage_path = build_storage_path(investigation_id, evidence_id, filename)
        async with aiofiles.open(storage_path, "wb") as f:
            await f.write(content)

        # Compute SHA-256 from disk (canonical)
        sha256 = compute_sha256(storage_path)
        mime_type = detect_mime_type(storage_path)
        evidence_type = get_evidence_type(filename)

        log.info(
            "evidence.uploaded",
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            filename=filename,
            size=size,
            sha256=sha256,
            evidence_type=evidence_type,
        )

        return EvidenceFile(
            id=evidence_id,
            investigation_id=investigation_id,
            original_filename=safe_filename(filename),
            storage_path=str(storage_path),
            file_size_bytes=size,
            sha256=sha256,
            mime_type=mime_type,
            evidence_type=evidence_type,
            parse_status="pending",
        )

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get_investigation(self, investigation_id: str) -> Investigation:
        return await self._get_or_404(investigation_id)

    async def list_investigations(
        self, limit: int = 20, offset: int = 0
    ) -> List[Investigation]:
        result = await self.db.execute(
            select(Investigation)
            .order_by(Investigation.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def get_evidence_files(
        self, investigation_id: str
    ) -> List[EvidenceFile]:
        await self._get_or_404(investigation_id)
        result = await self.db.execute(
            select(EvidenceFile)
            .where(EvidenceFile.investigation_id == investigation_id)
            .order_by(EvidenceFile.uploaded_at)
        )
        return list(result.scalars().all())

    # ── Status update (called by pipeline workers) ────────────────────────────

    async def update_status(
        self,
        investigation_id: str,
        status: InvestigationStatus,
        stage: Optional[str] = None,
        progress: Optional[int] = None,
        error: Optional[str] = None,
    ) -> None:
        investigation = await self._get_or_404(investigation_id)
        investigation.status = status
        if stage is not None:
            investigation.current_stage = stage
        if progress is not None:
            investigation.stage_progress = progress
        if error is not None:
            investigation.error_message = error
        if status == InvestigationStatus.COMPLETED:
            investigation.completed_at = datetime.now(timezone.utc)
        await self.db.flush()

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _get_or_404(self, investigation_id: str) -> Investigation:
        result = await self.db.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        investigation = result.scalar_one_or_none()
        if investigation is None:
            raise InvestigationServiceError(
                f"Investigation '{investigation_id}' not found.",
                code="not_found",
            )
        return investigation

    async def _count_evidence_files(self, investigation_id: str) -> int:
        result = await self.db.execute(
            select(func.count(EvidenceFile.id)).where(
                EvidenceFile.investigation_id == investigation_id
            )
        )
        return result.scalar_one()
