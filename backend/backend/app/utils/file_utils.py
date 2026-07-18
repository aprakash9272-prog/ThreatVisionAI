"""
ThreatVision AI — File Utilities
SHA256 hashing, MIME type detection, extension validation.
"""

import hashlib
import mimetypes
from pathlib import Path
from typing import Optional, Tuple

import structlog

from backend.app.config.settings import settings
from backend.app.models.investigation import EvidenceType

log = structlog.get_logger(__name__)

# Try to import python-magic for accurate MIME detection; fall back to mimetypes
try:
    import magic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False
    log.warning("python-magic not available; falling back to mimetypes")


# ── Extension → EvidenceType mapping ─────────────────────────────────────────

_EXT_TO_EVIDENCE_TYPE: dict[str, EvidenceType] = {
    ".eml":   EvidenceType.EMAIL,
    ".msg":   EvidenceType.EMAIL,
    ".evtx":  EvidenceType.EVTX,
    ".json":  EvidenceType.JSON,
    ".csv":   EvidenceType.CSV,
    ".pdf":   EvidenceType.PDF,
    ".txt":   EvidenceType.LOG,
    ".log":   EvidenceType.LOG,
    ".zip":   EvidenceType.ZIP,
    ".png":   EvidenceType.IMAGE,
    ".jpg":   EvidenceType.IMAGE,
    ".jpeg":  EvidenceType.IMAGE,
    ".docx":  EvidenceType.DOCX,
    ".xlsx":  EvidenceType.XLSX,
    ".pcap":  EvidenceType.PCAP,
    ".pcapng": EvidenceType.PCAP,
}


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 digest of a file. Streams in 8 MB chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_mime_type(file_path: Path) -> str:
    """
    Detect MIME type using python-magic (accurate) or mimetypes (fallback).
    python-magic reads the file magic bytes; mimetypes uses the extension.
    """
    if _MAGIC_AVAILABLE:
        try:
            return magic.from_file(str(file_path), mime=True)
        except Exception as exc:
            log.warning("mime_detection.magic_failed", path=str(file_path), error=str(exc))

    mime, _ = mimetypes.guess_type(str(file_path))
    return mime or "application/octet-stream"


def get_evidence_type(filename: str) -> EvidenceType:
    """Map a filename extension to an EvidenceType enum value."""
    ext = Path(filename).suffix.lower()
    return _EXT_TO_EVIDENCE_TYPE.get(ext, EvidenceType.UNKNOWN)


def is_allowed_extension(filename: str) -> bool:
    """Return True if the file extension is in the allowed list."""
    ext = Path(filename).suffix.lower()
    return ext in settings.ALLOWED_EXTENSIONS


def safe_filename(filename: str) -> str:
    """
    Sanitise a filename to prevent path traversal.
    Keeps only the final component and replaces dangerous characters.
    """
    name = Path(filename).name
    # Replace characters that could be dangerous on various filesystems
    for ch in r'\/:*?"<>|':
        name = name.replace(ch, "_")
    return name or "unnamed_file"


def human_size(size_bytes: int) -> str:
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} TB"


def build_storage_path(investigation_id: str, evidence_id: str, filename: str) -> Path:
    """
    Build the on-disk storage path for an uploaded file.
    Structure: uploads/<investigation_id>/<evidence_id>/<safe_filename>
    """
    safe_name = safe_filename(filename)
    path = settings.upload_dir / investigation_id / evidence_id / safe_name
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def validate_file_size(size_bytes: int) -> Tuple[bool, Optional[str]]:
    """
    Validate file size against the configured maximum.
    Returns (is_valid, error_message).
    """
    max_bytes = settings.max_upload_size_bytes
    if size_bytes > max_bytes:
        from backend.app.utils.file_utils import human_size
        return False, (
            f"File size {human_size(size_bytes)} exceeds "
            f"maximum allowed {human_size(max_bytes)}"
        )
    return True, None
