"""
SignalSafe Campus - Pydantic Schemas
"""

from backend.app.schemas.common import (
    ScanVerdict,
    ScanRiskLevel,
    EvidenceType,
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
    UserRole,
    ScanIndicator,
    HealthResponse,
    ErrorDetail,
    ErrorEnvelope,
)
from backend.app.schemas.scan import (
    ScanUrlRequest,
    ScanMessageRequest,
    ScanQrRequest,
    ScanResultResponse,
    ScanMessageResponse,
    ScanQrResponse,
)
from backend.app.schemas.incident import (
    CreateIncidentRequest,
    CreateIncidentResponse,
    IncidentDetailResponse,
    UpdateIncidentRequest,
    IncidentListResponse,
    IncidentNote,
    IncidentEvidence,
)
from backend.app.schemas.dashboard import DashboardStatsResponse

__all__ = [
    "ScanVerdict",
    "ScanRiskLevel",
    "EvidenceType",
    "IncidentCategory",
    "IncidentSeverity",
    "IncidentStatus",
    "UserRole",
    "ScanIndicator",
    "HealthResponse",
    "ErrorDetail",
    "ErrorEnvelope",
    "ScanUrlRequest",
    "ScanMessageRequest",
    "ScanQrRequest",
    "ScanResultResponse",
    "ScanMessageResponse",
    "ScanQrResponse",
    "CreateIncidentRequest",
    "CreateIncidentResponse",
    "IncidentDetailResponse",
    "UpdateIncidentRequest",
    "IncidentListResponse",
    "IncidentNote",
    "IncidentEvidence",
    "DashboardStatsResponse",
]
