"""
SignalSafe Campus - Incident Schema Definitions
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field, ConfigDict
from backend.app.schemas.common import (
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
)


class IncidentNote(BaseModel):
    id: UUID
    author_id: UUID
    note: str
    created_at: datetime


class IncidentEvidence(BaseModel):
    id: UUID
    evidence_type: str
    storage_path: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class CreateIncidentRequest(BaseModel):
    scan_id: Optional[UUID] = None
    category: IncidentCategory = Field(..., json_schema_extra={"example": IncidentCategory.PHISHING})
    summary: str = Field(
        ...,
        min_length=3,
        max_length=255,
        json_schema_extra={"example": "Suspicious account verification email"},
    )
    description: Optional[str] = Field(
        None,
        max_length=5000,
        json_schema_extra={"example": "Email asking to verify password immediately."},
    )
    evidence_refs: List[str] = Field(default_factory=list)


class CreateIncidentResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    incident_id: UUID
    status: IncidentStatus = IncidentStatus.SUBMITTED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mock_notice: Optional[str] = Field(
        default=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Database persistence is scheduled for Milestone 2."
        ),
        alias="_mock_notice",
        serialization_alias="_mock_notice",
    )


class IncidentDetailResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: UUID
    created_by: UUID
    scan_id: Optional[UUID] = None
    category: IncidentCategory
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.SUBMITTED
    summary: str
    description: Optional[str] = None
    assigned_to: Optional[UUID] = None
    campus_id: Optional[UUID] = None
    notes: List[IncidentNote] = Field(default_factory=list)
    evidence: List[IncidentEvidence] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    mock_notice: Optional[str] = Field(
        default=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Database persistence is scheduled for Milestone 2."
        ),
        alias="_mock_notice",
        serialization_alias="_mock_notice",
    )


class UpdateIncidentRequest(BaseModel):
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assigned_to: Optional[UUID] = None
    note: Optional[str] = Field(None, max_length=2000)


class IncidentListResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    items: List[IncidentDetailResponse]
    total: int
    page: int = 1
    page_size: int = 20
    pages: int = 1
    mock_notice: Optional[str] = Field(
        default="Temporary contract-compliant mock response (Milestone 1).",
        alias="_mock_notice",
        serialization_alias="_mock_notice",
    )
