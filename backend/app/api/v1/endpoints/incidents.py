"""
SignalSafe Campus - Incident Management Endpoints (Milestone 1 Contract Mocks)
"""

from uuid import UUID, uuid4
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from backend.app.schemas.incident import (
    CreateIncidentRequest,
    CreateIncidentResponse,
    IncidentDetailResponse,
    UpdateIncidentRequest,
    IncidentListResponse,
    IncidentNote,
    IncidentEvidence,
)
from backend.app.schemas.common import (
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
)
from backend.app.auth.dependencies import get_current_user, require_campus_admin
from backend.app.auth.token_validator import AuthenticatedUser

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.post(
    "",
    response_model=CreateIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a new incident report",
    description="Submits an incident report. Reporter identity is derived from the auth token.",
)
async def create_incident(
    payload: CreateIncidentRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> CreateIncidentResponse:
    # Server-side verification: reporter identity is derived exclusively from current_user.id
    new_id = uuid4()
    return CreateIncidentResponse(
        incident_id=new_id,
        status=IncidentStatus.SUBMITTED,
        created_at=datetime.now(timezone.utc),
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            f"Incident attributed to authenticated reporter '{current_user.id}'. "
            "Database persistence is scheduled for Milestone 2."
        ),
    )


@router.get(
    "",
    response_model=IncidentListResponse,
    summary="List incidents",
    description="Returns incidents visible to the caller based on role and campus tenancy.",
)
async def list_incidents(
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"),
    severity_filter: Optional[IncidentSeverity] = Query(None, alias="severity"),
    mine: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> IncidentListResponse:
    # Construct mock incident detail
    sample_id = UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    sample_incident = IncidentDetailResponse(
        id=sample_id,
        created_by=current_user.id if mine else UUID("00000000-0000-0000-0000-000000000001"),
        scan_id=UUID("3fa85f64-5717-4562-b3fc-2c963f66afa6"),
        category=IncidentCategory.PHISHING,
        severity=severity_filter or IncidentSeverity.HIGH,
        status=status_filter or IncidentStatus.INVESTIGATING,
        summary="Suspicious account verification message targeting campus email",
        description="I received an email stating that my campus password expired.",
        assigned_to=UUID("00000000-0000-0000-0000-000000000002"),
        campus_id=current_user.campus_id or UUID("11111111-1111-1111-1111-111111111111"),
        notes=[],
        evidence=[],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Database query filtering is scheduled for Milestone 2."
        ),
    )

    return IncidentListResponse(
        items=[sample_incident],
        total=1,
        page=page,
        page_size=page_size,
        pages=1,
        _mock_notice="Temporary contract-compliant mock response (Milestone 1).",
    )


@router.get(
    "/{id}",
    response_model=IncidentDetailResponse,
    summary="Get incident detail",
    description="Returns detailed incident record after checking authorization.",
)
async def get_incident_detail(
    id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> IncidentDetailResponse:
    return IncidentDetailResponse(
        id=id,
        created_by=current_user.id,
        scan_id=UUID("3fa85f64-5717-4562-b3fc-2c963f66afa6"),
        category=IncidentCategory.PHISHING,
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.INVESTIGATING,
        summary="Suspicious account verification message targeting campus email",
        description="I received an email stating that my campus password expired and asking to click a suspicious link.",
        assigned_to=UUID("00000000-0000-0000-0000-000000000002"),
        campus_id=current_user.campus_id or UUID("11111111-1111-1111-1111-111111111111"),
        notes=[
            IncidentNote(
                id=uuid4(),
                author_id=UUID("00000000-0000-0000-0000-000000000002"),
                note="Assigned to Security Operations. Lookalike domain confirmed.",
                created_at=datetime.now(timezone.utc),
            )
        ],
        evidence=[
            IncidentEvidence(
                id=uuid4(),
                evidence_type="user_report",
                storage_path=None,
                metadata={"source": "Extension", "url": "https://example.com/login"},
                created_at=datetime.now(timezone.utc),
            )
        ],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Database persistence and authorization checks are scheduled for Milestone 2."
        ),
    )


@router.patch(
    "/{id}",
    response_model=IncidentDetailResponse,
    summary="Update incident (Admin only)",
    description="Administrative updates for status, severity, assignment, or notes. (Admin only)",
)
async def update_incident(
    id: UUID,
    payload: UpdateIncidentRequest,
    admin_user: AuthenticatedUser = Depends(require_campus_admin),
) -> IncidentDetailResponse:
    return IncidentDetailResponse(
        id=id,
        created_by=UUID("00000000-0000-0000-0000-000000000001"),
        scan_id=UUID("3fa85f64-5717-4562-b3fc-2c963f66afa6"),
        category=IncidentCategory.PHISHING,
        severity=payload.severity or IncidentSeverity.HIGH,
        status=payload.status or IncidentStatus.INVESTIGATING,
        summary="Suspicious account verification message targeting campus email",
        description="Administrative update applied.",
        assigned_to=payload.assigned_to or admin_user.id,
        campus_id=admin_user.campus_id or UUID("11111111-1111-1111-1111-111111111111"),
        notes=[
            IncidentNote(
                id=uuid4(),
                author_id=admin_user.id,
                note=payload.note or "Admin status update applied.",
                created_at=datetime.now(timezone.utc),
            )
        ]
        if payload.note
        else [],
        evidence=[],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            f"Authorized by admin '{admin_user.id}'. Database update is scheduled for Milestone 2."
        ),
    )
