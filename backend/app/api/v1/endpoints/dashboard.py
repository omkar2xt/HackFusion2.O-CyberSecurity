"""
SignalSafe Campus - Dashboard Metrics Endpoint (Milestone 1 Contract Mocks)
"""

from fastapi import APIRouter, Depends
from backend.app.schemas.dashboard import DashboardStatsResponse
from backend.app.auth.dependencies import require_campus_admin
from backend.app.auth.token_validator import AuthenticatedUser

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/stats",
    response_model=DashboardStatsResponse,
    summary="Get administrative metrics",
    description="Returns aggregated metrics scoped to the administrator's campus tenancy.",
)
async def get_dashboard_stats(
    admin_user: AuthenticatedUser = Depends(require_campus_admin),
) -> DashboardStatsResponse:
    return DashboardStatsResponse(
        total_scans=142,
        total_incidents=28,
        open_incidents=9,
        resolved_incidents=19,
        incidents_by_severity={
            "LOW": 4,
            "MEDIUM": 12,
            "HIGH": 8,
            "CRITICAL": 4,
        },
        recent_activity_count=14,
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            f"Authorized for campus admin '{admin_user.id}'. Database analytics aggregation is scheduled for Milestone 2."
        ),
    )
