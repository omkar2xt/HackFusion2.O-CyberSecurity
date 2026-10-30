"""
SignalSafe Campus - Health Check Endpoint
"""

from fastapi import APIRouter
from backend.app.schemas.common import HealthResponse
from backend.app.core.config import settings

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check",
    description="Returns service health status without disclosing sensitive infrastructure.",
)
async def get_health() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        environment=settings.ENVIRONMENT,
    )
