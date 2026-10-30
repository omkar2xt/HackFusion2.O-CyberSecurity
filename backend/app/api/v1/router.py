"""
SignalSafe Campus - API v1 Router
"""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    health,
    scan,
    incidents,
    dashboard,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(scan.router)
api_router.include_router(incidents.router)
api_router.include_router(dashboard.router)
