"""
SignalSafe Campus - Dashboard Schema Definitions
"""

from typing import Dict, Optional
from pydantic import BaseModel, Field, ConfigDict


class DashboardStatsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    total_scans: int = Field(..., json_schema_extra={"example": 142})
    total_incidents: int = Field(..., json_schema_extra={"example": 28})
    open_incidents: int = Field(..., json_schema_extra={"example": 9})
    resolved_incidents: int = Field(..., json_schema_extra={"example": 19})
    incidents_by_severity: Dict[str, int] = Field(
        default_factory=lambda: {
            "LOW": 4,
            "MEDIUM": 12,
            "HIGH": 8,
            "CRITICAL": 4,
        }
    )
    recent_activity_count: int = Field(..., json_schema_extra={"example": 14})
    mock_notice: Optional[str] = Field(
        default=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Database analytics aggregation is scheduled for Milestone 2."
        ),
        alias="_mock_notice",
        serialization_alias="_mock_notice",
    )
