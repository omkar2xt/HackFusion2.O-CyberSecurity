"""
SignalSafe Campus - Scan Schema Definitions
"""

from uuid import UUID
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict
from backend.app.schemas.common import (
    ScanVerdict,
    ScanRiskLevel,
    ScanIndicator,
)


class ScanResultResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    scan_id: UUID
    verdict: ScanVerdict
    risk_level: ScanRiskLevel
    risk_score: int = Field(..., ge=0, le=100)
    scoring_version: str = "v1.0.0"
    indicators: List[ScanIndicator] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mock_notice: Optional[str] = Field(
        default=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Actual detection logic is scheduled for Milestone 2."
        ),
        alias="_mock_notice",
        serialization_alias="_mock_notice",
    )


class ScanUrlRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        json_schema_extra={"example": "https://example.com/login"},
    )


class ScanMessageRequest(BaseModel):
    message_text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        json_schema_extra={"example": "Urgent: your account will be suspended. Verify at https://example.com/login"},
    )


class ScanMessageResponse(ScanResultResponse):
    extracted_urls: List[str] = Field(default_factory=list)
    analysis_scope: str = "EXTRACTED_URLS_AND_HEURISTICS"


class ScanQrRequest(BaseModel):
    decoded_content: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        json_schema_extra={"example": "https://example.com/payment"},
    )


class ScanQrResponse(ScanResultResponse):
    payload_type: str = Field(..., json_schema_extra={"example": "URL"})
