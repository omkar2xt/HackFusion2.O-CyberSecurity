"""
SignalSafe Campus - Threat Scanning Endpoints (Milestone 1 Contract Mocks)
"""

import re
import urllib.parse
from uuid import uuid4
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends
from backend.app.schemas.scan import (
    ScanUrlRequest,
    ScanMessageRequest,
    ScanQrRequest,
    ScanResultResponse,
    ScanMessageResponse,
    ScanQrResponse,
    ScanDocumentRequest,
    ScanDocumentResponse,
    ScanCyberbullyingRequest,
    ScanCyberbullyingResponse,
)
from backend.app.schemas.common import (
    ScanVerdict,
    ScanRiskLevel,
    ScanIndicator,
    EvidenceType,
)
from backend.app.auth.dependencies import get_optional_current_user
from backend.app.auth.token_validator import AuthenticatedUser
from backend.app.core.errors import ValidationException

from backend.app.services.detection.hybrid_engine import detection_engine

router = APIRouter(prefix="/scan", tags=["Scan"])

# Permitted schemes for safe web scanning
PERMITTED_SCHEMES = {"http", "https"}
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)


def validate_and_normalize_url(raw_url: str) -> str:
    """Safely parses and validates scheme and host for user-submitted URLs."""
    return detection_engine.validate_and_normalize_url(raw_url)


@router.post(
    "/url",
    response_model=ScanResultResponse,
    summary="Scan submitted URL",
    description="Analyzes a submitted URL for phishing indicators using the hybrid detection engine.",
)
async def scan_url(
    payload: ScanUrlRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanResultResponse:
    return await detection_engine.analyze_url(payload.url, current_user=current_user)


@router.post(
    "/message",
    response_model=ScanMessageResponse,
    summary="Scan message text and extracted URLs",
    description="Extracts URLs from message and evaluates threat indicators using the hybrid detection engine.",
)
async def scan_message(
    payload: ScanMessageRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanMessageResponse:
    return await detection_engine.analyze_message(
        payload.message_text, current_user=current_user
    )


@router.post(
    "/qr",
    response_model=ScanQrResponse,
    summary="Scan decoded QR content",
    description="Evaluates decoded QR payload using the hybrid detection engine.",
)
async def scan_qr(
    payload: ScanQrRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanQrResponse:
    return await detection_engine.analyze_qr_payload(
        payload.decoded_content, current_user=current_user
    )

@router.post(
    "/document",
    response_model=ScanDocumentResponse,
    summary="Scan Office Attachment / Document",
    description="Evaluates Excel, Word, PDF, or HTML documents against CIC 2025 ML classifiers.",
)
async def scan_document(
    payload: ScanDocumentRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanDocumentResponse:
    return await detection_engine.analyze_document(
        file_name=payload.file_name,
        fmt=payload.format,
        details=payload.details,
        features=payload.features,
        current_user=current_user,
    )


@router.post(
    "/cyberbullying",
    response_model=ScanCyberbullyingResponse,
    summary="Scan Text for Harassment and Cyberbullying",
    description="Evaluates student communication against campus community safety heuristics.",
)
async def scan_cyberbullying(
    payload: ScanCyberbullyingRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanCyberbullyingResponse:
    return await detection_engine.analyze_cyberbullying(
        text=payload.text,
        current_user=current_user,
    )

