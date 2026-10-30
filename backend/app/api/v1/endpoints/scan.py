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

router = APIRouter(prefix="/scan", tags=["Scan"])

# Permitted schemes for safe web scanning
PERMITTED_SCHEMES = {"http", "https"}
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)


def validate_and_normalize_url(raw_url: str) -> str:
    """Safely parses and validates scheme and host for user-submitted URLs."""
    raw_url = raw_url.strip()
    if len(raw_url) > 2048:
        raise ValidationException("URL exceeds maximum permitted length of 2048 characters.")

    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except Exception:
        raise ValidationException("Malformed URL structure.")

    if not parsed.scheme or parsed.scheme.lower() not in PERMITTED_SCHEMES:
        raise ValidationException(
            f"Unsupported scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed."
        )

    if not parsed.netloc:
        raise ValidationException("URL must contain a valid host / domain name.")

    return raw_url


@router.post(
    "/url",
    response_model=ScanResultResponse,
    summary="Scan submitted URL",
    description="Analyzes a submitted URL for phishing indicators. (Milestone 1 Temporary Mock)",
)
async def scan_url(
    payload: ScanUrlRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanResultResponse:
    validated_url = validate_and_normalize_url(payload.url)

    # Temporary contract-compliant mock response
    return ScanResultResponse(
        scan_id=uuid4(),
        verdict=ScanVerdict.SUSPICIOUS,
        risk_level=ScanRiskLevel.HIGH,
        risk_score=78,
        scoring_version="v1.0.0",
        indicators=[
            ScanIndicator(
                code="LOOKALIKE_HOST",
                label="Possible lookalike domain",
                evidence_type=EvidenceType.HEURISTIC,
                detail=f"Target URL '{validated_url[:50]}' resembles a sensitive institution service.",
            )
        ],
        recommendations=[
            "Do not enter credentials or campus passwords.",
            "Access campus services using verified bookmarks or portals.",
        ],
        checked_at=datetime.now(timezone.utc),
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Authoritative detection engine logic is scheduled for Milestone 2."
        ),
    )


@router.post(
    "/message",
    response_model=ScanMessageResponse,
    summary="Scan message text and extracted URLs",
    description="Extracts URLs from message and evaluates risk indicators. (Milestone 1 Temporary Mock)",
)
async def scan_message(
    payload: ScanMessageRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanMessageResponse:
    text = payload.message_text
    extracted = URL_REGEX.findall(text)

    return ScanMessageResponse(
        scan_id=uuid4(),
        verdict=ScanVerdict.SUSPICIOUS if extracted else ScanVerdict.LOW_RISK,
        risk_level=ScanRiskLevel.MEDIUM if extracted else ScanRiskLevel.LOW,
        risk_score=60 if extracted else 20,
        scoring_version="v1.0.0",
        indicators=[
            ScanIndicator(
                code="URGENCY_LANGUAGE",
                label="Urgency cues detected in message",
                evidence_type=EvidenceType.HEURISTIC,
                detail="Message contains urgent phrases typical of phishing lures.",
            )
        ]
        if extracted
        else [],
        recommendations=[
            "Do not click links inside unsolicited or urgent messages.",
            "Verify any account inquiries directly with official campus IT.",
        ],
        checked_at=datetime.now(timezone.utc),
        extracted_urls=extracted,
        analysis_scope="EXTRACTED_URLS_AND_HEURISTICS",
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Authoritative message analysis engine is scheduled for Milestone 2."
        ),
    )


@router.post(
    "/qr",
    response_model=ScanQrResponse,
    summary="Scan decoded QR content",
    description="Evaluates decoded QR payload. (Milestone 1 Temporary Mock)",
)
async def scan_qr(
    payload: ScanQrRequest,
    current_user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> ScanQrResponse:
    content = payload.decoded_content.strip()
    is_url = bool(URL_REGEX.match(content))

    if is_url:
        validate_and_normalize_url(content)

    return ScanQrResponse(
        scan_id=uuid4(),
        verdict=ScanVerdict.LOW_RISK,
        risk_level=ScanRiskLevel.LOW,
        risk_score=15,
        scoring_version="v1.0.0",
        indicators=[],
        recommendations=[
            "No immediate malicious indicators detected in QR payload.",
            "Always inspect the destination address carefully before entering sensitive data.",
        ],
        checked_at=datetime.now(timezone.utc),
        payload_type="URL" if is_url else "RAW_TEXT",
        _mock_notice=(
            "Temporary contract-compliant mock response (Milestone 1). "
            "Actual QR analysis integration is scheduled for Milestone 2."
        ),
    )
