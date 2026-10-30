"""
SignalSafe Campus - Hybrid Detection Engine Coordinator
Module: backend/app/services/detection/hybrid_engine.py

Integrates ML inference, deterministic rule evaluation, external threat intelligence,
QR decoding, and message URL extraction into a unified detection workflow.
Preserves existing OpenAPI contract specifications and response models.
"""

from datetime import datetime, timezone
import re
from typing import List, Optional
from uuid import uuid4

from backend.app.auth.token_validator import AuthenticatedUser
from backend.app.core.errors import ValidationException
from backend.app.schemas.common import EvidenceType, ScanIndicator, ScanRiskLevel, ScanVerdict
from backend.app.schemas.scan import (
    ScanMessageResponse,
    ScanQrResponse,
    ScanResultResponse,
)
from backend.app.services.detection.correlation import evidence_correlator
from backend.app.services.detection.explanations import explanation_generator
from backend.app.services.detection.model_adapters import model_registry
from backend.app.services.detection.qr import qr_analyzer
from backend.app.services.detection.rules import rule_engine
from backend.app.services.detection.scoring import risk_scoring_service
from backend.app.services.detection.threat_intel import threat_intel_service
from backend.app.services.detection.url_features import (
    extract_url_features,
    normalize_url,
)

# Permitted schemes for safe web scanning
PERMITTED_SCHEMES = frozenset({"http", "https"})

# URL extraction regex for message text parsing
URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)

# Urgency keywords indicative of social engineering phishing lures
URGENCY_KEYWORDS = (
    "urgent", "immediately", "immediate action", "suspend", "suspended",
    "account closure", "unauthorized access", "compromised", "verify your identity",
    "security alert", "within 24 hours", "action required", "payroll update",
)


class DetectionEngine:
    """Master coordinator for hybrid threat detection."""

    def __init__(self):
        self.rule_engine = rule_engine
        self.threat_intel = threat_intel_service
        self.model_registry = model_registry
        self.qr_analyzer = qr_analyzer
        self.correlator = evidence_correlator
        self.scorer = risk_scoring_service
        self.explainer = explanation_generator

    def validate_and_normalize_url(self, raw_url: str) -> str:
        """Validates input URL bounds, scheme restrictions, and structure."""
        if not raw_url or not isinstance(raw_url, str):
            raise ValidationException("URL must be a non-empty string.")

        clean = raw_url.strip()
        if len(clean) > 2048:
            raise ValidationException("URL exceeds maximum permitted length of 2048 characters.")

        # Strict scheme validation before deep parsing
        colon_idx = clean.find(":")
        if colon_idx != -1:
            scheme_prefix = clean[:colon_idx].lower()
            if scheme_prefix not in PERMITTED_SCHEMES:
                raise ValidationException(
                    f"Unsupported scheme '{scheme_prefix}'. Only 'http' and 'https' are allowed."
                )
        else:
            raise ValidationException("URL must specify a permitted scheme ('http' or 'https').")

        norm = normalize_url(clean)
        if not norm.is_valid:
            raise ValidationException(f"Invalid URL: {norm.error_reason or 'Malformed structure'}")

        if norm.scheme not in PERMITTED_SCHEMES:
            raise ValidationException(
                f"Unsupported scheme '{norm.scheme}'. Only 'http' and 'https' are allowed."
            )

        if not norm.hostname:
            raise ValidationException("URL must contain a valid host / domain name.")

        return clean

    async def analyze_url(
        self,
        url: str,
        current_user: Optional[AuthenticatedUser] = None,
    ) -> ScanResultResponse:
        """
        Executes hybrid threat evaluation on a target URL:
        1. Feature extraction (34 features).
        2. Rule engine evaluation.
        3. Parallel threat intelligence lookups (Google Safe Browsing, VirusTotal, URLhaus).
        4. ML model inference (Model A / mock adapter).
        5. Evidence correlation (anti-double-counting).
        6. Risk scoring & explanation generation.
        """
        valid_url = self.validate_and_normalize_url(url)
        features = extract_url_features(valid_url)

        # 1. Rule Engine
        rule_res = self.rule_engine.evaluate(features)

        # 2. External Threat Intelligence
        ti_res = await self.threat_intel.query_all(valid_url)

        # 3. ML Model Inference
        url_model = self.model_registry.get_url_model()
        url_pred = url_model.predict(features)

        # 4. Evidence Correlation
        evidence = self.correlator.correlate(
            target_type="URL",
            target=valid_url,
            rule_result=rule_res,
            threat_intel_results=ti_res.results,
            url_prediction=url_pred,
        )

        # 5. Risk Scoring
        scoring = self.scorer.calculate_score(evidence)

        # 6. Explanations & Recommendations
        recommendations = self.explainer.generate_recommendations(evidence, scoring)
        indicators = evidence.indicators

        # Notice for contract compatibility
        mock_note = (
            "Hybrid detection engine evaluated deterministic rules and external threat intelligence. "
            "ML URL classifier operated via verified contract adapter."
        )

        return ScanResultResponse(
            scan_id=uuid4(),
            verdict=scoring.verdict,
            risk_level=scoring.risk_level,
            risk_score=scoring.risk_score,
            scoring_version=scoring.scoring_version,
            indicators=indicators,
            recommendations=recommendations,
            checked_at=datetime.now(timezone.utc),
            mock_notice=mock_note,
        )

    async def analyze_qr_payload(
        self,
        decoded_content: str,
        current_user: Optional[AuthenticatedUser] = None,
    ) -> ScanQrResponse:
        """
        Evaluates decoded QR content.
        Routes URLs through full URL inspection pipeline.
        Applies security heuristics to non-URL payloads.
        """
        clean = decoded_content.strip()
        if not clean:
            raise ValidationException("Decoded QR content cannot be empty.")

        entry = self.qr_analyzer.analyze_decoded_text(clean)

        if entry.is_url:
            # Route destination through authoritative URL inspection
            url_res = await self.analyze_url(clean, current_user=current_user)
            return ScanQrResponse(
                scan_id=url_res.scan_id,
                verdict=url_res.verdict,
                risk_level=url_res.risk_level,
                risk_score=url_res.risk_score,
                scoring_version=url_res.scoring_version,
                indicators=url_res.indicators,
                recommendations=url_res.recommendations,
                checked_at=url_res.checked_at,
                payload_type="URL",
                mock_notice=url_res.mock_notice,
            )

        # Non-URL QR Payload Analysis
        indicators: List[ScanIndicator] = []
        risk_score = 5
        verdict = ScanVerdict.LOW_RISK
        risk_level = ScanRiskLevel.LOW
        recs = [
            "No immediate malicious payload detected in QR text.",
            "Always verify the purpose of scanned codes before taking action.",
        ]

        if entry.payload_type == "WIFI":
            indicators.append(
                ScanIndicator(
                    code="WIFI_CONFIG_PAYLOAD",
                    label="Wi-Fi network configuration payload",
                    evidence_type=EvidenceType.HEURISTIC,
                    detail="QR code contains Wi-Fi access configuration. Verify network authenticity before connecting.",
                )
            )
            risk_score = 25
            recs = [
                "Verify this network configuration matches official campus Wi-Fi credentials.",
                "Untrusted Wi-Fi configurations can expose network traffic to eavesdropping.",
            ]

        return ScanQrResponse(
            scan_id=uuid4(),
            verdict=verdict,
            risk_level=risk_level,
            risk_score=risk_score,
            scoring_version=self.scorer.calculate_score(
                self.correlator.correlate("QR", clean)
            ).scoring_version,
            indicators=indicators,
            recommendations=recs,
            checked_at=datetime.now(timezone.utc),
            payload_type="RAW_TEXT",
            mock_notice="QR text payload evaluated via static heuristics.",
        )

    async def analyze_message(
        self,
        message_text: str,
        current_user: Optional[AuthenticatedUser] = None,
    ) -> ScanMessageResponse:
        """
        Extracts URLs from message text and evaluates urgency/phishing social engineering cues.
        """
        clean = message_text.strip()
        if not clean:
            raise ValidationException("Message text cannot be empty.")

        extracted_urls = URL_REGEX.findall(clean)
        indicators: List[ScanIndicator] = []
        recs: List[str] = []

        # Check Urgency & Social Engineering Cues
        text_lower = clean.lower()
        has_urgency = any(kw in text_lower for kw in URGENCY_KEYWORDS)
        if has_urgency:
            indicators.append(
                ScanIndicator(
                    code="URGENCY_LANGUAGE",
                    label="Urgency cues detected in message",
                    evidence_type=EvidenceType.HEURISTIC,
                    detail="Message contains urgent phrases typical of credential harvesting and phishing lures.",
                )
            )

        # If URLs extracted, evaluate each URL and take maximum threat outcome
        highest_score = 0
        dominant_verdict = ScanVerdict.LOW_RISK
        dominant_risk_level = ScanRiskLevel.LOW

        if extracted_urls:
            url_analyses = []
            for u in extracted_urls[:5]:  # Bound analysis to first 5 URLs to prevent resource exhaustion
                try:
                    u_res = await self.analyze_url(u, current_user=current_user)
                    url_analyses.append(u_res)
                except Exception:
                    pass

            for u_res in url_analyses:
                if u_res.risk_score > highest_score:
                    highest_score = u_res.risk_score
                    dominant_verdict = u_res.verdict
                    dominant_risk_level = u_res.risk_level
                indicators.extend(u_res.indicators)
                recs.extend(u_res.recommendations)

            if has_urgency:
                highest_score = min(highest_score + 15, 100)
                if highest_score >= 30:
                    dominant_verdict = ScanVerdict.SUSPICIOUS
                    dominant_risk_level = (
                        ScanRiskLevel.MEDIUM if highest_score < 65 else ScanRiskLevel.HIGH
                    )
        else:
            if has_urgency:
                highest_score = 35
                dominant_verdict = ScanVerdict.SUSPICIOUS
                dominant_risk_level = ScanRiskLevel.MEDIUM
                recs.append("Exercise caution: Unsolicited urgent requests may represent impersonation scams.")
            else:
                highest_score = 10
                recs.append("No extracted URLs or immediate phishing lures detected.")

        # Deduplicate recommendations and indicators
        unique_recs = list(dict.fromkeys(recs))[:5]
        seen_codes = set()
        unique_indicators = []
        for ind in indicators:
            if ind.code not in seen_codes:
                unique_indicators.append(ind)
                seen_codes.add(ind.code)

        return ScanMessageResponse(
            scan_id=uuid4(),
            verdict=dominant_verdict,
            risk_level=dominant_risk_level,
            risk_score=highest_score,
            scoring_version="v1.0.0",
            indicators=unique_indicators,
            recommendations=unique_recs or ["Exercise caution with unsolicited messages."],
            checked_at=datetime.now(timezone.utc),
            extracted_urls=extracted_urls,
            analysis_scope="EXTRACTED_URLS_AND_HEURISTICS",
            mock_notice="Message analyzed via URL extraction, threat intelligence, and social engineering heuristics.",
        )


detection_engine = DetectionEngine()
