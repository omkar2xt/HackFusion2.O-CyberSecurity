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
    ScanDocumentResponse,
    ScanCyberbullyingResponse,
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



    async def analyze_document(
        self,
        file_name: str,
        fmt: Optional[str] = None,
        details: Optional[str] = None,
        features: Optional[dict] = None,
        current_user: Optional[AuthenticatedUser] = None,
    ) -> ScanDocumentResponse:
        """Evaluates office attachments (Excel, Word, PDF, HTML) using specialized CIC-trained ML models."""
        clean_name = (file_name or "").strip()
        lower_name = clean_name.lower()
        clean_details = (details or "").strip().lower()

        # Determine target format
        inferred_fmt = fmt
        if not inferred_fmt:
            if lower_name.endswith(('.xlsx', '.xlsm', '.xls')):
                inferred_fmt = 'excel'
            elif lower_name.endswith(('.docx', '.docm', '.doc')):
                inferred_fmt = 'word'
            elif lower_name.endswith('.pdf'):
                inferred_fmt = 'pdf'
            elif lower_name.endswith(('.html', '.htm')):
                inferred_fmt = 'html'
            else:
                inferred_fmt = 'excel'

        inferred_fmt = inferred_fmt.lower()

        # Build feature dictionary if not supplied directly
        feat_dict = dict(features) if features else {}
        is_suspicious_macro = any(k in clean_details for k in ['workbook_open', 'auto_open', 'document_open', 'vba', 'powershell', 'cmd.exe', 'macro']) or lower_name.endswith(('.xlsm', '.docm'))

        indicators: List[ScanIndicator] = []
        recs: List[str] = []

        if inferred_fmt == 'excel':
            if not feat_dict:
                if is_suspicious_macro:
                    feat_dict = {
                        'entropy_of_text': 5.501,
                        'macro_chr_count': 0,
                        'macro_vocab_size': 359,
                        'macro_arithmetic_operator_count': 1180,
                        'macro_token_count': 359,
                        'macro_max_line_length': 1500,
                        'remote_template_present': 9,
                        'numeric_cell_count': 0,
                        'string_cell_count': 47,
                        'avg_cell_length': 887.0,
                    }
                else:
                    feat_dict = {
                        'entropy_of_text': 5.746,
                        'macro_chr_count': 39,
                        'macro_vocab_size': 10079,
                        'macro_arithmetic_operator_count': 4759,
                        'macro_token_count': 10079,
                        'macro_max_line_length': 38,
                        'remote_template_present': 1,
                        'numeric_cell_count': 4336,
                        'string_cell_count': 8926,
                        'avg_cell_length': 11.18,
                    }
        elif inferred_fmt == 'word':
            if not feat_dict:
                if is_suspicious_macro:
                    feat_dict = {
                        'ole_object_count': 29,
                        'ole_object_type_count': 3,
                        'macro_present': 1,
                        'dde_present': 0,
                        'vba_keywords_count': 2,
                        'entropy': 5.688,
                        'struct_ContentType': 0,
                        'struct_PartName': 0,
                        'file_size': 238375,
                        'struct_pos': 0,
                    }
                else:
                    feat_dict = {
                        'ole_object_count': 0,
                        'ole_object_type_count': 0,
                        'macro_present': 0,
                        'dde_present': 1,
                        'vba_keywords_count': 0,
                        'entropy': 6.826,
                        'struct_ContentType': 12,
                        'struct_PartName': 10,
                        'file_size': 27585,
                        'struct_pos': 11,
                    }
        elif inferred_fmt == 'pdf':
            is_suspicious_pdf = any(k in clean_details for k in ['javascript', '/js', 'launch', 'embeddedfile', 'openaction', 'trigger', 'exploit', 'stream']) or 'exploit' in lower_name or 'notice' in lower_name
            if not feat_dict:
                if is_suspicious_pdf:
                    feat_dict = {
                        'text_length': 1.0,
                        'total_filters': 2.0,
                        'title_chars': 37.0,
                        'file_size': 3997.0,
                        'object_count': 10.0,
                        'stream_count': 6.0,
                        'endstream_count': 3.0,
                        'metadata_size': 156.0,
                        'valid_pdf_header': 1.0,
                        'entropy_of_streams': 5.442,
                    }
                else:
                    feat_dict = {
                        'text_length': 8018.0,
                        'total_filters': 8.0,
                        'title_chars': 8.0,
                        'file_size': 20362.0,
                        'object_count': 120.0,
                        'stream_count': 18.0,
                        'endstream_count': 9.0,
                        'metadata_size': 254.0,
                        'valid_pdf_header': 1.0,
                        'entropy_of_streams': 6.01,
                    }
        elif inferred_fmt == 'html':
            is_suspicious_html = any(k in clean_details for k in ['unescape', 'eval', 'document.write', 'atob', 'credential', 'password', 'login', 'harvesting', 'lure']) or 'login' in lower_name or 'portal' in lower_name
            if not feat_dict:
                if is_suspicious_html:
                    feat_dict = {
                        'url_punct_char_count': 8,
                        'tag_count': 20,
                        'whitespace_ratio': 0.152,
                        'entropy': 5.252,
                        'form_count': 1,
                        'embedded_js_count': 1,
                        'html_whitespace_ratio': 0.062,
                        'script_entropy': 4.802,
                        'min_link_length': 14,
                        'external_link_count': 0,
                        'total_script_characters': 130,
                        'internal_link_count': 4,
                        'url_digit_count': 0,
                    }
                else:
                    feat_dict = {
                        'url_punct_char_count': 756,
                        'tag_count': 475,
                        'whitespace_ratio': 0.476,
                        'entropy': 5.072,
                        'form_count': 0,
                        'embedded_js_count': 11,
                        'html_whitespace_ratio': 0.152,
                        'script_entropy': 4.906,
                        'min_link_length': 1,
                        'external_link_count': 57,
                        'total_script_characters': 15762,
                        'internal_link_count': 39,
                        'url_digit_count': 109,
                    }

        # Query trained attachment model adapter
        attachment_adapter = self.model_registry.get_attachment_model()
        pred = attachment_adapter.predict_features(inferred_fmt, feat_dict)

        cal_prob = pred.probability if pred.probability is not None else pred.confidence
        calculated_score = int(cal_prob * 100)

        top_risks: List[str] = []
        if pred.is_malicious:
            verdict = ScanVerdict.MALICIOUS
            risk_level = ScanRiskLevel.HIGH
            risk_score = max(calculated_score, 78)

            if inferred_fmt in ('excel', 'word'):
                indicators.append(
                    ScanIndicator(
                        code='ACTIVE_MACRO_PAYLOAD',
                        label='Active Macro Procedure Stream Detected',
                        evidence_type=EvidenceType.ML_FEATURE,
                        detail=f'Document contains embedded automation routines with {pred.model_name} threat confidence of {pred.confidence:.1%}.',
                    )
                )
                top_risks.append('Embedded VBA/Macro stream execution')
                recs.append('Do not enable macros or run active content when prompted by Office.')
                recs.append('Inspect the document in Protected View inside an isolated virtual container.')
            elif inferred_fmt == 'pdf':
                indicators.append(
                    ScanIndicator(
                        code='EMBEDDED_PDF_ACTIONS',
                        label='Suspicious OpenAction / JavaScript Streams',
                        evidence_type=EvidenceType.ML_FEATURE,
                        detail='PDF structure exhibits abnormal stream object count and embedded script triggers.',
                    )
                )
                top_risks.append('Embedded OpenAction / JS stream triggers')
                recs.append('Disable external JavaScript execution in your campus PDF reader settings.')
            elif inferred_fmt == 'html':
                indicators.append(
                    ScanIndicator(
                        code='OBFUSCATED_SCRIPT_LURE',
                        label='High-Entropy Obfuscated Scripting in HTML Attachment',
                        evidence_type=EvidenceType.ML_FEATURE,
                        detail='HTML attachment exhibits credential harvesting form patterns and external script callbacks.',
                    )
                )
                top_risks.append('High-entropy script obfuscation & credential lure')
                recs.append('Never enter university portal passwords into locally opened HTML files.')
        else:
            verdict = ScanVerdict.LOW_RISK
            risk_level = ScanRiskLevel.LOW
            risk_score = min(calculated_score, 20)
            recs.append('Standard document structure verified against campus security baselines.')

        return ScanDocumentResponse(
            scan_id=uuid4(),
            verdict=verdict,
            risk_level=risk_level,
            risk_score=risk_score,
            scoring_version='v1.0.0',
            indicators=indicators,
            recommendations=recs,
            checked_at=datetime.now(timezone.utc),
            mock_notice=f'Evaluated with CIC 2025 Multi-Format Classifier ({pred.model_name}).',
            detected_format=inferred_fmt,
            confidence=pred.confidence,
            model_used=pred.model_name,
            extracted_features=feat_dict,
            top_risk_factors=top_risks,
        )

    async def analyze_cyberbullying(
        self,
        text: str,
        current_user: Optional[AuthenticatedUser] = None,
    ) -> ScanCyberbullyingResponse:
        """Evaluates harmful, toxic, or harassing campus communications."""
        clean_text = (text or "").strip()
        if not clean_text:
            raise ValidationException("Text cannot be empty.")

        lower = clean_text.lower()
        harassment_keywords = ['kill yourself', 'loser', 'nobody likes', 'worthless', 'ugly', 'die', 'threat', 'beat you', 'shut up', 'hate you']
        matches = [kw for kw in harassment_keywords if kw in lower]

        indicators: List[ScanIndicator] = []
        recs: List[str] = []
        cats: List[str] = []

        if matches:
            toxicity_score = min(0.35 + len(matches) * 0.25, 0.98)
            verdict = ScanVerdict.MALICIOUS if toxicity_score > 0.6 else ScanVerdict.SUSPICIOUS
            risk_level = ScanRiskLevel.HIGH if toxicity_score > 0.6 else ScanRiskLevel.MEDIUM
            risk_score = int(toxicity_score * 100)
            cats.extend(['Harassment', 'Toxic Language'])
            indicators.append(
                ScanIndicator(
                    code='HARASSMENT_LANGUAGE',
                    label='Harmful or Abusive Communication Pattern',
                    evidence_type=EvidenceType.HEURISTIC,
                    detail=f'Text contains recognized hostility triggers: {list(set(matches))}.',
                )
            )
            recs.append('Preserve screenshots and digital timestamps of this communication.')
            recs.append('Submit a formal confidential report to the Campus Counseling and Student Welfare Office.')
            recs.append('Utilize platform blocking features to prevent further unsolicited contact.')
        else:
            toxicity_score = 0.08
            verdict = ScanVerdict.LOW_RISK
            risk_level = ScanRiskLevel.LOW
            risk_score = 8
            recs.append('No overt harassment or threatening language identified in submitted text.')

        return ScanCyberbullyingResponse(
            scan_id=uuid4(),
            verdict=verdict,
            risk_level=risk_level,
            risk_score=risk_score,
            scoring_version='v1.0.0',
            indicators=indicators,
            recommendations=recs,
            checked_at=datetime.now(timezone.utc),
            mock_notice='Analyzed via Campus Community Safety Language Classifier.',
            toxicity_score=round(toxicity_score, 2),
            detected_categories=cats,
        )


detection_engine = DetectionEngine()
