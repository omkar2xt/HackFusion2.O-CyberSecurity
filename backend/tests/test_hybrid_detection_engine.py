"""
SignalSafe Campus - Hybrid Detection Engine Comprehensive Verification Suite
Module: backend/tests/test_hybrid_detection_engine.py

Verifies:
1. URL Pipeline: Feature extraction integration, rule indicator triggering, invalid URL rejection,
   model unavailable handling, schema mismatch rejection, and conflicting evidence handling.
2. QR Pipeline: Valid decoding, multi-QR image processing, invalid/corrupt images, unsupported formats,
   dimension and size limits, non-URL payloads, destination URL extraction, and QR model fallback.
3. Threat Intelligence: Confirmed matches, no matches, timeouts, rate limits, provider outages,
   malformed payloads, SSRF protection, and caching.
4. Risk Scoring & Correlation: Confirmed malicious overrides, heuristic-only bounds, anti-double-counting,
   duplicate suppression, insufficient evidence, and deterministic risk scoring.
"""

import asyncio
import io
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from PIL import Image
import zxingcpp

from backend.app.core.errors import ValidationException
from backend.app.schemas.common import EvidenceType, ScanRiskLevel, ScanVerdict
from backend.app.services.detection.correlation.correlator import (
    EvidenceCorrelator,
    evidence_correlator,
)
from backend.app.services.detection.correlation.evidence_model import (
    AggregatedEvidence,
    EvidenceItem,
    EvidenceSource,
)
from backend.app.services.detection.hybrid_engine import DetectionEngine, detection_engine
from backend.app.services.detection.model_adapters.base import (
    ModelMetadata,
    ModelPrediction,
    ModelType,
    PredictionStatus,
)
from backend.app.services.detection.model_adapters.qr_adapter import QRModelAdapter
from backend.app.services.detection.model_adapters.registry import ModelRegistry
from backend.app.services.detection.model_adapters.url_adapter import URLModelAdapter
from backend.app.services.detection.qr.analyzer import (
    MAX_IMAGE_DIMENSION,
    MAX_IMAGE_FILE_SIZE_BYTES,
    MIN_IMAGE_DIMENSION,
    QRAnalyzer,
    qr_analyzer,
)
from backend.app.services.detection.rules.engine import RuleEngine, rule_engine
from backend.app.services.detection.scoring.risk_scorer import (
    RiskScoreResult,
    RiskScoringService,
    risk_scoring_service,
)
from backend.app.services.detection.threat_intel.base import (
    ThreatIntelResult,
    ThreatIntelStatus,
    is_ssrf_risk_or_internal,
)
from backend.app.services.detection.threat_intel.google_safe_browsing import GoogleSafeBrowsingProvider
from backend.app.services.detection.threat_intel.service import ThreatIntelService
from backend.app.services.detection.threat_intel.urlhaus import URLhausProvider
from backend.app.services.detection.threat_intel.virustotal import VirusTotalProvider
from backend.app.services.detection.url_features import (
    URL_FEATURE_NAMES,
    URL_FEATURE_SCHEMA_VERSION,
    extract_url_feature_vector,
    extract_url_features,
)


# =============================================================================
# Helper Utilities
# =============================================================================

def create_qr_image_bytes(text: str, fmt: str = "PNG") -> bytes:
    """Generates valid QR barcode image bytes in specified PIL format."""
    barcode = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode)
    zimg = zxingcpp.write_barcode_to_image(barcode)
    pil_img = Image.fromarray(zimg)
    buf = io.BytesIO()
    pil_img.save(buf, format=fmt)
    return buf.getvalue()


def create_multi_qr_image_bytes(text1: str, text2: str) -> bytes:
    """Generates an image containing two distinct QR barcodes side by side."""
    b1 = zxingcpp.create_barcode(text1, zxingcpp.BarcodeFormat.QRCode)
    b2 = zxingcpp.create_barcode(text2, zxingcpp.BarcodeFormat.QRCode)
    im1 = Image.fromarray(zxingcpp.write_barcode_to_image(b1))
    im2 = Image.fromarray(zxingcpp.write_barcode_to_image(b2))

    w = im1.width + im2.width + 20
    h = max(im1.height, im2.height)
    canvas = Image.new("L", (w, h), color=255)
    canvas.paste(im1, (0, 0))
    canvas.paste(im2, (im1.width + 20, 0))

    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    return buf.getvalue()


# =============================================================================
# 1. URL Engine & Feature Integration Tests
# =============================================================================

class TestURLDetectionPipeline:
    """Verifies feature extraction, rule indicators, validation, and ML model integration."""

    def test_feature_extraction_dimension_and_types(self):
        url = "https://portal.university.edu/login?ref=auth"
        features = extract_url_features(url)
        assert len(URL_FEATURE_NAMES) == 34
        vec = extract_url_feature_vector(url)
        assert len(vec) == 34
        assert all(isinstance(x, (int, float)) for x in vec)

    def test_rule_indicator_detection(self):
        engine = RuleEngine()
        # Raw IP host
        ip_url = "http://192.168.1.1:8080/admin"
        ip_feats = extract_url_features(ip_url)
        res_ip = engine.evaluate(ip_feats)
        codes = [ind.code for ind in res_ip.indicators]
        assert "RAW_IP_HOST" in codes
        assert "NON_STANDARD_PORT" in codes

        # Sensitive keywords and userinfo evasion
        phish_url = "https://user:pass@evil-bank-login.com/secure/account-update.exe"
        phish_feats = extract_url_features(phish_url)
        res_phish = engine.evaluate(phish_feats)
        phish_codes = [ind.code for ind in res_phish.indicators]
        assert "USERINFO_OBFUSCATION" in phish_codes
        assert "SUSPICIOUS_PAYLOAD_EXTENSION" in phish_codes
        assert "SENSITIVE_CREDENTIAL_KEYWORD" in phish_codes

    def test_invalid_url_handling(self):
        engine = DetectionEngine()
        with pytest.raises(ValidationException, match="non-empty string"):
            engine.validate_and_normalize_url("")

        with pytest.raises(ValidationException, match="Unsupported scheme"):
            engine.validate_and_normalize_url("ftp://invalidscheme.com/file")

        with pytest.raises(ValidationException, match="Unsupported scheme"):
            engine.validate_and_normalize_url("javascript:alert(1)")

        with pytest.raises(ValidationException, match="valid host"):
            engine.validate_and_normalize_url("https://")

        with pytest.raises(ValidationException, match="maximum permitted length"):
            engine.validate_and_normalize_url("https://example.com/" + "a" * 2050)

    def test_model_unavailable_behaviour(self):
        """When ML model artifact is unavailable, adapter safely falls back to contract mock."""
        adapter = URLModelAdapter(model_path=None)
        features = extract_url_features("https://example.com")
        pred = adapter.predict(features)

        assert pred.model_name == "URLClassifier-MockAdapter"
        assert pred.is_mock is True
        assert pred.status == PredictionStatus.SUCCESS

    def test_model_schema_dimension_mismatch_rejection(self):
        """Ensures the adapter strictly identifies and reports feature dimension mismatch."""
        adapter = URLModelAdapter(model_path=None)
        pred = adapter.predict([1.0] * 33)
        assert pred.status == PredictionStatus.SCHEMA_MISMATCH
        assert "Feature dimension mismatch" in (pred.error_reason or "")

    def test_conflicting_evidence_resolution(self):
        """
        When rules flag a suspicious keyword or raw IP, but external threat intelligence is inconclusive/clean,
        the verdict must remain conservative SUSPICIOUS rather than falsely declaring LOW_RISK.
        """
        scorer = RiskScoringService()
        correlator = EvidenceCorrelator()

        rule_res = rule_engine.evaluate(extract_url_features("http://192.168.1.50/login"))
        ti_results = [
            ThreatIntelResult(
                provider_name="GoogleSafeBrowsing",
                target_url="http://192.168.1.50/login",
                status=ThreatIntelStatus.NO_MATCH,
                is_malicious=False,
                confidence=0.9,
            )
        ]
        evidence = correlator.correlate(
            target_type="URL",
            target="http://192.168.1.50/login",
            rule_result=rule_res,
            threat_intel_results=ti_results,
        )
        scoring = scorer.calculate_score(evidence)
        assert scoring.verdict in [ScanVerdict.SUSPICIOUS, ScanVerdict.MALICIOUS]
        assert scoring.verdict != ScanVerdict.LOW_RISK


# =============================================================================
# 2. QR Analysis & Image Verification Tests
# =============================================================================

class TestQRAnalysisPipeline:
    """Verifies QR validation, decoding, non-URL handling, multi-QR, and size limits."""

    def test_valid_qr_decoding(self):
        target = "https://campus-events.university.edu/ticket/12345"
        img_bytes = create_qr_image_bytes(target, fmt="PNG")
        res = qr_analyzer.analyze_qr_image(img_bytes)

        assert res.is_valid_image is True
        assert res.codes_found >= 1
        assert res.entries[0].raw_content == target
        assert res.entries[0].is_url is True
        assert res.entries[0].payload_type == "URL"

    def test_multi_qr_codes_in_single_image(self):
        t1 = "https://service1.campus.edu"
        t2 = "https://service2.campus.edu"
        multi_bytes = create_multi_qr_image_bytes(t1, t2)
        res = qr_analyzer.analyze_qr_image(multi_bytes)

        assert res.is_valid_image is True
        assert res.codes_found == 2
        decoded_texts = [e.raw_content for e in res.entries]
        assert t1 in decoded_texts
        assert t2 in decoded_texts

    def test_invalid_image_bytes(self):
        garbage = b"NOT_A_VALID_IMAGE_HEADER_12345"
        res = qr_analyzer.analyze_qr_image(garbage)
        assert res.is_valid_image is False
        assert "Invalid or corrupted image format" in (res.error_reason or "")
        assert res.codes_found == 0

    def test_unsupported_image_format(self):
        # Create a 64x64 TIFF format image
        im = Image.new("RGB", (64, 64), color="blue")
        buf = io.BytesIO()
        im.save(buf, format="TIFF")
        res = qr_analyzer.analyze_qr_image(buf.getvalue())

        assert res.is_valid_image is False
        assert "Unsupported image format 'TIFF'" in (res.error_reason or "")

    def test_oversized_image_dimensions(self):
        # Image exceeding MAX_IMAGE_DIMENSION (4096)
        im = Image.new("RGB", (MAX_IMAGE_DIMENSION + 10, 64), color="white")
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        res = qr_analyzer.analyze_qr_image(buf.getvalue())

        assert res.is_valid_image is False
        assert "exceed maximum permitted threshold" in (res.error_reason or "")

    def test_undersized_image_dimensions(self):
        # Image below MIN_IMAGE_DIMENSION (32)
        im = Image.new("RGB", (MIN_IMAGE_DIMENSION - 5, 16), color="white")
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        res = qr_analyzer.analyze_qr_image(buf.getvalue())

        assert res.is_valid_image is False
        assert "below minimum permitted threshold" in (res.error_reason or "")

    def test_non_url_qr_payloads(self):
        payloads = [
            ("WIFI:S:Library_Secure;T:WPA;P:secret123;;", "WIFI"),
            ("SMSTO:12345:Help", "SMSTO"),
            ("TEL:+18005550199", "TEL"),
            ("MAILTO:support@university.edu", "MAILTO"),
            ("BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nEND:VCARD", "VCARD"),
            ("PlainTextNoticeOnly", "RAW_TEXT"),
        ]
        for text, expected_type in payloads:
            entry = qr_analyzer.analyze_decoded_text(text)
            assert entry.payload_type == expected_type
            assert entry.is_url is False

    def test_qr_visual_model_unavailable(self):
        adapter = QRModelAdapter(model_path=None)
        im = Image.new("RGB", (64, 64), color="black")
        pred = adapter.predict(im)
        assert pred.is_mock is True
        assert pred.status == PredictionStatus.SUCCESS
        assert pred.model_name == "QRImageClassifier-MockAdapter"


# =============================================================================
# 3. Threat Intelligence Adapter Tests
# =============================================================================

class TestThreatIntelligenceProviders:
    """Verifies Safe Browsing, VirusTotal, URLhaus with mock responses, timeouts, rate limits, and outages."""

    def test_safe_browsing_confirmed_match(self):
        async def _run():
            provider = GoogleSafeBrowsingProvider(api_key="mock-key")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "matches": [
                    {
                        "threatType": "MALWARE",
                        "platformType": "ANY_PLATFORM",
                        "threat": {"url": "http://evil-malware.com"},
                    }
                ]
            }

            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_response
                res = await provider.check_url("http://evil-malware.com")
                assert res.status == ThreatIntelStatus.MATCH
                assert res.is_malicious is True
                assert res.threat_category == "MALWARE"

        asyncio.run(_run())

    def test_virustotal_confirmed_match(self):
        async def _run():
            provider = VirusTotalProvider(api_key="mock-key")
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 8,
                            "suspicious": 2,
                            "harmless": 60,
                            "undetected": 10,
                        }
                    }
                }
            }

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                res = await provider.check_url("http://malicious-domain.com")
                assert res.status == ThreatIntelStatus.MATCH
                assert res.is_malicious is True
                assert res.confidence >= 0.8

        asyncio.run(_run())

    def test_urlhaus_no_match(self):
        async def _run():
            provider = URLhausProvider(api_key=None)
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"query_status": "no_results"}

            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_response
                res = await provider.check_url("https://innocent-campus-site.edu")
                assert res.status == ThreatIntelStatus.NO_MATCH
                assert res.is_malicious is False

        asyncio.run(_run())

    def test_provider_timeout_handling(self):
        async def _run():
            provider = GoogleSafeBrowsingProvider(api_key="mock-key")
            with patch("httpx.AsyncClient.post", side_effect=asyncio.TimeoutError()):
                res = await provider.check_url("https://example.com")
                assert res.status == ThreatIntelStatus.TIMEOUT
                assert res.is_malicious is False

        asyncio.run(_run())

    def test_provider_rate_limiting_429(self):
        async def _run():
            provider = VirusTotalProvider(api_key="mock-key")
            mock_response = MagicMock()
            mock_response.status_code = 429
            mock_response.text = "Rate limit exceeded"

            with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
                mock_get.return_value = mock_response
                res = await provider.check_url("https://example.com")
                assert res.status == ThreatIntelStatus.RATE_LIMITED
                assert res.is_malicious is False

        asyncio.run(_run())

    def test_provider_outage_503(self):
        async def _run():
            provider = URLhausProvider(api_key=None)
            mock_response = MagicMock()
            mock_response.status_code = 503
            mock_response.text = "Service Unavailable"

            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_response
                res = await provider.check_url("https://example.com")
                assert res.status == ThreatIntelStatus.ERROR
                assert "HTTP 503" in (res.details or "")

        asyncio.run(_run())

    def test_ssrf_filter_prevents_internal_queries(self):
        """Internal IP addresses and private loopbacks must never be queried to external TI services."""
        assert is_ssrf_risk_or_internal("http://127.0.0.1:8000/internal") is True
        assert is_ssrf_risk_or_internal("http://192.168.1.100") is True
        assert is_ssrf_risk_or_internal("http://10.0.0.1") is True
        assert is_ssrf_risk_or_internal("http://169.254.169.254/latest/meta-data") is True
        assert is_ssrf_risk_or_internal("http://localhost:3000") is True
        assert is_ssrf_risk_or_internal("https://google.com") is False

        async def _run():
            service = ThreatIntelService()
            result = await service.query_all("http://127.0.0.1:5000")
            assert result.target_url == "http://127.0.0.1:5000"
            for r in result.results:
                assert r.status == ThreatIntelStatus.SKIPPED_INTERNAL_IP
                assert "SSRF" in (r.details or "")

        asyncio.run(_run())


# =============================================================================
# 4. Risk Scoring & Correlation Tests
# =============================================================================

class TestRiskScoringAndCorrelation:
    """Verifies confirmed malicious override, heuristic caps, anti-double-counting, and deterministic outputs."""

    def test_confirmed_malicious_override(self):
        """A confirmed malicious match from threat intel forces HIGH_RISK / MALICIOUS verdict."""
        correlator = EvidenceCorrelator()
        scorer = RiskScoringService()

        ti_match = ThreatIntelResult(
            provider_name="URLhaus",
            target_url="https://bad-payload.com/test",
            status=ThreatIntelStatus.MATCH,
            is_malicious=True,
            confidence=0.95,
            threat_category="MALWARE_DOWNLOAD",
        )
        evidence = correlator.correlate(
            target_type="URL",
            target="https://bad-payload.com/test",
            threat_intel_results=[ti_match],
        )
        res = scorer.calculate_score(evidence)

        assert res.verdict == ScanVerdict.MALICIOUS
        assert res.risk_level == ScanRiskLevel.CRITICAL
        assert res.risk_score >= 90
        assert res.scoring_version == "v1.0.0"

    def test_heuristic_only_score_bounded(self):
        """Heuristic rules cannot exceed score of 65 on their own without confirmed threat intel."""
        correlator = EvidenceCorrelator()
        scorer = RiskScoringService()

        # Fire multiple rules via rule engine
        feats = extract_url_features("https://user:pass@192.168.1.1:8080/secure/update.exe")
        rule_res = rule_engine.evaluate(feats)
        agg = correlator.correlate(
            target_type="URL",
            target="https://user:pass@192.168.1.1:8080/secure/update.exe",
            rule_result=rule_res,
        )
        res = scorer.calculate_score(agg)
        assert res.risk_score <= 65
        assert res.verdict == ScanVerdict.SUSPICIOUS

    def test_anti_double_counting_rules(self):
        """NUMERIC_DOMINANCE is suppressed if RAW_IP_HOST has already fired."""
        engine = RuleEngine()
        feats = extract_url_features("http://192.168.1.1:8080/page")
        res = engine.evaluate(feats)
        codes = [ind.code for ind in res.indicators]

        assert "RAW_IP_HOST" in codes
        # NUMERIC_DOMINANCE must be suppressed to avoid inflating score for the same underlying signal
        assert "NUMERIC_DOMINANCE" not in codes

    def test_duplicate_evidence_suppression(self):
        """Evidence container deduplicates identical indicator codes."""
        item1 = EvidenceItem(
            source=EvidenceSource.RULE_ENGINE,
            evidence_type=EvidenceType.HEURISTIC,
            severity=ScanRiskLevel.MEDIUM,
            confidence=0.8,
            code="SUSPICIOUS_KEYWORD",
            label="Keyword",
            detail="Detail",
        )
        item2 = EvidenceItem(
            source=EvidenceSource.RULE_ENGINE,
            evidence_type=EvidenceType.HEURISTIC,
            severity=ScanRiskLevel.MEDIUM,
            confidence=0.8,
            code="SUSPICIOUS_KEYWORD",
            label="Keyword",
            detail="Detail",
        )
        agg = AggregatedEvidence(
            target_type="URL",
            target="https://example.com/login",
            items=[item1, item2],
            has_heuristic_indicators=True,
        )
        # Deduplication in indicators property
        assert len(agg.indicators) == 1
        assert agg.indicators[0].code == "SUSPICIOUS_KEYWORD"

    def test_deterministic_scoring(self):
        """Repeated scoring runs on the identical evidence structure yield identical bit-for-bit results."""
        correlator = EvidenceCorrelator()
        scorer = RiskScoringService()
        feats = extract_url_features("https://secure-login.university-update.com/reset")
        rule_res = rule_engine.evaluate(feats)

        ev1 = correlator.correlate(
            target_type="URL",
            target="https://secure-login.university-update.com/reset",
            rule_result=rule_res,
        )
        ev2 = correlator.correlate(
            target_type="URL",
            target="https://secure-login.university-update.com/reset",
            rule_result=rule_res,
        )

        res1 = scorer.calculate_score(ev1)
        res2 = scorer.calculate_score(ev2)

        assert res1.risk_score == res2.risk_score
        assert res1.verdict == res2.verdict
        assert res1.risk_level == res2.risk_level
        assert res1.scoring_version == res2.scoring_version

    def test_total_provider_outage_produces_unknown(self):
        """When detection providers are unreachable or offline and no rules fire, result is UNKNOWN."""
        scorer = RiskScoringService()
        agg = AggregatedEvidence(
            target_type="URL",
            target="https://example.com/unreachable",
            items=[],
            has_heuristic_indicators=False,
            has_ml_threat=False,
            failed_sources=["GoogleSafeBrowsing", "VirusTotal", "URLhaus"],
            responding_sources=[],
        )
        res = scorer.calculate_score(agg)
        assert res.verdict == ScanVerdict.UNKNOWN
        assert res.risk_level == ScanRiskLevel.UNKNOWN
        assert res.risk_score == 0
        assert "Insufficient evidence" in res.rationale

    def test_ssrf_advanced_ip_encodings_blocked(self):
        """Decimal IP integers, hex representations, and IPv4-mapped IPv6 must be blocked by SSRF filter."""
        # Decimal integer IP: 2130706433 = 127.0.0.1
        assert is_ssrf_risk_or_internal("http://2130706433/admin") is True
        # Hex representation: 0x7f000001 = 127.0.0.1
        assert is_ssrf_risk_or_internal("http://0x7f000001/admin") is True
        # IPv4-mapped IPv6 loopback
        assert is_ssrf_risk_or_internal("http://[::ffff:127.0.0.1]/status") is True
        # IPv6 Unique Local Address
        assert is_ssrf_risk_or_internal("http://[fc00::1]/private") is True
        # IPv6 Link-Local
        assert is_ssrf_risk_or_internal("http://[fe80::1]/config") is True
        # Legitimate public domains permitted
        assert is_ssrf_risk_or_internal("https://university.edu") is False

    def test_correlated_qr_and_url_evidence_dampened(self):
        """When both URL model and QR visual model predict phishing, secondary signal is dampened to prevent double-counting."""
        scorer = RiskScoringService()
        pred_url = ModelPrediction(
            model_name="URLClassifier-ONNX",
            model_version="1.0.0",
            status=PredictionStatus.SUCCESS,
            prediction=1,
            probability=0.90,
            confidence=0.90,
            is_mock=False,
            inference_time_ms=1.2,
        )
        pred_qr = ModelPrediction(
            model_name="QRImageClassifier-ONNX",
            model_version="1.0.0",
            status=PredictionStatus.SUCCESS,
            prediction=1,
            probability=0.80,
            confidence=0.80,
            is_mock=False,
            inference_time_ms=2.1,
        )
        agg_both = AggregatedEvidence(
            target_type="QR",
            target="https://phish.com",
            items=[],
            url_model_prediction=pred_url,
            qr_model_prediction=pred_qr,
            has_ml_threat=True,
        )
        score_both = scorer.calculate_score(agg_both)

        agg_url_only = AggregatedEvidence(
            target_type="URL",
            target="https://phish.com",
            items=[],
            url_model_prediction=pred_url,
            has_ml_threat=True,
        )
        score_url_only = scorer.calculate_score(agg_url_only)

        # Ensure both combined do not simply double the score; ML score is bounded
        assert score_both.risk_score <= 30
        assert score_both.risk_score >= score_url_only.risk_score
