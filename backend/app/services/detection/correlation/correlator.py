"""
SignalSafe Campus - Evidence Correlator
Module: backend/app/services/detection/correlation/correlator.py

Combines ML predictions, rule indicators, and threat intelligence matches
into a unified evidence container while preventing double-counting and handling conflicts.
"""

from typing import List, Optional
from backend.app.schemas.common import EvidenceType, ScanRiskLevel
from backend.app.services.detection.correlation.evidence_model import (
    AggregatedEvidence,
    EvidenceItem,
    EvidenceSource,
)
from backend.app.services.detection.model_adapters.base import ModelPrediction, PredictionStatus
from backend.app.services.detection.rules.engine import RuleEvaluationResult
from backend.app.services.detection.threat_intel.base import ThreatIntelResult, ThreatIntelStatus


class EvidenceCorrelator:
    """Correlates evidence from heterogeneous detection layers."""

    def correlate(
        self,
        target_type: str,
        target: str,
        rule_result: Optional[RuleEvaluationResult] = None,
        threat_intel_results: Optional[List[ThreatIntelResult]] = None,
        url_prediction: Optional[ModelPrediction] = None,
        qr_prediction: Optional[ModelPrediction] = None,
    ) -> AggregatedEvidence:
        items: List[EvidenceItem] = []
        responding_sources: List[str] = []
        failed_sources: List[str] = []
        has_confirmed = False
        has_heuristic = False
        has_ml = False

        # 1. Correlate Threat Intelligence Evidence (Authoritative Ground Truth)
        if threat_intel_results:
            for ti in threat_intel_results:
                if ti.status == ThreatIntelStatus.MATCH and ti.is_malicious:
                    has_confirmed = True
                    items.append(
                        EvidenceItem(
                            source=EvidenceSource.THREAT_INTELLIGENCE,
                            evidence_type=EvidenceType.THREAT_INTELLIGENCE,
                            severity=ScanRiskLevel.CRITICAL if ti.confidence >= 0.90 else ScanRiskLevel.HIGH,
                            confidence=ti.confidence,
                            code=f"THREAT_INTEL_{ti.provider_name.upper().replace(' ', '_')}",
                            label=f"Flagged by {ti.provider_name}",
                            detail=ti.details,
                            is_confirmed_threat=True,
                        )
                    )
                    responding_sources.append(ti.provider_name)
                elif ti.status in (
                    ThreatIntelStatus.ERROR,
                    ThreatIntelStatus.TIMEOUT,
                    ThreatIntelStatus.RATE_LIMITED,
                    ThreatIntelStatus.UNAVAILABLE,
                ):
                    failed_sources.append(ti.provider_name)
                else:
                    responding_sources.append(ti.provider_name)

        # 2. Correlate Rule Engine Evidence
        if rule_result and rule_result.fired_rules:
            has_heuristic = True
            for rule in rule_result.fired_rules:
                items.append(
                    EvidenceItem(
                        source=EvidenceSource.RULE_ENGINE,
                        evidence_type=EvidenceType.HEURISTIC,
                        severity=rule.severity,
                        confidence=0.85,
                        code=rule.code,
                        label=rule.label,
                        detail=rule.detail_template,
                    )
                )
            responding_sources.append("RuleEngine")

        # 3. Correlate URL ML Model Prediction
        if url_prediction:
            if url_prediction.status == PredictionStatus.SUCCESS:
                responding_sources.append(url_prediction.model_name)
                if url_prediction.is_phishing:
                    has_ml = True
                    items.append(
                        EvidenceItem(
                            source=EvidenceSource.ML_URL_MODEL,
                            evidence_type=EvidenceType.HEURISTIC,
                            severity=ScanRiskLevel.HIGH if url_prediction.confidence >= 0.80 else ScanRiskLevel.MEDIUM,
                            confidence=url_prediction.confidence,
                            code="ML_URL_PHISHING_PATTERN",
                            label="Machine Learning Phishing Classifier Flag",
                            detail=(
                                f"Model '{url_prediction.model_name}' (v{url_prediction.model_version}) "
                                f"flagged structural phishing patterns (probability: {url_prediction.probability})."
                                + (" [MOCK ADAPTER]" if url_prediction.is_mock else "")
                            ),
                            is_mock=url_prediction.is_mock,
                        )
                    )
            else:
                failed_sources.append(f"URLModel:{url_prediction.status.value}")

        # 4. Correlate QR Image ML Model Prediction (Anti-Double-Counting)
        if qr_prediction:
            if qr_prediction.status == PredictionStatus.SUCCESS:
                responding_sources.append(qr_prediction.model_name)
                if qr_prediction.is_phishing:
                    # Check if URL model already flagged. If both flagged, correlate under shared threat
                    detail_note = (
                        f"Visual QR model '{qr_prediction.model_name}' detected suspicious QR structure."
                        + (" [MOCK ADAPTER]" if qr_prediction.is_mock else "")
                    )
                    if url_prediction and url_prediction.is_phishing:
                        detail_note += " (Correlated with decoded URL structural analysis)."

                    items.append(
                        EvidenceItem(
                            source=EvidenceSource.ML_QR_MODEL,
                            evidence_type=EvidenceType.HEURISTIC,
                            severity=ScanRiskLevel.HIGH if qr_prediction.confidence >= 0.80 else ScanRiskLevel.MEDIUM,
                            confidence=qr_prediction.confidence,
                            code="ML_QR_VISUAL_ANOMALY",
                            label="QR Visual Anomaly Detected",
                            detail=detail_note,
                            is_mock=qr_prediction.is_mock,
                        )
                    )
            else:
                failed_sources.append(f"QRModel:{qr_prediction.status.value}")

        return AggregatedEvidence(
            target_type=target_type,
            target=target,
            items=items,
            url_model_prediction=url_prediction,
            qr_model_prediction=qr_prediction,
            threat_intel_results=threat_intel_results or [],
            fired_rules=rule_result.fired_rules if rule_result else [],
            has_confirmed_threat=has_confirmed,
            has_heuristic_indicators=has_heuristic,
            has_ml_threat=has_ml,
            responding_sources=responding_sources,
            failed_sources=failed_sources,
        )


evidence_correlator = EvidenceCorrelator()
