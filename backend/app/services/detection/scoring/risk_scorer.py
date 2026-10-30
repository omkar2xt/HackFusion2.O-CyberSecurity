"""
SignalSafe Campus - Risk Scoring Service
Module: backend/app/services/detection/scoring/risk_scorer.py

Implements transparent, deterministic, versioned risk scoring combining
authoritative threat intelligence matches, ML predictions, and heuristic rule indicators.
"""

from dataclasses import dataclass
from typing import Tuple
from backend.app.schemas.common import ScanRiskLevel, ScanVerdict
from backend.app.services.detection.correlation.evidence_model import AggregatedEvidence

SCORING_POLICY_VERSION = "v1.0.0"


@dataclass(frozen=True)
class RiskScoreResult:
    """Calculated risk score, verdict, and risk level."""
    verdict: ScanVerdict
    risk_level: ScanRiskLevel
    risk_score: int  # 0 to 100
    scoring_version: str
    is_confirmed_threat: bool
    rationale: str


class RiskScoringService:
    """Calculates bounded, explainable threat scores from aggregated evidence."""

    def calculate_score(self, evidence: AggregatedEvidence) -> RiskScoreResult:
        """
        Calculates deterministic risk score (0-100), verdict, and risk level.
        Enforces clear separation between confirmed threat intelligence and probabilistic heuristics.
        """
        # Case 1: Confirmed Threat Intelligence Match (Ground Truth)
        if evidence.has_confirmed_threat:
            top_match = None
            for item in evidence.items:
                if item.is_confirmed_threat:
                    top_match = item
                    break

            conf = top_match.confidence if top_match else 0.95
            score = int(85 + (15 * conf))
            score = max(85, min(100, score))

            risk_level = ScanRiskLevel.CRITICAL if score >= 90 else ScanRiskLevel.HIGH
            return RiskScoreResult(
                verdict=ScanVerdict.MALICIOUS,
                risk_level=risk_level,
                risk_score=score,
                scoring_version=SCORING_POLICY_VERSION,
                is_confirmed_threat=True,
                rationale="Confirmed malicious threat match identified by external intelligence registries.",
            )

        # Case 2: Insufficient Evidence / Outage State
        # If external threat intel completely failed or was unavailable, ML was unavailable/mock, and 0 rules fired:
        if (
            not evidence.has_heuristic_indicators
            and not evidence.has_ml_threat
            and not evidence.items
            and len(evidence.failed_sources) > 0
            and len(evidence.responding_sources) == 0
        ):
            return RiskScoreResult(
                verdict=ScanVerdict.UNKNOWN,
                risk_level=ScanRiskLevel.UNKNOWN,
                risk_score=0,
                scoring_version=SCORING_POLICY_VERSION,
                is_confirmed_threat=False,
                rationale="Insufficient evidence: Detection providers were unreachable or offline.",
            )

        # Case 3: Heuristic Rules + Machine Learning Signals
        rule_score = sum(r.score_contribution for r in evidence.fired_rules)
        rule_score = min(rule_score, 60)  # Cap rule contributions

        # ML Contribution (with Anti-Double-Counting)
        ml_score = 0
        if evidence.url_model_prediction and evidence.url_model_prediction.is_phishing:
            prob = evidence.url_model_prediction.probability or 0.70
            ml_score += int(25 * prob)

        if evidence.qr_model_prediction and evidence.qr_model_prediction.is_phishing:
            prob = evidence.qr_model_prediction.probability or 0.60
            # If URL model already contributed, add secondary dampening to avoid double counting
            if ml_score > 0:
                ml_score += int(10 * prob)
            else:
                ml_score += int(20 * prob)

        ml_score = min(ml_score, 30)  # Cap ML contributions

        combined_score = rule_score + ml_score
        combined_score = min(combined_score, 80)  # Heuristics without confirmed intel capped at 80

        # Verdict and Risk Level Mapping
        if combined_score >= 65:
            verdict = ScanVerdict.SUSPICIOUS
            risk_level = ScanRiskLevel.HIGH
            rationale = "High-confidence structural and heuristic phishing patterns detected."
        elif combined_score >= 30:
            verdict = ScanVerdict.SUSPICIOUS
            risk_level = ScanRiskLevel.MEDIUM
            rationale = "Multiple suspicious indicators detected requiring user caution."
        elif combined_score > 0:
            verdict = ScanVerdict.LOW_RISK
            risk_level = ScanRiskLevel.LOW
            rationale = "Minor low-risk anomalies detected; no verified threat identified."
        else:
            verdict = ScanVerdict.LOW_RISK
            risk_level = ScanRiskLevel.LOW
            combined_score = 5  # Baseline minimal score for clean scans
            rationale = "No immediate threat indicators detected. Safety is never guaranteed."

        return RiskScoreResult(
            verdict=verdict,
            risk_level=risk_level,
            risk_score=combined_score,
            scoring_version=SCORING_POLICY_VERSION,
            is_confirmed_threat=False,
            rationale=rationale,
        )


risk_scoring_service = RiskScoringService()
