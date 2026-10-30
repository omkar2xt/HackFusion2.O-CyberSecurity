"""
SignalSafe Campus - Explanation Generator
Module: backend/app/services/detection/explanations/generator.py

Generates human-readable explanations, indicator details, and contextual recommendations.
Never claims an item is verified safe solely because no threat was found.
"""

from typing import List, Tuple
from backend.app.schemas.common import ScanIndicator, ScanRiskLevel, ScanVerdict
from backend.app.services.detection.correlation.evidence_model import AggregatedEvidence
from backend.app.services.detection.scoring.risk_scorer import RiskScoreResult


class ExplanationGenerator:
    """Generates transparent explanations and user-facing security recommendations."""

    def generate_recommendations(
        self,
        evidence: AggregatedEvidence,
        scoring: RiskScoreResult,
    ) -> List[str]:
        """Produces contextual security guidance tailored to specific detected threat vectors."""
        recs: List[str] = []

        if scoring.verdict == ScanVerdict.MALICIOUS:
            recs.append("CRITICAL: Do not visit this site or interact with its contents.")
            recs.append("Do not enter student credentials, campus passwords, or payment cards.")
            recs.append("Report this link to campus IT security if received via campus email.")
            return recs

        if scoring.verdict == ScanVerdict.SUSPICIOUS:
            recs.append("Caution: This destination exhibits characteristics of credential harvesting campaigns.")
            recs.append("Do not enter your institutional login credentials or personal information.")
            if any(r.code == "SUSPICIOUS_PAYLOAD_EXTENSION" for r in evidence.fired_rules):
                recs.append("Do not download or execute files from this link.")
            if any(r.code == "RAW_IP_HOST" for r in evidence.fired_rules):
                recs.append("Legitimate campus services always use authenticated domain names, not raw IP addresses.")
            recs.append("Verify this request by accessing the official service directly through verified bookmarks.")
            return recs

        if scoring.verdict == ScanVerdict.UNKNOWN:
            recs.append("Detection telemetry was inconclusive due to provider reachability.")
            recs.append("Exercise extreme caution before sharing personal or campus information.")
            recs.append("Submit the sample to IT security for manual triage if unsolicited.")
            return recs

        # LOW_RISK baseline recommendations
        recs.append("No immediate threat indicators detected; however, safety is never guaranteed.")
        recs.append("Always verify the address bar matches the official campus domain before signing in.")
        recs.append("Never share multi-factor authentication (MFA) codes with third parties.")
        return recs

    def build_summary_explanation(
        self,
        evidence: AggregatedEvidence,
        scoring: RiskScoreResult,
    ) -> str:
        """Constructs an explanatory summary paragraph."""
        parts: List[str] = []

        # Verdict explanation
        parts.append(scoring.rationale)

        # Fired indicators
        if evidence.fired_rules:
            rule_labels = [r.label for r in evidence.fired_rules[:3]]
            parts.append(f"Identified heuristic indicators: {', '.join(rule_labels)}.")

        # Threat intel providers
        if evidence.threat_intel_results:
            active = [ti.provider_name for ti in evidence.threat_intel_results if ti.status.value in ("MATCH", "NO_MATCH")]
            if active:
                parts.append(f"Threat intelligence queried: {', '.join(active)}.")

        # ML model contribution
        if evidence.url_model_prediction:
            m = evidence.url_model_prediction
            if m.is_phishing:
                mock_note = " (mock adapter)" if m.is_mock else ""
                parts.append(f"ML URL classifier (v{m.model_version}){mock_note} flagged structural phishing patterns.")

        return " ".join(parts)


explanation_generator = ExplanationGenerator()
