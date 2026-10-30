"""
SignalSafe Campus - Detection Rule Engine
Module: backend/app/services/detection/rules/engine.py

Evaluates deterministic, explainable heuristic rules against the authoritative
34-feature URL schema. Anti-bias controls ensure HTTPS absence is never used as proof.
"""

from dataclasses import dataclass
from typing import Dict, List, Set
from backend.app.schemas.common import ScanIndicator
from backend.app.services.detection.rules.indicators import RULE_CATALOGUE, RuleDefinition
from backend.app.services.detection.url_features import URLFeatures, extract_url_features


@dataclass(frozen=True)
class RuleEvaluationResult:
    """Result of rule engine evaluation on a URL."""
    indicators: List[ScanIndicator]
    fired_rules: List[RuleDefinition]
    raw_score: int
    capped_score: int  # Capped at MAX_RULE_SCORE to prevent heuristic inflation


MAX_RULE_SCORE = 65


class RuleEngine:
    """Deterministic, explainable rule engine for URL threat evaluation."""

    def evaluate(self, features_or_url: URLFeatures | str) -> RuleEvaluationResult:
        """
        Evaluates heuristic indicators against URL features.
        Suppresses redundant/overlapping indicators to prevent double counting.
        """
        if isinstance(features_or_url, str):
            features = extract_url_features(features_or_url)
        else:
            features = features_or_url

        fired_rules: List[RuleDefinition] = []
        indicators: List[ScanIndicator] = []
        raw_score = 0
        fired_codes: Set[str] = set()

        def add_rule(code: str, custom_detail: str | None = None):
            if code not in fired_codes and code in RULE_CATALOGUE:
                rule = RULE_CATALOGUE[code]
                fired_rules.append(rule)
                indicators.append(rule.build_indicator(custom_detail))
                fired_codes.add(code)

        # 1. Critical Obfuscation & Delivery Vector Rules
        if features.is_ip_address > 0:
            add_rule("RAW_IP_HOST")

        if features.is_punycode > 0:
            add_rule("PUNYCODE_HOMOGRAPH")

        if features.at_symbol_count > 0:
            add_rule(
                "USERINFO_OBFUSCATION",
                f"URL contains {features.at_symbol_count} '@' symbol(s) obscuring true host.",
            )

        if features.suspicious_file_extension > 0:
            add_rule("SUSPICIOUS_PAYLOAD_EXTENSION")

        # 2. Structural & Redirection Evasion Rules
        if features.double_slash_in_path > 0:
            add_rule("DOUBLE_SLASH_EVASION")

        if features.has_non_standard_port > 0:
            add_rule("NON_STANDARD_PORT")

        if features.subdomain_count >= 3 or features.subdomain_length > 25:
            add_rule(
                "EXCESSIVE_SUBDOMAINS",
                f"URL has {features.subdomain_count} subdomains ({features.subdomain_length} chars).",
            )

        # 3. Phishing Keywords
        if features.suspicious_keyword_in_domain > 0 or features.suspicious_keyword_count >= 2:
            add_rule(
                "SENSITIVE_CREDENTIAL_KEYWORD",
                f"Detected {features.suspicious_keyword_count} security/credential keyword(s).",
            )

        # 4. Character & Encoding Anomalies (with Anti-Double-Counting)
        # If RAW_IP_HOST already fired, do not fire NUMERIC_DOMINANCE (shared underlying cause)
        if "RAW_IP_HOST" not in fired_codes:
            if features.percentage_numeric_chars_domain >= 30.0 or features.percentage_numeric_chars >= 40.0:
                add_rule("NUMERIC_DOMINANCE")

        if features.domain_entropy >= 4.25:
            add_rule("HIGH_CHARACTER_ENTROPY")

        if features.percent_count >= 5:
            add_rule("HIGH_PERCENT_ENCODING")

        if features.url_length >= 100:
            add_rule("EXCESSIVE_URL_LENGTH")

        # Compute combined score
        raw_score = sum(r.score_contribution for r in fired_rules)
        capped_score = min(raw_score, MAX_RULE_SCORE)

        return RuleEvaluationResult(
            indicators=indicators,
            fired_rules=fired_rules,
            raw_score=raw_score,
            capped_score=capped_score,
        )


rule_engine = RuleEngine()
