"""
SignalSafe Campus - Detection Rule Indicators & Definitions
Module: backend/app/services/detection/rules/indicators.py
"""

from dataclasses import dataclass
from typing import Optional
from backend.app.schemas.common import EvidenceType, ScanRiskLevel, ScanIndicator


@dataclass(frozen=True)
class RuleDefinition:
    """Definition for an explainable detection rule indicator."""
    code: str
    label: str
    evidence_type: EvidenceType
    severity: ScanRiskLevel
    detail_template: str
    score_contribution: int

    def build_indicator(self, detail_override: Optional[str] = None) -> ScanIndicator:
        return ScanIndicator(
            code=self.code,
            label=self.label,
            evidence_type=self.evidence_type,
            detail=detail_override or self.detail_template,
        )


# Explainable Rule Catalogue
RULE_CATALOGUE = {
    "RAW_IP_HOST": RuleDefinition(
        code="RAW_IP_HOST",
        label="Raw IP address used as hostname",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.HIGH,
        detail_template="The target address specifies a raw IP address instead of an authenticated domain name.",
        score_contribution=35,
    ),
    "PUNYCODE_HOMOGRAPH": RuleDefinition(
        code="PUNYCODE_HOMOGRAPH",
        label="Internationalized homograph domain detected",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.HIGH,
        detail_template="Domain contains Punycode ('xn--') indicating an Internationalized Domain Name homograph lure.",
        score_contribution=30,
    ),
    "USERINFO_OBFUSCATION": RuleDefinition(
        code="USERINFO_OBFUSCATION",
        label="Userinfo credential obfuscation (@ symbol)",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.HIGH,
        detail_template="URL embeds '@' credentials, obscuring the actual destination hostname from users.",
        score_contribution=30,
    ),
    "NON_STANDARD_PORT": RuleDefinition(
        code="NON_STANDARD_PORT",
        label="Unusual web port specified",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.MEDIUM,
        detail_template="URL directs traffic to a non-standard network port (outside standard 80/443).",
        score_contribution=15,
    ),
    "EXCESSIVE_SUBDOMAINS": RuleDefinition(
        code="EXCESSIVE_SUBDOMAINS",
        label="Excessive subdomain depth",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.MEDIUM,
        detail_template="URL contains 3 or more nested subdomains, a pattern frequently used to evade domain filters.",
        score_contribution=15,
    ),
    "SUSPICIOUS_PAYLOAD_EXTENSION": RuleDefinition(
        code="SUSPICIOUS_PAYLOAD_EXTENSION",
        label="Executable or archive payload extension",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.HIGH,
        detail_template="The target path ends with a dangerous executable or script extension (.exe, .zip, .bat, .apk).",
        score_contribution=35,
    ),
    "SENSITIVE_CREDENTIAL_KEYWORD": RuleDefinition(
        code="SENSITIVE_CREDENTIAL_KEYWORD",
        label="Credential harvesting keywords detected",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.MEDIUM,
        detail_template="URL contains sensitive security or login keywords typical of account harvesting campaigns.",
        score_contribution=20,
    ),
    "DOUBLE_SLASH_EVASION": RuleDefinition(
        code="DOUBLE_SLASH_EVASION",
        label="Double-slash path redirection evasion",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.MEDIUM,
        detail_template="URL path contains '//' which can trigger open-redirect or reverse proxy bypass vulnerabilities.",
        score_contribution=20,
    ),
    "HIGH_CHARACTER_ENTROPY": RuleDefinition(
        code="HIGH_CHARACTER_ENTROPY",
        label="High character randomness in domain",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.LOW,
        detail_template="Domain exhibits unusually high Shannon character entropy, characteristic of DGAs.",
        score_contribution=10,
    ),
    "NUMERIC_DOMINANCE": RuleDefinition(
        code="NUMERIC_DOMINANCE",
        label="High numeric density in hostname",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.MEDIUM,
        detail_template="Hostname consists of an unusually high percentage of numeric digits.",
        score_contribution=15,
    ),
    "EXCESSIVE_URL_LENGTH": RuleDefinition(
        code="EXCESSIVE_URL_LENGTH",
        label="Abnormally long URL structure",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.LOW,
        detail_template="URL length exceeds 100 characters, frequently used to push suspicious tokens out of view.",
        score_contribution=10,
    ),
    "HIGH_PERCENT_ENCODING": RuleDefinition(
        code="HIGH_PERCENT_ENCODING",
        label="Heavy percent-encoding obfuscation",
        evidence_type=EvidenceType.HEURISTIC,
        severity=ScanRiskLevel.LOW,
        detail_template="URL uses excessive percent-encoding (%XX) to evade string-based static detection filters.",
        score_contribution=10,
    ),
}
