"""
SignalSafe Campus - Centralized Evidence Model
Module: backend/app/services/detection/correlation/evidence_model.py
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from backend.app.schemas.common import EvidenceType, ScanIndicator, ScanRiskLevel
from backend.app.services.detection.model_adapters.base import ModelPrediction
from backend.app.services.detection.rules.indicators import RuleDefinition
from backend.app.services.detection.threat_intel.base import ThreatIntelResult


class EvidenceSource(str, Enum):
    THREAT_INTELLIGENCE = "threat_intelligence"
    ML_URL_MODEL = "ml_url_model"
    ML_QR_MODEL = "ml_qr_model"
    RULE_ENGINE = "rule_engine"
    QR_STRUCTURE = "qr_structure"


@dataclass(frozen=True)
class EvidenceItem:
    """An individual atomic item of threat evidence with provenance tracking."""
    source: EvidenceSource
    evidence_type: EvidenceType
    severity: ScanRiskLevel
    confidence: float  # 0.0 to 1.0
    code: str
    label: str
    detail: str
    is_confirmed_threat: bool = False
    is_mock: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class AggregatedEvidence:
    """Consolidated container of all collected evidence items for a scan target."""
    target_type: str  # "URL", "QR", "MESSAGE"
    target: str
    items: List[EvidenceItem]
    url_model_prediction: Optional[ModelPrediction] = None
    qr_model_prediction: Optional[ModelPrediction] = None
    threat_intel_results: List[ThreatIntelResult] = field(default_factory=list)
    fired_rules: List[RuleDefinition] = field(default_factory=list)
    has_confirmed_threat: bool = False
    has_heuristic_indicators: bool = False
    has_ml_threat: bool = False
    responding_sources: List[str] = field(default_factory=list)
    failed_sources: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def indicators(self) -> List[ScanIndicator]:
        """Maps internal evidence items to user-facing API ScanIndicators."""
        seen_codes = set()
        res = []
        for item in self.items:
            if item.code not in seen_codes:
                res.append(
                    ScanIndicator(
                        code=item.code,
                        label=item.label,
                        evidence_type=item.evidence_type,
                        detail=item.detail,
                    )
                )
                seen_codes.add(item.code)
        return res
