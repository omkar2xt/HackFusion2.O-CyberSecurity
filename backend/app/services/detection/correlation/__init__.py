"""
SignalSafe Campus - Evidence Correlation Package
"""

from backend.app.services.detection.correlation.evidence_model import (
    AggregatedEvidence,
    EvidenceItem,
    EvidenceSource,
)
from backend.app.services.detection.correlation.correlator import (
    EvidenceCorrelator,
    evidence_correlator,
)

__all__ = [
    "AggregatedEvidence",
    "EvidenceItem",
    "EvidenceSource",
    "EvidenceCorrelator",
    "evidence_correlator",
]
