"""
SignalSafe Campus - Detection Rules Package
"""

from backend.app.services.detection.rules.indicators import (
    RULE_CATALOGUE,
    RuleDefinition,
)
from backend.app.services.detection.rules.engine import (
    RuleEngine,
    RuleEvaluationResult,
    rule_engine,
)

__all__ = [
    "RULE_CATALOGUE",
    "RuleDefinition",
    "RuleEngine",
    "RuleEvaluationResult",
    "rule_engine",
]
