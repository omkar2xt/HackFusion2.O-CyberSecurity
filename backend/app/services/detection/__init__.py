"""
SignalSafe Campus - Detection Services Package
Provides centralized, deterministic feature extraction and detection modules.
"""

from backend.app.services.detection.url_features import (
    URL_FEATURE_NAMES,
    URL_FEATURE_SCHEMA_VERSION,
    URL_FEATURE_SCHEMA,
    extract_url_feature_dict,
    extract_url_feature_vector,
    normalize_url,
    URLFeatures,
    URLNormalizationResult,
)
from backend.app.services.detection.hybrid_engine import (
    DetectionEngine,
    detection_engine,
)

__all__ = [
    "URL_FEATURE_NAMES",
    "URL_FEATURE_SCHEMA_VERSION",
    "URL_FEATURE_SCHEMA",
    "extract_url_feature_dict",
    "extract_url_feature_vector",
    "normalize_url",
    "URLFeatures",
    "URLNormalizationResult",
    "DetectionEngine",
    "detection_engine",
]

